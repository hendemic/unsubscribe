pub mod api;

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use unsubscribe_core::{
    domain_from_email, parse_list_unsubscribe, EmailProvider, Folder, FolderMessage, MessageId,
    ScanProgress, ScanResult, SenderInfo,
};

use api::{
    BatchModifyRequest, CreateLabelRequest, CreateLabelResponse, LabelRef, LabelsListResponse,
    MessageMetadata, MessagesListResponse,
};

/// Gmail REST API adapter for the `EmailProvider` trait.
///
/// Implements scanning via `q=list:unsubscribe` filter and archiving via
/// `batchModify`. Requires a valid OAuth2 access token — token acquisition
/// and refresh are handled by the caller.
///
/// All HTTP calls go through the `HttpClient` port so this provider is fully
/// testable with mock implementations.
pub struct GmailProvider<C: unsubscribe_core::HttpClient> {
    /// Short-lived OAuth2 access token with `gmail.modify` scope.
    access_token: String,
    http: C,
}

impl<C: unsubscribe_core::HttpClient> GmailProvider<C> {
    pub fn new(access_token: impl Into<String>, http: C) -> Self {
        Self { access_token: access_token.into(), http }
    }

    // -----------------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------------

    fn api_get(&self, path: &str) -> Result<String> {
        let url = format!("https://gmail.googleapis.com/gmail/v1/users/me/{path}");
        let response = self
            .http
            .get_with_headers(
                &url,
                &[("Authorization", &format!("Bearer {}", self.access_token))],
            )
            .with_context(|| format!("GET {url}"))?;

        if response.status == 401 {
            bail!("Gmail API returned 401 Unauthorized — access token may be expired");
        }
        if response.status >= 400 {
            bail!("Gmail API error {}: {}", response.status, response.body);
        }

        Ok(response.body)
    }

    fn api_post_json(&self, path: &str, body: &str) -> Result<String> {
        let url = format!("https://gmail.googleapis.com/gmail/v1/users/me/{path}");
        let response = self
            .http
            .post_body_with_headers(
                &url,
                "application/json",
                body,
                &[("Authorization", &format!("Bearer {}", self.access_token))],
            )
            .with_context(|| format!("POST {url}"))?;

        if response.status == 401 {
            bail!("Gmail API returned 401 Unauthorized — access token may be expired");
        }
        if response.status >= 400 {
            bail!("Gmail API error {}: {}", response.status, response.body);
        }

        Ok(response.body)
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    /// Fetch all message IDs matching `q=list:unsubscribe`, paginating through
    /// the full result set.
    fn list_unsubscribe_message_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let query = match &page_token {
                Some(token) => format!(
                    "messages?q=list%3Aunsubscribe&maxResults=500&pageToken={token}"
                ),
                None => "messages?q=list%3Aunsubscribe&maxResults=500".to_string(),
            };

            let body = self.api_get(&query)?;
            let list: MessagesListResponse = serde_json::from_str(&body)
                .context("Failed to parse messages list response")?;

            ids.extend(list.messages.into_iter().map(|m| m.id));

            match list.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }

        Ok(ids)
    }

    /// Fetch metadata headers for a single message.
    fn fetch_message_metadata(&self, id: &str) -> Result<MessageMetadata> {
        let path = format!(
            "messages/{id}?format=metadata\
             &metadataHeaders=From\
             &metadataHeaders=List-Unsubscribe\
             &metadataHeaders=List-Unsubscribe-Post"
        );
        let body = self.api_get(&path)?;
        serde_json::from_str(&body).context("Failed to parse message metadata response")
    }

    // -----------------------------------------------------------------------
    // Label management
    // -----------------------------------------------------------------------

    /// Find an existing label by name, returning its ID.
    fn find_label(&self, name: &str) -> Result<Option<String>> {
        let body = self.api_get("labels")?;
        let list: LabelsListResponse =
            serde_json::from_str(&body).context("Failed to parse labels list response")?;

        Ok(list
            .labels
            .into_iter()
            .find(|l: &LabelRef| l.name.eq_ignore_ascii_case(name))
            .map(|l| l.id))
    }

    /// Create a label with the given name and return its ID.
    fn create_label(&self, name: &str) -> Result<String> {
        let req = CreateLabelRequest {
            name: name.to_string(),
            label_list_visibility: "labelShow",
            message_list_visibility: "show",
        };
        let body =
            serde_json::to_string(&req).context("Failed to serialize create label request")?;
        let response = self.api_post_json("labels", &body)?;
        let created: CreateLabelResponse =
            serde_json::from_str(&response).context("Failed to parse create label response")?;
        Ok(created.id)
    }

    /// Return the ID for a label by name, creating it if it doesn't exist.
    fn get_or_create_label(&self, name: &str) -> Result<String> {
        if let Some(id) = self.find_label(name)? {
            return Ok(id);
        }
        self.create_label(name)
    }
}

impl<C: unsubscribe_core::HttpClient> EmailProvider for GmailProvider<C> {
    /// Scan for senders with List-Unsubscribe headers via Gmail API.
    ///
    /// Uses `q=list:unsubscribe` server-side filter so we only fetch messages
    /// that have unsubscribe headers — much more efficient than IMAP scanning.
    /// The `folders` parameter is ignored; Gmail's server-side filter covers
    /// all mail.
    fn scan(&self, _folders: &[Folder], progress: &dyn ScanProgress) -> Result<ScanResult> {
        let inbox = Folder::new("Gmail");
        progress.on_folder_start(&inbox, 0);

        let message_ids = self.list_unsubscribe_message_ids()?;
        let total = message_ids.len() as u32;

        // Report the real total now that we know it
        progress.on_folder_start(&inbox, total);

        let mut senders: HashMap<String, SenderInfo> = HashMap::new();
        let mut warnings: Vec<String> = Vec::new();

        for id in &message_ids {
            let meta = match self.fetch_message_metadata(id) {
                Ok(m) => m,
                Err(e) => {
                    let w = format!("Failed to fetch message {id}: {e}");
                    if !warnings.contains(&w) {
                        warnings.push(w);
                    }
                    progress.on_messages_scanned(&inbox, 1);
                    continue;
                }
            };

            let Some(unsub_header) = meta.header("List-Unsubscribe") else {
                progress.on_messages_scanned(&inbox, 1);
                continue;
            };
            let unsub_header = unsub_header.to_string();

            let has_one_click = meta.header("List-Unsubscribe-Post").is_some();

            let Some(from_header) = meta.header("From") else {
                progress.on_messages_scanned(&inbox, 1);
                continue;
            };

            let (sender_name, sender_email) = parse_from_header(from_header);

            let parsed_unsub = parse_list_unsubscribe(&unsub_header, &sender_email);
            if let Some(w) = parsed_unsub.warning {
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
            let (urls, mailtos) = (parsed_unsub.urls, parsed_unsub.mailtos);

            // Gmail message IDs are opaque strings — use directly as MessageId
            let message_id = MessageId::new(id.clone());

            let sender_key = sender_email.to_lowercase();
            let entry = senders.entry(sender_key).or_insert_with(|| {
                let domain = domain_from_email(&sender_email);
                SenderInfo {
                    display_name: sender_name.clone(),
                    email: sender_email.clone(),
                    domain,
                    unsubscribe_urls: Vec::new(),
                    unsubscribe_mailto: Vec::new(),
                    one_click: false,
                    email_count: 0,
                    messages: Vec::new(),
                }
            });

            for u in urls {
                if !entry.unsubscribe_urls.contains(&u) {
                    entry.unsubscribe_urls.push(u);
                }
            }
            for m in mailtos {
                if !entry.unsubscribe_mailto.contains(&m) {
                    entry.unsubscribe_mailto.push(m);
                }
            }
            if has_one_click {
                entry.one_click = true;
            }
            entry.email_count += 1;
            entry.messages.push(FolderMessage {
                // Gmail doesn't have IMAP-style folders; use a placeholder
                folder: Folder::new("INBOX"),
                message_id,
            });

            if entry.display_name.is_empty() && !sender_name.is_empty() {
                entry.display_name = sender_name;
            }

            progress.on_messages_scanned(&inbox, 1);
        }

        progress.on_folder_done(&inbox);

        let mut result: Vec<SenderInfo> = senders.into_values().collect();
        result.sort_by(|a, b| b.email_count.cmp(&a.email_count));

        Ok(ScanResult { senders: result, warnings })
    }

    /// Archive messages by removing the INBOX label and adding the destination
    /// label. Creates the destination label if it doesn't exist.
    ///
    /// The `destination` folder name is used as the Gmail label name.
    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32> {
        if messages.is_empty() {
            return Ok(0);
        }

        let label_id = self.get_or_create_label(destination.as_str())?;

        let ids: Vec<String> = messages
            .iter()
            .map(|m| m.message_id.as_str().to_string())
            .collect();

        // batchModify accepts up to 1000 IDs per request
        let mut archived = 0u32;
        for chunk in ids.chunks(1000) {
            let req = BatchModifyRequest {
                ids: chunk.to_vec(),
                remove_label_ids: vec!["INBOX".to_string()],
                add_label_ids: vec![label_id.clone()],
            };
            let body = serde_json::to_string(&req)
                .context("Failed to serialize batchModify request")?;
            // batchModify returns 204 No Content on success
            self.api_post_json("messages/batchModify", &body)?;
            archived += chunk.len() as u32;
        }

        Ok(archived)
    }
}

// ---------------------------------------------------------------------------
// From header parsing
// ---------------------------------------------------------------------------

/// Parse a RFC 5322 From header value into (display_name, email).
///
/// Handles the common formats:
/// - `"Display Name" <email@example.com>`
/// - `Display Name <email@example.com>`
/// - `<email@example.com>`
/// - `email@example.com`
fn parse_from_header(from: &str) -> (String, String) {
    let from = from.trim();

    // "Name" <email> or Name <email>
    if let Some(angle_start) = from.rfind('<') {
        if let Some(angle_end) = from[angle_start..].find('>') {
            let email = from[angle_start + 1..angle_start + angle_end].trim().to_string();
            let name = from[..angle_start]
                .trim()
                .trim_matches('"')
                .trim()
                .to_string();
            return (name, email);
        }
    }

    // Plain email address
    (String::new(), from.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use unsubscribe_core::NoopProgress;
    use std::sync::Mutex;
    use unsubscribe_core::{HttpClient, HttpResponse};

    // -----------------------------------------------------------------------
    // Mock HttpClient
    // -----------------------------------------------------------------------

    /// Records outgoing requests and returns pre-programmed responses.
    struct MockHttpClient {
        /// Responses to return in order. Each entry is (status, body).
        responses: Mutex<VecDeque<(u16, String)>>,
        /// Recorded (method, url, body) tuples for assertions.
        calls: Mutex<Vec<(String, String, String)>>,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                responses: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn push(&self, status: u16, body: impl Into<String>) {
            self.responses.lock().unwrap().push_back((status, body.into()));
        }

        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls.lock().unwrap().clone()
        }

        fn next_response(&self, method: &str, url: &str, body: &str) -> HttpResponse {
            self.calls.lock().unwrap().push((
                method.to_string(),
                url.to_string(),
                body.to_string(),
            ));
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, "{}".to_string()));
            HttpResponse { status, body }
        }
    }

    impl HttpClient for MockHttpClient {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            Ok(self.next_response("GET", url, ""))
        }

        fn get_with_headers(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
            Ok(self.next_response("GET", url, ""))
        }

        fn post_form(&self, url: &str, _params: &[(&str, &str)]) -> Result<HttpResponse> {
            Ok(self.next_response("POST", url, ""))
        }

        fn post_body(&self, url: &str, _content_type: &str, body: &str) -> Result<HttpResponse> {
            Ok(self.next_response("POST", url, body))
        }

        fn post_body_with_headers(
            &self,
            url: &str,
            _content_type: &str,
            body: &str,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse> {
            Ok(self.next_response("POST", url, body))
        }
    }

    // -----------------------------------------------------------------------
    // From header parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_from_quoted_name_with_angle() {
        let (name, email) = parse_from_header(r#""Acme Newsletter" <news@acme.com>"#);
        assert_eq!(name, "Acme Newsletter");
        assert_eq!(email, "news@acme.com");
    }

    #[test]
    fn parse_from_unquoted_name_with_angle() {
        let (name, email) = parse_from_header("Acme Newsletter <news@acme.com>");
        assert_eq!(name, "Acme Newsletter");
        assert_eq!(email, "news@acme.com");
    }

    #[test]
    fn parse_from_angle_only() {
        let (name, email) = parse_from_header("<news@acme.com>");
        assert_eq!(name, "");
        assert_eq!(email, "news@acme.com");
    }

    #[test]
    fn parse_from_plain_email() {
        let (name, email) = parse_from_header("news@acme.com");
        assert_eq!(name, "");
        assert_eq!(email, "news@acme.com");
    }

    // -----------------------------------------------------------------------
    // Scan flow
    // -----------------------------------------------------------------------

    fn make_list_response(ids: &[&str], next_page: Option<&str>) -> String {
        let messages: String = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let next = next_page
            .map(|t| format!(r#","nextPageToken":"{t}""#))
            .unwrap_or_default();
        format!(r#"{{"messages":[{messages}]{next}}}"#)
    }

    fn make_metadata_response(id: &str, from: &str, unsub: &str, one_click: bool) -> String {
        let one_click_header = if one_click {
            r#",{"name":"List-Unsubscribe-Post","value":"List-Unsubscribe=One-Click"}"#
        } else {
            ""
        };
        format!(
            r#"{{"id":"{id}","payload":{{"headers":[
                {{"name":"From","value":"{from}"}},
                {{"name":"List-Unsubscribe","value":"{unsub}"}}
                {one_click_header}
            ]}}}}"#
        )
    }

    #[test]
    fn scan_aggregates_senders() {
        let http = MockHttpClient::new();

        // First page: two messages
        http.push(200, make_list_response(&["msg1", "msg2"], None));
        // msg1 metadata
        http.push(
            200,
            make_metadata_response(
                "msg1",
                "Newsletter <news@example.com>",
                "<https://example.com/unsub>",
                false,
            ),
        );
        // msg2 metadata — same sender
        http.push(
            200,
            make_metadata_response(
                "msg2",
                "Newsletter <news@example.com>",
                "<https://example.com/unsub>",
                true,
            ),
        );

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 1);
        let sender = &result.senders[0];
        assert_eq!(sender.email, "news@example.com");
        assert_eq!(sender.display_name, "Newsletter");
        assert_eq!(sender.email_count, 2);
        assert!(sender.one_click);
        assert_eq!(sender.unsubscribe_urls, vec!["https://example.com/unsub"]);
        assert_eq!(sender.messages.len(), 2);
    }

    #[test]
    fn scan_paginates_through_all_results() {
        let http = MockHttpClient::new();

        // Page 1 with a next_page_token
        http.push(200, make_list_response(&["msg1"], Some("token-page-2")));
        // Page 2 — no next_page_token
        http.push(200, make_list_response(&["msg2"], None));
        // msg1 metadata
        http.push(
            200,
            make_metadata_response(
                "msg1",
                "Sender A <a@example.com>",
                "<https://a.com/unsub>",
                false,
            ),
        );
        // msg2 metadata
        http.push(
            200,
            make_metadata_response(
                "msg2",
                "Sender B <b@example.com>",
                "<https://b.com/unsub>",
                false,
            ),
        );

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 2);
    }

    #[test]
    fn scan_skips_messages_without_unsub_header() {
        let http = MockHttpClient::new();

        http.push(200, make_list_response(&["msg1"], None));
        // Metadata response without List-Unsubscribe header
        http.push(
            200,
            r#"{"id":"msg1","payload":{"headers":[{"name":"From","value":"news@example.com"}]}}"#,
        );

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 0);
    }

    #[test]
    fn scan_empty_inbox_returns_empty_result() {
        let http = MockHttpClient::new();
        http.push(200, r#"{"messages":[]}"#);

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 0);
        assert_eq!(result.warnings.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Archive flow
    // -----------------------------------------------------------------------

    fn make_folder_message(id: &str) -> FolderMessage {
        FolderMessage {
            folder: Folder::new("INBOX"),
            message_id: MessageId::new(id),
        }
    }

    #[test]
    fn archive_creates_label_and_batch_modifies() {
        let http = MockHttpClient::new();

        // get_or_create_label: find_label returns empty list → create label
        http.push(200, r#"{"labels":[]}"#);
        http.push(200, r#"{"id":"Label_123","name":"Unsubscribed"}"#);
        // batchModify
        http.push(204, "");

        let provider = GmailProvider::new("test-token", http);
        let messages = vec![
            make_folder_message("msg1"),
            make_folder_message("msg2"),
        ];
        let destination = Folder::new("Unsubscribed");

        let count = provider.archive(&messages, &destination).unwrap();
        assert_eq!(count, 2);

        let calls = provider.http.calls();
        // 1. GET labels
        assert!(calls[0].1.contains("labels"));
        // 2. POST create label
        assert!(calls[1].0 == "POST" && calls[1].1.contains("labels"));
        // 3. POST batchModify
        assert!(calls[2].1.contains("batchModify"));
        let body: serde_json::Value = serde_json::from_str(&calls[2].2).unwrap();
        assert_eq!(body["removeLabelIds"], serde_json::json!(["INBOX"]));
        assert_eq!(body["addLabelIds"], serde_json::json!(["Label_123"]));
        assert_eq!(body["ids"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn archive_reuses_existing_label() {
        let http = MockHttpClient::new();

        // find_label returns an existing label
        http.push(
            200,
            r#"{"labels":[{"id":"Label_456","name":"Unsubscribed"}]}"#,
        );
        // batchModify
        http.push(204, "");

        let provider = GmailProvider::new("test-token", http);
        let messages = vec![make_folder_message("msgA")];
        let destination = Folder::new("Unsubscribed");

        let count = provider.archive(&messages, &destination).unwrap();
        assert_eq!(count, 1);

        let calls = provider.http.calls();
        // Only 2 calls: GET labels + POST batchModify (no create label call)
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn archive_empty_messages_returns_zero_without_api_calls() {
        let http = MockHttpClient::new();

        let provider = GmailProvider::new("test-token", http);
        let count = provider.archive(&[], &Folder::new("Unsubscribed")).unwrap();

        assert_eq!(count, 0);
        assert_eq!(provider.http.calls().len(), 0);
    }
}
