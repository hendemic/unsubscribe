pub mod api;

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use unsubscribe_core::{
    domain_from_email, parse_from_header, parse_list_unsubscribe, EmailProvider, Folder,
    FolderMessage, MessageId, ScanProgress, ScanResult, SenderInfo,
};

use api::{
    BatchModifyRequest, CreateLabelRequest, CreateLabelResponse, LabelRef, LabelsListResponse,
    MessageMetadata, MessagesListResponse,
};

/// Gmail REST API adapter for the `EmailProvider` trait.
///
/// Implements scanning via Gmail's `^unsub` system label and archiving via
/// `batchModify`. Requires a valid OAuth2 access token — token acquisition
/// and refresh are handled by the caller.
///
/// All HTTP calls go through the `HttpClient` port so this provider is fully
/// testable with mock implementations.
pub struct GmailProvider<C: unsubscribe_core::HttpClient> {
    /// Short-lived OAuth2 access token with `gmail.modify` scope.
    access_token: String,
    http: C,
    /// Archive label name used to exclude already-archived messages from scans.
    /// When set, the query appends `-label:"<name>"` so previously handled
    /// senders do not reappear on subsequent scans.
    archive_label: Option<String>,
}

impl<C: unsubscribe_core::HttpClient> GmailProvider<C> {
    pub fn new(access_token: impl Into<String>, http: C) -> Self {
        Self { access_token: access_token.into(), http, archive_label: None }
    }

    /// Construct a provider that excludes messages carrying `archive_label`
    /// from scan results. Pass the same label name used by `archive()`.
    pub fn with_archive_label(
        access_token: impl Into<String>,
        http: C,
        archive_label: impl Into<String>,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            http,
            archive_label: Some(archive_label.into()),
        }
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

    /// Fetch all message IDs from Gmail's `^unsub` system label, paginating
    /// through the full result set. This label is automatically applied by
    /// Gmail to bulk/newsletter emails — broader coverage than searching
    /// for the `List-Unsubscribe` header alone.
    ///
    /// When an archive label is configured, messages carrying that label are
    /// excluded via `-label:"<name>"` so already-archived senders don't
    /// reappear. If the label doesn't exist yet in Gmail the exclusion is a
    /// no-op (Gmail ignores unknown label references in search queries).
    fn list_unsubscribe_message_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut page_token: Option<String> = None;

        // Build the scan query, excluding the archive label when configured.
        // Label names with spaces must be quoted in Gmail query syntax.
        // The query string is percent-encoded for the URL.
        let encoded_q = match &self.archive_label {
            Some(label) if label.contains(' ') => {
                format!("label%3A%5Eunsub+-label%3A%22{}%22", percent_encode_label(label))
            }
            Some(label) => {
                format!("label%3A%5Eunsub+-label%3A{}", percent_encode_label(label))
            }
            None => "label%3A%5Eunsub".to_string(),
        };

        loop {
            let query = match &page_token {
                Some(token) => format!(
                    "messages?q={encoded_q}&maxResults=500&pageToken={token}"
                ),
                None => format!("messages?q={encoded_q}&maxResults=500"),
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

    /// Fetch metadata headers for a batch of messages in a single HTTP request.
    ///
    /// Gmail's batch endpoint accepts up to 100 individual requests as
    /// `multipart/mixed`. This is ~100x faster than one-request-per-message.
    ///
    /// Returns results as `BatchItemResult` so the caller can distinguish
    /// 429-rate-limited items (retry candidates) from permanent failures.
    fn fetch_message_metadata_batch(&self, ids: &[String]) -> Result<Vec<(String, BatchItemResult)>> {
        let boundary = "batch_unsub";
        let mut body = String::new();

        for id in ids {
            body.push_str(&format!(
                "--{boundary}\r\n\
                 Content-Type: application/http\r\n\
                 Content-ID: <{id}>\r\n\
                 \r\n\
                 GET /gmail/v1/users/me/messages/{id}?format=metadata\
                 &metadataHeaders=From\
                 &metadataHeaders=List-Unsubscribe\
                 &metadataHeaders=List-Unsubscribe-Post HTTP/1.1\r\n\
                 \r\n"
                // Note: internalDate is returned in the message object itself,
                // not as a metadata header — no need to request it via metadataHeaders.
            ));
        }
        body.push_str(&format!("--{boundary}--\r\n"));

        let content_type = format!("multipart/mixed; boundary={boundary}");

        // Retry whole-batch 429 errors with exponential backoff
        let mut attempt = 0;
        let response = loop {
            let resp = self
                .http
                .post_body_with_headers(
                    "https://www.googleapis.com/batch/gmail/v1",
                    &content_type,
                    &body,
                    &[("Authorization", &format!("Bearer {}", self.access_token))],
                )
                .context("Gmail batch request failed")?;

            if resp.status == 429 && attempt < 3 {
                attempt += 1;
                thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                continue;
            }
            break resp;
        };

        if response.status >= 400 {
            bail!("Gmail batch API error {}: {}", response.status, response.body);
        }

        parse_batch_response(&response.body, ids)
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
    /// Scan for bulk/newsletter senders via Gmail API.
    ///
    /// Uses Gmail's `^unsub` system label to find messages Gmail has identified
    /// as bulk email. The `folders` parameter is ignored; Gmail's label covers
    /// all mail.
    ///
    /// Individual sub-request 429 errors are retried with exponential backoff
    /// and reduced batch sizes. See acceptance criteria for retry bounds.
    fn scan(&self, _folders: &[Folder], progress: &dyn ScanProgress) -> Result<ScanResult> {
        let inbox = Folder::new("Gmail");

        let message_ids = self.list_unsubscribe_message_ids()?;
        let total = message_ids.len() as u32;

        progress.on_folder_start(&inbox, total);

        let mut senders: HashMap<String, SenderInfo> = HashMap::new();
        let mut warnings: Vec<String> = Vec::new();

        // Fetch metadata in batches of 50 with adaptive rate-limit delays.
        // Gmail counts each sub-request against quota, so 50 per batch
        // with a pause between avoids 429 Too Many Requests errors.
        let default_batch_size: usize = 50;
        let min_retry_batch_size: usize = 10;
        let max_retries: u32 = 3;
        let retry_total_cap = Duration::from_secs(60);

        let mut delay = Duration::from_millis(250);
        let mut retry_start: Option<std::time::Instant> = None;

        for (i, chunk) in message_ids.chunks(default_batch_size).enumerate() {
            if i > 0 {
                thread::sleep(delay);
            }

            let batch_results = match self.fetch_message_metadata_batch(chunk) {
                Ok(results) => results,
                Err(e) => {
                    // Whole-batch failure (network or batch-level 429 already retried)
                    delay = (delay * 2).min(Duration::from_secs(4));
                    warnings.push(format!("Batch fetch failed: {e}"));
                    progress.on_messages_scanned(&inbox, chunk.len() as u32);
                    continue;
                }
            };

            // Collect IDs that got per-message 429s for retry
            let mut to_retry: Vec<String> = Vec::new();
            let mut had_rate_limits = false;

            for (id, result) in batch_results {
                match result {
                    BatchItemResult::Ok(meta) => {
                        self.process_message_metadata(
                            &id, meta, &mut senders, &mut warnings, &inbox, progress,
                        );
                    }
                    BatchItemResult::RateLimited => {
                        had_rate_limits = true;
                        to_retry.push(id);
                        // Do not report progress here — will be reported after retry
                    }
                    BatchItemResult::Err(e) => {
                        let w = format!("Failed to fetch message {id}: {e}");
                        if !warnings.contains(&w) {
                            warnings.push(w);
                        }
                        progress.on_messages_scanned(&inbox, 1);
                    }
                }
            }

            // Per-message retry loop for 429'd IDs
            if !to_retry.is_empty() {
                had_rate_limits = true;
                if retry_start.is_none() {
                    retry_start = Some(std::time::Instant::now());
                }

                let mut retry_batch_size = (default_batch_size / 2).max(min_retry_batch_size);
                let mut attempt = 0u32;
                let mut remaining = to_retry.clone();

                while !remaining.is_empty() && attempt < max_retries {
                    // Check total retry time budget
                    if retry_start.map(|s| s.elapsed() > retry_total_cap).unwrap_or(false) {
                        break;
                    }

                    let backoff = Duration::from_secs(2u64.pow(attempt));
                    thread::sleep(backoff);
                    attempt += 1;

                    let mut still_failing: Vec<String> = Vec::new();

                    for retry_chunk in remaining.chunks(retry_batch_size) {
                        match self.fetch_message_metadata_batch(retry_chunk) {
                            Ok(retry_results) => {
                                for (id, result) in retry_results {
                                    match result {
                                        BatchItemResult::Ok(meta) => {
                                            self.process_message_metadata(
                                                &id, meta, &mut senders, &mut warnings,
                                                &inbox, progress,
                                            );
                                        }
                                        BatchItemResult::RateLimited => {
                                            still_failing.push(id);
                                        }
                                        BatchItemResult::Err(e) => {
                                            let w = format!("Failed to fetch message {id}: {e}");
                                            if !warnings.contains(&w) {
                                                warnings.push(w);
                                            }
                                            progress.on_messages_scanned(&inbox, 1);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Whole retry batch failed — treat all as still failing
                                warnings.push(format!("Retry batch failed: {e}"));
                                still_failing.extend_from_slice(retry_chunk);
                            }
                        }
                    }

                    remaining = still_failing;
                    // Reduce retry batch size further on continued failures
                    retry_batch_size = retry_batch_size.saturating_sub(10).max(min_retry_batch_size);
                }

                // Report any messages that exhausted retries
                if !remaining.is_empty() {
                    let n = remaining.len();
                    let msg = format!(
                        "{n} message(s) could not be fetched after {attempt} retries due to rate limiting"
                    );
                    if !warnings.contains(&msg) {
                        warnings.push(msg);
                    }
                    // These messages were never counted in progress — count them now
                    progress.on_messages_scanned(&inbox, n as u32);
                }
            }

            // Adjust inter-batch delay based on rate limit presence
            if had_rate_limits {
                delay = (delay * 2).min(Duration::from_secs(4));
            } else {
                // Ease back down after a clean batch
                delay = Duration::from_millis(250);
                retry_start = None; // reset retry budget window after a clean batch
            }
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

impl<C: unsubscribe_core::HttpClient> GmailProvider<C> {
    /// Process a successfully-fetched message metadata, updating sender aggregation maps.
    fn process_message_metadata(
        &self,
        id: &str,
        meta: MessageMetadata,
        senders: &mut HashMap<String, SenderInfo>,
        warnings: &mut Vec<String>,
        inbox: &Folder,
        progress: &dyn ScanProgress,
    ) {
        let Some(unsub_header) = meta.header("List-Unsubscribe") else {
            progress.on_messages_scanned(inbox, 1);
            return;
        };
        let unsub_header = unsub_header.to_string();

        let has_one_click = meta.header("List-Unsubscribe-Post").is_some();

        let Some(from_header) = meta.header("From") else {
            progress.on_messages_scanned(inbox, 1);
            return;
        };

        let (sender_name, sender_email) = parse_from_header(from_header);

        let parsed_unsub = parse_list_unsubscribe(&unsub_header, &sender_email);
        if let Some(w) = parsed_unsub.warning {
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
        let (urls, mailtos) = (parsed_unsub.urls, parsed_unsub.mailtos);

        let message_id = MessageId::new(id.to_string());
        let msg_timestamp = meta.timestamp_secs();

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
                last_seen: None,
            }
        });

        // Gmail returns messages newest-first. The first URLs we encounter
        // for a sender are the freshest — preserve them and skip older ones.
        if entry.unsubscribe_urls.is_empty() && !urls.is_empty() {
            entry.unsubscribe_urls = urls;
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
            folder: Folder::new("INBOX"),
            message_id,
        });

        entry.last_seen = match (entry.last_seen, msg_timestamp) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (None, ts) => ts,
            (existing, None) => existing,
        };

        if entry.display_name.is_empty() && !sender_name.is_empty() {
            entry.display_name = sender_name;
        }

        progress.on_messages_scanned(inbox, 1);
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Percent-encode a Gmail label name for use inside a query string value.
///
/// Encodes characters that are not safe inside a URL query component:
/// spaces become `%20`, `"` becomes `%22`, `+` becomes `%2B`.
fn percent_encode_label(label: &str) -> String {
    label
        .chars()
        .flat_map(|c| match c {
            ' ' => vec!['%', '2', '0'],
            '"' => vec!['%', '2', '2'],
            '+' => vec!['%', '2', 'B'],
            '%' => vec!['%', '2', '5'],
            c => vec![c],
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Batch response parsing
// ---------------------------------------------------------------------------

/// The outcome of a single sub-request within a Gmail batch response.
enum BatchItemResult {
    /// Successfully parsed message metadata.
    Ok(MessageMetadata),
    /// Sub-request was rate-limited (HTTP 429). Caller should retry this message ID.
    RateLimited,
    /// Other error (4xx or 5xx that is not 429, or a parse failure). Do not retry.
    Err(anyhow::Error),
}

/// Parse a Gmail batch API `multipart/mixed` response into individual results.
///
/// Each part contains an HTTP response with status line, headers, and a JSON body.
/// We extract the status code and body, then deserialize successful responses
/// into `MessageMetadata`. 429 sub-request errors are represented as
/// `BatchItemResult::RateLimited` so the caller can retry them separately.
fn parse_batch_response(
    body: &str,
    ids: &[String],
) -> Result<Vec<(String, BatchItemResult)>> {
    // Extract boundary from the response body — find the first line starting
    // with "--". Google may include leading whitespace or blank lines.
    let boundary = body
        .lines()
        .find_map(|line| line.trim().strip_prefix("--"))
        .map(|b| b.trim().to_string())
        .context("Could not find boundary in batch response")?;

    let mut results = Vec::new();
    let separator = format!("--{boundary}");

    let parts: Vec<&str> = body.split(&separator).collect();

    // Skip first (empty before first boundary) and last (closing boundary)
    let mut id_iter = ids.iter();
    for part in parts.iter().skip(1) {
        let part = part.trim();
        if part == "--" || part.is_empty() {
            continue;
        }

        let id = match id_iter.next() {
            Some(id) => id.clone(),
            None => break,
        };

        let result = parse_single_batch_part(part);
        results.push((id, result));
    }

    Ok(results)
}

/// Parse a single part from a batch response.
///
/// Each part has the structure:
/// ```text
/// Content-Type: application/http
/// <blank line>
/// HTTP/1.1 200 OK
/// <headers>
/// <blank line>
/// <JSON body>
/// ```
///
/// Returns `BatchItemResult::RateLimited` for 429 status codes so the
/// caller knows to retry the affected message ID.
fn parse_single_batch_part(part: &str) -> BatchItemResult {
    let result = parse_single_batch_part_inner(part);
    match result {
        Ok(meta) => BatchItemResult::Ok(meta),
        Err(e) => {
            // Check if the error message indicates a 429
            let msg = format!("{e}");
            if msg.contains("HTTP 429") {
                BatchItemResult::RateLimited
            } else {
                BatchItemResult::Err(e)
            }
        }
    }
}

fn parse_single_batch_part_inner(part: &str) -> Result<MessageMetadata> {
    // The part has: MIME headers \n\n HTTP response (status + headers \n\n body)
    let http_start = part
        .find("HTTP/")
        .context("No HTTP status line in batch part")?;
    let http_section = &part[http_start..];

    // Split HTTP response into headers+status and body
    let (http_headers, json_body) = http_section
        .split_once("\r\n\r\n")
        .or_else(|| http_section.split_once("\n\n"))
        .context("Could not separate HTTP headers from body in batch part")?;

    // Check status code
    let status_line = http_headers.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("Failed to parse HTTP status code from: {status_line}"))?;

    if status_code >= 400 {
        bail!("HTTP {status_code}: {}", json_body.trim());
    }

    serde_json::from_str(json_body.trim()).context("Failed to parse message metadata from batch")
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

    /// Wrap individual JSON metadata responses into a multipart batch response
    /// matching the format returned by Gmail's batch API.
    fn make_batch_response(metadata_jsons: &[String]) -> String {
        let boundary = "batch_boundary";
        let mut body = String::new();
        for json in metadata_jsons {
            body.push_str(&format!(
                "--{boundary}\r\n\
                 Content-Type: application/http\r\n\
                 \r\n\
                 HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 \r\n\
                 {json}\r\n"
            ));
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        body
    }

    #[test]
    fn scan_aggregates_senders() {
        // Gmail returns messages newest-first. msg1 is newer (first in list).
        // The URL from msg1 should be preserved; msg2's different URL is older
        // and should not overwrite the fresh one.
        let http = MockHttpClient::new();

        // First page: two messages — msg1 is newer (newest-first order)
        http.push(200, make_list_response(&["msg1", "msg2"], None));
        // Batch metadata response for both messages
        let batch = make_batch_response(&[
            make_metadata_response(
                "msg1",
                "Newsletter <news@example.com>",
                "<https://example.com/unsub?t=fresh>",
                false,
            ),
            make_metadata_response(
                "msg2",
                "Newsletter <news@example.com>",
                "<https://example.com/unsub?t=old>",
                true,
            ),
        ]);
        http.push(200, batch);

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 1);
        let sender = &result.senders[0];
        assert_eq!(sender.email, "news@example.com");
        assert_eq!(sender.display_name, "Newsletter");
        assert_eq!(sender.email_count, 2);
        assert!(sender.one_click);
        // The first-encountered (newest) URL wins
        assert_eq!(sender.unsubscribe_urls, vec!["https://example.com/unsub?t=fresh"]);
        assert_eq!(sender.messages.len(), 2);
    }

    #[test]
    fn scan_most_recently_encountered_url_wins() {
        // Gmail returns newest-first. The URL from the first message we process
        // is the freshest and must not be overwritten by older messages.
        let http = MockHttpClient::new();

        http.push(200, make_list_response(&["newest", "middle", "oldest"], None));
        let batch = make_batch_response(&[
            make_metadata_response(
                "newest",
                "Sender <sender@example.com>",
                "<https://example.com/unsub?t=3>",
                false,
            ),
            make_metadata_response(
                "middle",
                "Sender <sender@example.com>",
                "<https://example.com/unsub?t=2>",
                false,
            ),
            make_metadata_response(
                "oldest",
                "Sender <sender@example.com>",
                "<https://example.com/unsub?t=1>",
                false,
            ),
        ]);
        http.push(200, batch);

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 1);
        let sender = &result.senders[0];
        // t=3 is from the newest message and should win
        assert_eq!(
            sender.unsubscribe_urls,
            vec!["https://example.com/unsub?t=3"],
            "newest (first-encountered) URL should be preserved"
        );
        assert_eq!(sender.email_count, 3);
    }

    #[test]
    fn scan_paginates_through_all_results() {
        let http = MockHttpClient::new();

        // Page 1 with a next_page_token
        http.push(200, make_list_response(&["msg1"], Some("token-page-2")));
        // Page 2 — no next_page_token
        http.push(200, make_list_response(&["msg2"], None));
        // Single batch response for both messages (IDs collected across pages first)
        let batch = make_batch_response(&[
            make_metadata_response(
                "msg1",
                "Sender A <a@example.com>",
                "<https://a.com/unsub>",
                false,
            ),
            make_metadata_response(
                "msg2",
                "Sender B <b@example.com>",
                "<https://b.com/unsub>",
                false,
            ),
        ]);
        http.push(200, batch);

        let provider = GmailProvider::new("test-token", http);
        let result = provider.scan(&[], &NoopProgress).unwrap();

        assert_eq!(result.senders.len(), 2);
    }

    #[test]
    fn scan_skips_messages_without_unsub_header() {
        let http = MockHttpClient::new();

        http.push(200, make_list_response(&["msg1"], None));
        // Batch response with metadata lacking List-Unsubscribe header
        let batch = make_batch_response(&[
            r#"{"id":"msg1","payload":{"headers":[{"name":"From","value":"news@example.com"}]}}"#
                .to_string(),
        ]);
        http.push(200, batch);

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
    // Query construction
    // -----------------------------------------------------------------------

    #[test]
    fn scan_query_excludes_archive_label_without_spaces() {
        let http = MockHttpClient::new();
        // Return empty result so the test ends after the first list call
        http.push(200, r#"{"messages":[]}"#);

        let provider =
            GmailProvider::with_archive_label("test-token", http, "Unsubscribed");
        let _ = provider.scan(&[], &NoopProgress).unwrap();

        let calls = provider.http.calls();
        // The first call is the messages list; verify the URL contains the exclusion
        let url = &calls[0].1;
        assert!(
            url.contains("-label%3AUnsubscribed"),
            "Expected archive label exclusion in query URL, got: {url}"
        );
    }

    #[test]
    fn scan_query_excludes_archive_label_with_spaces() {
        let http = MockHttpClient::new();
        http.push(200, r#"{"messages":[]}"#);

        let provider =
            GmailProvider::with_archive_label("test-token", http, "My Archive");
        let _ = provider.scan(&[], &NoopProgress).unwrap();

        let calls = provider.http.calls();
        let url = &calls[0].1;
        // Spaces in the label name must be quoted, and space → %20 inside quotes
        assert!(
            url.contains("-label%3A%22My%20Archive%22"),
            "Expected quoted archive label exclusion in query URL, got: {url}"
        );
    }

    #[test]
    fn scan_query_no_exclusion_when_no_archive_label() {
        let http = MockHttpClient::new();
        http.push(200, r#"{"messages":[]}"#);

        let provider = GmailProvider::new("test-token", http);
        let _ = provider.scan(&[], &NoopProgress).unwrap();

        let calls = provider.http.calls();
        let url = &calls[0].1;
        assert!(
            !url.contains("-label"),
            "Expected no label exclusion in query URL without archive label, got: {url}"
        );
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
