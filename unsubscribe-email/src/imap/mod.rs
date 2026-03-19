use std::collections::HashMap;
use std::net::TcpStream;

use anyhow::{bail, Context, Result};
use imap::Session;
use mail_parser::MessageParser;
use native_tls::TlsStream;

use unsubscribe_core::{
    domain_from_email, parse_from_header, parse_list_unsubscribe, EmailProvider, Folder,
    FolderMessage, MessageId, ScanProgress, ScanResult, SenderInfo,
};

/// Maximum concurrent IMAP connections per scan. Gmail allows ~15 simultaneous
/// connections; we stay well under that to avoid throttling.
const MAX_CONCURRENT_CONNECTIONS: usize = 5;

/// IMAP adapter for the `EmailProvider` trait.
///
/// Connects to an IMAP server over TLS and scans mailboxes for senders
/// with List-Unsubscribe headers. Spawns one thread per folder for parallelism,
/// capped at `MAX_CONCURRENT_CONNECTIONS` to respect server limits.
pub struct ImapProvider {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl ImapProvider {
    pub fn new(host: String, port: u16, username: String, password: String) -> Self {
        Self { host, port, username, password }
    }

    fn connect(&self) -> Result<Session<TlsStream<TcpStream>>> {
        let tls = native_tls::TlsConnector::builder().build()?;
        let client = imap::connect(
            (self.host.as_str(), self.port),
            &self.host,
            &tls,
        )
        .context("Failed to connect to IMAP server")?;

        let session = client
            .login(&self.username, &self.password)
            .map_err(|e| anyhow::anyhow!("IMAP login failed: {}", e.0))?;

        Ok(session)
    }
}

impl EmailProvider for ImapProvider {
    fn scan(&self, folders: &[Folder], progress: &dyn ScanProgress) -> Result<ScanResult> {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();
        let mut all_warnings: Vec<String> = Vec::new();

        // Process folders in batches to respect server connection limits
        for batch in folders.chunks(MAX_CONCURRENT_CONNECTIONS) {
            std::thread::scope(|s| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|folder| {
                        let provider = ImapProvider {
                            host: self.host.clone(),
                            port: self.port,
                            username: self.username.clone(),
                            password: self.password.clone(),
                        };
                        let folder = folder.clone();
                        s.spawn(move || scan_folder(&provider, &folder, progress))
                    })
                    .collect();

                for handle in handles {
                    let folder_result = handle.join().expect("scan thread panicked")?;
                    let warnings = merge_folder_result(&mut combined, folder_result);
                    for w in warnings {
                        if !all_warnings.contains(&w) {
                            all_warnings.push(w);
                        }
                    }
                }

                Ok::<(), anyhow::Error>(())
            })?;
        }

        let mut senders: Vec<SenderInfo> = combined.into_values().collect();
        senders.sort_by(|a, b| b.email_count.cmp(&a.email_count));

        Ok(ScanResult { senders, warnings: all_warnings })
    }

    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32> {
        let mut session = self.connect()?;
        let dest = destination.as_str();

        // Check if server supports MOVE (RFC 6851). Gmail and some other servers
        // don't, so we fall back to COPY + STORE \Deleted + EXPUNGE.
        let has_move = session
            .capabilities()
            .map(|caps| caps.has_str("MOVE"))
            .unwrap_or(false);

        // Create destination folder if it doesn't exist
        session.create(dest).ok();
        session.subscribe(dest).ok();

        // Group messages by folder so we only select each folder once
        let mut by_folder: HashMap<&str, Vec<&FolderMessage>> = HashMap::new();
        for msg in messages {
            by_folder
                .entry(msg.folder.as_str())
                .or_default()
                .push(msg);
        }

        let mut archived = 0u32;

        for (folder, msgs) in &by_folder {
            let mailbox = session
                .select(folder)
                .with_context(|| format!("Failed to select folder: {folder}"))?;

            // Parse UIDs from MessageId and verify UIDVALIDITY
            let mut uids: Vec<String> = Vec::new();
            for msg in msgs {
                let (uid, expected_validity) = parse_message_id(msg.message_id.as_str())
                    .with_context(|| {
                        format!("Invalid MessageId format: {}", msg.message_id)
                    })?;

                if let Some(current_validity) = mailbox.uid_validity {
                    if current_validity != expected_validity {
                        bail!(
                            "UIDVALIDITY changed for folder '{folder}' \
                             (was {expected_validity}, now {current_validity}). \
                             Aborting archive to avoid moving wrong emails. Please re-scan."
                        );
                    }
                }

                uids.push(uid.to_string());
            }

            // Process in chunks to avoid overly long IMAP commands
            for chunk in uids.chunks(100) {
                let uid_set = chunk.join(",");

                if has_move {
                    session
                        .uid_mv(&uid_set, dest)
                        .with_context(|| {
                            format!("Failed to move emails from {folder} to {dest}")
                        })?;
                } else {
                    // Fallback: COPY + flag \Deleted + EXPUNGE
                    session
                        .uid_copy(&uid_set, dest)
                        .with_context(|| {
                            format!("Failed to copy emails from {folder} to {dest}")
                        })?;
                    let _ = session
                        .uid_store(&uid_set, "+FLAGS (\\Deleted)")
                        .with_context(|| {
                            format!("Failed to flag emails as deleted in {folder}")
                        })?;
                    session.expunge().with_context(|| {
                        format!("Failed to expunge deleted emails from {folder}")
                    })?;
                }

                archived += chunk.len() as u32;
            }
        }

        session.logout().ok();
        Ok(archived)
    }
}

// ---------------------------------------------------------------------------
// Internal types and functions
// ---------------------------------------------------------------------------

/// Per-folder scan result before merging into the combined map.
struct FolderResult {
    senders: HashMap<String, SenderInfo>,
    warnings: Vec<String>,
}

/// Scan a single IMAP folder on a dedicated connection.
fn scan_folder(
    provider: &ImapProvider,
    folder: &Folder,
    progress: &dyn ScanProgress,
) -> Result<FolderResult> {
    let mut session = provider.connect()?;
    let mut senders: HashMap<String, SenderInfo> = HashMap::new();
    let mut warnings: Vec<String> = Vec::new();
    let parser = MessageParser::default();

    let folder_name = folder.as_str();
    let mailbox = session
        .select(folder_name)
        .with_context(|| format!("Failed to select folder: {folder_name}"))?;

    let total = mailbox.exists;
    progress.on_folder_start(folder, total);

    if total == 0 {
        progress.on_folder_done(folder);
        session.logout().ok();
        return Ok(FolderResult { senders, warnings });
    }

    let uid_validity = mailbox.uid_validity;

    // Fetch in batches to bound memory usage on large mailboxes
    let batch_size = 500u32;
    let mut start = 1u32;
    while start <= total {
        let end = total.min(start + batch_size - 1);
        let sequence = format!("{start}:{end}");
        let messages = session
            .fetch(&sequence, "(UID INTERNALDATE BODY.PEEK[HEADER])")
            .with_context(|| format!("Failed to fetch messages {start}:{end}"))?;

        for msg in messages.iter() {
            progress.on_messages_scanned(folder, 1);

            let Some(uid) = msg.uid else { continue };
            // Extract the message timestamp (Unix seconds) from INTERNALDATE.
            let internal_date_ts: Option<i64> = msg
                .internal_date()
                .map(|dt| dt.timestamp());

            let Some(header_bytes) = msg.header() else { continue };
            let Some(parsed) = parser.parse(header_bytes) else { continue };

            let Some(unsub_header) = parsed.header_raw("List-Unsubscribe") else {
                continue;
            };
            let unsub_header = unsub_header.to_string();

            let has_one_click = parsed.header_raw("List-Unsubscribe-Post").is_some();

            let from_raw = parsed
                .header_raw("From")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let (sender_name, sender_email) = parse_from_header(&from_raw);
            if sender_email.is_empty() {
                continue;
            }

            let parsed_unsub = parse_list_unsubscribe(&unsub_header, &sender_email);
            if let Some(w) = parsed_unsub.warning {
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
            let (urls, mailtos) = (parsed_unsub.urls, parsed_unsub.mailtos);

            // Encode the IMAP UID into a MessageId: "folder:uid:uidvalidity"
            let message_id = encode_message_id(
                folder_name,
                uid,
                uid_validity.unwrap_or(0),
            );

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

            // Replace URLs with the most recently encountered set. IMAP sequences
            // are in chronological order (oldest first), so the last-seen URLs are
            // the freshest and least likely to be expired.
            if !urls.is_empty() {
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
                folder: folder.clone(),
                message_id,
            });

            // Track the most recent message date for staleness detection.
            entry.last_seen = match (entry.last_seen, internal_date_ts) {
                (Some(existing), Some(new)) => Some(existing.max(new)),
                (None, ts) => ts,
                (existing, None) => existing,
            };

            // Update display name if we got a better one
            if entry.display_name.is_empty() && !sender_name.is_empty() {
                entry.display_name = sender_name;
            }
        }

        start = end + 1;
    }

    progress.on_folder_done(folder);
    session.logout().ok();
    Ok(FolderResult { senders, warnings })
}

/// Merge a per-folder result into the combined sender map.
fn merge_folder_result(
    combined: &mut HashMap<String, SenderInfo>,
    folder_result: FolderResult,
) -> Vec<String> {
    for (key, sender) in folder_result.senders {
        let entry = combined.entry(key).or_insert_with(|| SenderInfo {
            display_name: sender.display_name.clone(),
            email: sender.email.clone(),
            domain: sender.domain.clone(),
            unsubscribe_urls: Vec::new(),
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            email_count: 0,
            messages: Vec::new(),
            last_seen: None,
        });

        // Incoming folder's URLs replace existing ones. When merging across
        // folders there is no reliable timestamp ordering, so last-merged wins.
        if !sender.unsubscribe_urls.is_empty() {
            entry.unsubscribe_urls = sender.unsubscribe_urls;
        }
        for m in &sender.unsubscribe_mailto {
            if !entry.unsubscribe_mailto.contains(m) {
                entry.unsubscribe_mailto.push(m.clone());
            }
        }
        if sender.one_click {
            entry.one_click = true;
        }
        entry.email_count += sender.email_count;
        entry.messages.extend(sender.messages);

        // Take the most recent date seen across all folders.
        entry.last_seen = match (entry.last_seen, sender.last_seen) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (None, b) => b,
            (a, None) => a,
        };

        if entry.display_name.is_empty() && !sender.display_name.is_empty() {
            entry.display_name = sender.display_name.clone();
        }
    }

    folder_result.warnings
}

// ---------------------------------------------------------------------------
// MessageId encoding: "folder:uid:uidvalidity"
// ---------------------------------------------------------------------------

fn encode_message_id(folder: &str, uid: u32, uid_validity: u32) -> MessageId {
    MessageId::new(format!("{folder}:{uid}:{uid_validity}"))
}

/// Parse a MessageId back into (uid, uid_validity).
fn parse_message_id(id: &str) -> Result<(u32, u32)> {
    // Format: "folder:uid:uidvalidity" — split from the right since folder names can contain colons
    let Some(last_colon) = id.rfind(':') else {
        bail!("MessageId missing uidvalidity segment: {id}");
    };
    let uid_validity: u32 = id[last_colon + 1..]
        .parse()
        .with_context(|| format!("Invalid uidvalidity in MessageId: {id}"))?;

    let rest = &id[..last_colon];
    let Some(second_colon) = rest.rfind(':') else {
        bail!("MessageId missing uid segment: {id}");
    };
    let uid: u32 = rest[second_colon + 1..]
        .parse()
        .with_context(|| format!("Invalid uid in MessageId: {id}"))?;

    Ok((uid, uid_validity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use unsubscribe_core::{Folder, FolderMessage, MessageId, ScanProgress, SenderInfo};

    // -----------------------------------------------------------------------
    // Test infrastructure
    // -----------------------------------------------------------------------

    /// Records all ScanProgress calls for assertion in tests.
    struct TestProgress {
        calls: Mutex<Vec<ProgressCall>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ProgressCall {
        FolderStart { folder: String, total: u32 },
        MessagesScanned { folder: String, count: u32 },
        FolderDone { folder: String },
    }

    impl TestProgress {
        fn new() -> Self {
            Self { calls: Mutex::new(Vec::new()) }
        }

        fn calls(&self) -> Vec<ProgressCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ScanProgress for TestProgress {
        fn on_folder_start(&self, folder: &Folder, total_messages: u32) {
            self.calls.lock().unwrap().push(ProgressCall::FolderStart {
                folder: folder.as_str().to_string(),
                total: total_messages,
            });
        }

        fn on_messages_scanned(&self, folder: &Folder, count: u32) {
            self.calls.lock().unwrap().push(ProgressCall::MessagesScanned {
                folder: folder.as_str().to_string(),
                count,
            });
        }

        fn on_folder_done(&self, folder: &Folder) {
            self.calls.lock().unwrap().push(ProgressCall::FolderDone {
                folder: folder.as_str().to_string(),
            });
        }
    }

    /// Builds a SenderInfo with sensible defaults for testing.
    fn make_sender(
        email: &str,
        email_count: u32,
        urls: Vec<&str>,
        mailtos: Vec<&str>,
        one_click: bool,
        display_name: &str,
        messages: Vec<FolderMessage>,
    ) -> SenderInfo {
        SenderInfo {
            display_name: display_name.to_string(),
            email: email.to_string(),
            domain: domain_from_email(email),
            unsubscribe_urls: urls.into_iter().map(String::from).collect(),
            unsubscribe_mailto: mailtos.into_iter().map(String::from).collect(),
            one_click,
            email_count,
            messages,
            last_seen: None,
        }
    }

    // -----------------------------------------------------------------------
    // MessageId encoding/decoding
    // -----------------------------------------------------------------------

    #[test]
    fn message_id_round_trip() {
        let id = encode_message_id("INBOX", 42, 12345);
        let (uid, validity) = parse_message_id(id.as_str()).unwrap();
        assert_eq!(uid, 42);
        assert_eq!(validity, 12345);
    }

    #[test]
    fn message_id_folder_with_colons() {
        // Gmail-style folder names contain colons and slashes
        let id = encode_message_id("[Gmail]/All Mail", 100, 999);
        let (uid, validity) = parse_message_id(id.as_str()).unwrap();
        assert_eq!(uid, 100);
        assert_eq!(validity, 999);
    }

    #[test]
    fn message_id_folder_with_multiple_colons() {
        let id = encode_message_id("a:b:c", 7, 8);
        let (uid, validity) = parse_message_id(id.as_str()).unwrap();
        assert_eq!(uid, 7);
        assert_eq!(validity, 8);
    }

    #[test]
    fn parse_message_id_missing_all_segments() {
        let err = parse_message_id("nocolonshere").unwrap_err();
        assert!(
            format!("{err}").contains("missing uidvalidity"),
            "expected 'missing uidvalidity' in: {err}"
        );
    }

    #[test]
    fn parse_message_id_missing_uid_segment() {
        // Only one colon: "folder:uidvalidity" -- uid segment is missing
        let err = parse_message_id("INBOX:12345").unwrap_err();
        assert!(
            format!("{err}").contains("missing uid"),
            "expected 'missing uid' in: {err}"
        );
    }

    #[test]
    fn parse_message_id_non_numeric_uid() {
        let err = parse_message_id("INBOX:abc:12345").unwrap_err();
        assert!(
            format!("{err}").contains("Invalid uid"),
            "expected 'Invalid uid' in: {err}"
        );
    }

    #[test]
    fn parse_message_id_non_numeric_validity() {
        let err = parse_message_id("INBOX:42:xyz").unwrap_err();
        assert!(
            format!("{err}").contains("Invalid uidvalidity"),
            "expected 'Invalid uidvalidity' in: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Sender aggregation (merge_folder_result)
    // -----------------------------------------------------------------------

    #[test]
    fn merge_same_sender_across_folders_sums_email_count() {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let folder1 = FolderResult {
            senders: HashMap::from([(
                "news@example.com".to_string(),
                make_sender(
                    "news@example.com", 3,
                    vec!["https://example.com/unsub"],
                    vec![],
                    false,
                    "Example News",
                    vec![FolderMessage {
                        folder: Folder::new("INBOX"),
                        message_id: MessageId::new("INBOX:1:100"),
                    }],
                ),
            )]),
            warnings: vec![],
        };

        let folder2 = FolderResult {
            senders: HashMap::from([(
                "news@example.com".to_string(),
                make_sender(
                    "news@example.com", 2,
                    vec!["https://example.com/unsub"],
                    vec![],
                    false,
                    "",
                    vec![FolderMessage {
                        folder: Folder::new("Spam"),
                        message_id: MessageId::new("Spam:5:200"),
                    }],
                ),
            )]),
            warnings: vec![],
        };

        merge_folder_result(&mut combined, folder1);
        merge_folder_result(&mut combined, folder2);

        let sender = &combined["news@example.com"];
        assert_eq!(sender.email_count, 5);
        assert_eq!(sender.messages.len(), 2);
    }

    #[test]
    fn merge_replaces_urls_with_later_folder_and_deduplicates_mailtos() {
        // The second folder's URLs replace the first (last-merged wins).
        // Mailtos are still deduped across folders.
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let folder1 = FolderResult {
            senders: HashMap::from([(
                "a@test.com".to_string(),
                make_sender(
                    "a@test.com", 1,
                    vec!["https://test.com/unsub?token=old"],
                    vec!["mailto:unsub@test.com"],
                    false, "", vec![],
                ),
            )]),
            warnings: vec![],
        };

        let folder2 = FolderResult {
            senders: HashMap::from([(
                "a@test.com".to_string(),
                make_sender(
                    "a@test.com", 1,
                    vec!["https://test.com/unsub?token=new"],
                    vec!["mailto:unsub@test.com"],
                    false, "", vec![],
                ),
            )]),
            warnings: vec![],
        };

        merge_folder_result(&mut combined, folder1);
        merge_folder_result(&mut combined, folder2);

        let sender = &combined["a@test.com"];
        // folder2's URL replaces folder1's
        assert_eq!(sender.unsubscribe_urls, vec!["https://test.com/unsub?token=new"]);
        // mailtos are still deduped
        assert_eq!(sender.unsubscribe_mailto.len(), 1);
    }

    #[test]
    fn merge_most_recent_url_wins_across_folders() {
        // Verify the specific scenario: a sender with different URLs per folder —
        // the last-merged folder's URL is the one that wins.
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let old_folder = FolderResult {
            senders: HashMap::from([(
                "news@example.com".to_string(),
                make_sender(
                    "news@example.com", 1,
                    vec!["https://example.com/unsub?t=expired"],
                    vec![],
                    false, "Example", vec![],
                ),
            )]),
            warnings: vec![],
        };

        let new_folder = FolderResult {
            senders: HashMap::from([(
                "news@example.com".to_string(),
                make_sender(
                    "news@example.com", 1,
                    vec!["https://example.com/unsub?t=fresh"],
                    vec![],
                    false, "Example", vec![],
                ),
            )]),
            warnings: vec![],
        };

        merge_folder_result(&mut combined, old_folder);
        merge_folder_result(&mut combined, new_folder);

        let sender = &combined["news@example.com"];
        assert_eq!(
            sender.unsubscribe_urls,
            vec!["https://example.com/unsub?t=fresh"],
            "most recently merged folder's URL should win"
        );
    }

    #[test]
    fn merge_display_name_first_non_empty_wins() {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        // First folder has empty display name
        let folder1 = FolderResult {
            senders: HashMap::from([(
                "b@test.com".to_string(),
                make_sender("b@test.com", 1, vec![], vec![], false, "", vec![]),
            )]),
            warnings: vec![],
        };

        // Second folder has a display name
        let folder2 = FolderResult {
            senders: HashMap::from([(
                "b@test.com".to_string(),
                make_sender("b@test.com", 1, vec![], vec![], false, "Beta News", vec![]),
            )]),
            warnings: vec![],
        };

        merge_folder_result(&mut combined, folder1);
        merge_folder_result(&mut combined, folder2);

        assert_eq!(combined["b@test.com"].display_name, "Beta News");
    }

    #[test]
    fn merge_one_click_flag_ored_across_folders() {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let folder1 = FolderResult {
            senders: HashMap::from([(
                "c@test.com".to_string(),
                make_sender("c@test.com", 1, vec![], vec![], false, "", vec![]),
            )]),
            warnings: vec![],
        };

        let folder2 = FolderResult {
            senders: HashMap::from([(
                "c@test.com".to_string(),
                make_sender("c@test.com", 1, vec![], vec![], true, "", vec![]),
            )]),
            warnings: vec![],
        };

        merge_folder_result(&mut combined, folder1);
        merge_folder_result(&mut combined, folder2);

        assert!(combined["c@test.com"].one_click);
    }

    #[test]
    fn merge_single_folder_adds_sender_to_map() {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let folder = FolderResult {
            senders: HashMap::from([(
                "only@test.com".to_string(),
                make_sender(
                    "only@test.com", 5,
                    vec!["https://test.com/unsub"],
                    vec!["mailto:leave@test.com"],
                    true, "Only Sender",
                    vec![FolderMessage {
                        folder: Folder::new("INBOX"),
                        message_id: MessageId::new("INBOX:10:500"),
                    }],
                ),
            )]),
            warnings: vec!["some warning".to_string()],
        };

        let warnings = merge_folder_result(&mut combined, folder);

        assert_eq!(combined.len(), 1);
        let sender = &combined["only@test.com"];
        assert_eq!(sender.email_count, 5);
        assert_eq!(sender.display_name, "Only Sender");
        assert!(sender.one_click);
        assert_eq!(sender.unsubscribe_urls, vec!["https://test.com/unsub"]);
        assert_eq!(sender.unsubscribe_mailto, vec!["mailto:leave@test.com"]);
        assert_eq!(sender.messages.len(), 1);
        assert_eq!(warnings, vec!["some warning"]);
    }

    #[test]
    fn merge_returns_warnings_from_folder_result() {
        let mut combined: HashMap<String, SenderInfo> = HashMap::new();

        let folder = FolderResult {
            senders: HashMap::new(),
            warnings: vec!["warn1".to_string(), "warn2".to_string()],
        };

        let warnings = merge_folder_result(&mut combined, folder);
        assert_eq!(warnings, vec!["warn1", "warn2"]);
    }

    // -----------------------------------------------------------------------
    // TestProgress infrastructure verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_records_calls() {
        let progress = TestProgress::new();
        let folder = Folder::new("INBOX");

        progress.on_folder_start(&folder, 100);
        progress.on_messages_scanned(&folder, 50);
        progress.on_messages_scanned(&folder, 50);
        progress.on_folder_done(&folder);

        let calls = progress.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], ProgressCall::FolderStart { folder: "INBOX".to_string(), total: 100 });
        assert_eq!(calls[1], ProgressCall::MessagesScanned { folder: "INBOX".to_string(), count: 50 });
        assert_eq!(calls[2], ProgressCall::MessagesScanned { folder: "INBOX".to_string(), count: 50 });
        assert_eq!(calls[3], ProgressCall::FolderDone { folder: "INBOX".to_string() });
    }
}
