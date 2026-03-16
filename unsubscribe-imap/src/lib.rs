use std::collections::HashMap;
use std::net::TcpStream;

use anyhow::{bail, Context, Result};
use imap::Session;
use mail_parser::MessageParser;
use native_tls::TlsStream;

use unsubscribe_core::{
    domain_from_email, parse_list_unsubscribe, EmailProvider, Folder, FolderMessage, MessageId,
    ScanProgress, ScanResult, SenderInfo,
};

/// IMAP adapter for the `EmailProvider` trait.
///
/// Connects to an IMAP server over TLS and scans mailboxes for senders
/// with List-Unsubscribe headers. Spawns one thread per folder for parallelism.
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

        // Use scoped threads so the progress reference can be shared safely
        std::thread::scope(|s| {
            let handles: Vec<_> = folders
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

        let mut senders: Vec<SenderInfo> = combined.into_values().collect();
        senders.sort_by(|a, b| b.email_count.cmp(&a.email_count));

        Ok(ScanResult { senders, warnings: all_warnings })
    }

    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32> {
        let mut session = self.connect()?;
        let dest = destination.as_str();

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
                session
                    .uid_mv(&uid_set, dest)
                    .with_context(|| {
                        format!("Failed to move emails from {folder} to {dest}")
                    })?;
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
            .fetch(&sequence, "(UID BODY.PEEK[HEADER])")
            .with_context(|| format!("Failed to fetch messages {start}:{end}"))?;

        for msg in messages.iter() {
            progress.on_messages_scanned(folder, 1);

            let Some(uid) = msg.uid else { continue };
            let Some(header_bytes) = msg.header() else { continue };
            let Some(parsed) = parser.parse(header_bytes) else { continue };

            let Some(unsub_header) = parsed.header_raw("List-Unsubscribe") else {
                continue;
            };
            let unsub_header = unsub_header.to_string();

            let has_one_click = parsed.header_raw("List-Unsubscribe-Post").is_some();

            let Some(from) = parsed.from() else { continue };
            let Some(first) = from.clone().into_list().into_iter().next() else {
                continue;
            };
            let sender_name = first.name().unwrap_or("").to_string();
            let sender_email = first.address().unwrap_or("unknown").to_string();

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
                }
            });

            // Merge URLs (dedup)
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
                folder: folder.clone(),
                message_id,
            });

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
        });

        for u in &sender.unsubscribe_urls {
            if !entry.unsubscribe_urls.contains(u) {
                entry.unsubscribe_urls.push(u.clone());
            }
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

