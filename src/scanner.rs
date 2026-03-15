use anyhow::{bail, Context, Result};
use imap::Session;
use indicatif::{ProgressBar, ProgressStyle};
use mail_parser::MessageParser;
use native_tls::TlsStream;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::net::TcpStream;
use url::Url;

use crate::config::Config;

/// Represents a sender with unsubscribe information
#[derive(Debug, Clone)]
pub struct SenderInfo {
    /// Display name or email address
    pub display_name: String,
    /// Email address of the sender
    pub email: String,
    /// Domain extracted from the sender email
    pub domain: String,
    /// Unsubscribe URLs found (from List-Unsubscribe header)
    pub unsubscribe_urls: Vec<String>,
    /// Mailto unsubscribe addresses
    pub unsubscribe_mailto: Vec<String>,
    /// Whether RFC 8058 one-click unsubscribe is supported
    pub one_click: bool,
    /// Number of emails from this sender
    pub email_count: u32,
    /// IMAP UIDs of emails from this sender (folder -> UIDs)
    pub uids: HashMap<String, Vec<u32>>,
    /// UIDVALIDITY per folder (to verify UIDs are still valid)
    pub uid_validity: HashMap<String, u32>,
}

/// Connect to IMAP server and return an authenticated session
fn connect(config: &Config) -> Result<Session<TlsStream<TcpStream>>> {
    let tls = native_tls::TlsConnector::builder().build()?;
    let client = imap::connect(
        (config.imap.host.as_str(), config.imap.port),
        &config.imap.host,
        &tls,
    )
    .context("Failed to connect to IMAP server")?;

    let session = client
        .login(&config.imap.username, &config.imap.password)
        .map_err(|e| anyhow::anyhow!("IMAP login failed: {}", e.0))?;

    Ok(session)
}

/// Decode RFC 2047 encoded words in a header value.
/// Handles `=?charset?Q?encoded?=` (quoted-printable) and `=?charset?B?encoded?=` (base64).
fn decode_rfc2047(input: &str) -> String {
    // First, unfold the header: remove CRLF + leading whitespace on continuation lines
    let unfolded = input
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ")
        .replace("\n ", " ")
        .replace("\n\t", " ");

    let mut result = String::new();
    let mut remaining = unfolded.as_str();
    let mut last_was_encoded = false;

    while let Some(start) = remaining.find("=?") {
        let before = &remaining[..start];
        // Per RFC 2047: whitespace between adjacent encoded-words is ignored
        if !last_was_encoded || !before.trim().is_empty() {
            result.push_str(before);
        }
        remaining = &remaining[start + 2..];

        // Parse charset
        let Some(q1) = remaining.find('?') else {
            result.push_str("=?");
            last_was_encoded = false;
            continue;
        };
        let _charset = &remaining[..q1];
        remaining = &remaining[q1 + 1..];

        // Parse encoding
        let Some(q2) = remaining.find('?') else {
            result.push_str("=?");
            result.push_str(_charset);
            result.push('?');
            last_was_encoded = false;
            continue;
        };
        let encoding = &remaining[..q2];
        remaining = &remaining[q2 + 1..];

        // Parse encoded text until ?=
        let Some(end) = remaining.find("?=") else {
            last_was_encoded = false;
            continue;
        };
        let encoded_text = &remaining[..end];
        remaining = &remaining[end + 2..];

        match encoding.to_uppercase().as_str() {
            "Q" => {
                let mut chars = encoded_text.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '=' => {
                            let h1 = chars.next();
                            let h2 = chars.next();
                            if let (Some(h1), Some(h2)) = (h1, h2) {
                                let hex = format!("{h1}{h2}");
                                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                    result.push(byte as char);
                                }
                            }
                        }
                        '_' => result.push(' '),
                        _ => result.push(c),
                    }
                }
            }
            "B" => {
                // Base64 decoding - less common but handle it
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded_text)
                {
                    result.push_str(&String::from_utf8_lossy(&decoded));
                }
            }
            _ => {
                result.push_str(encoded_text);
            }
        }
        last_was_encoded = true;
    }

    result.push_str(remaining);
    result
}

/// Extract unsubscribe URLs from a List-Unsubscribe header value.
/// Format: `<https://example.com/unsub>, <mailto:unsub@example.com>`
/// Result of parsing a List-Unsubscribe header, including any warning
struct ParsedUnsub {
    urls: Vec<String>,
    mailtos: Vec<String>,
    warning: Option<String>,
}

fn parse_list_unsubscribe(header_value: &str, sender_email: &str) -> ParsedUnsub {
    // Decode RFC 2047 encoded words first
    let decoded = decode_rfc2047(header_value);

    let mut urls = Vec::new();
    let mut mailtos = Vec::new();
    let mut had_unparsed = false;

    for part in decoded.split(',') {
        let trimmed = part.trim().trim_start_matches('<').trim_end_matches('>');
        if trimmed.starts_with("mailto:") {
            mailtos.push(trimmed.to_string());
        } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_string());
        } else if !trimmed.is_empty() {
            had_unparsed = true;
        }
    }

    let warning = if urls.is_empty() && mailtos.is_empty() && had_unparsed {
        Some(format!("{sender_email}: {decoded}"))
    } else {
        None
    };

    ParsedUnsub { urls, mailtos, warning }
}

/// Extract domain from an email address
fn domain_from_email(email: &str) -> String {
    email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_lowercase())
        .unwrap_or_else(|| email.to_lowercase())
}

/// Result of scanning, including any warnings about unparseable headers
pub struct ScanResult {
    pub senders: Vec<SenderInfo>,
    pub warnings: Vec<String>,
}

/// Scan all configured folders and return sender info grouped by sender email
pub fn scan(config: &Config) -> Result<ScanResult> {
    let mut session = connect(config)?;
    let mut senders: HashMap<String, SenderInfo> = HashMap::new();
    let mut warnings: Vec<String> = Vec::new();
    let parser = MessageParser::default();

    // Track UIDVALIDITY per folder for safety checks during archive
    let mut uid_validities: HashMap<String, u32> = HashMap::new();

    for folder in &config.scan.folders {
        eprintln!("Scanning folder: {folder}");
        let mailbox = session
            .select(folder)
            .with_context(|| format!("Failed to select folder: {folder}"))?;

        let total = mailbox.exists;
        if total == 0 {
            eprintln!("  (empty)");
            continue;
        }

        if let Some(validity) = mailbox.uid_validity {
            uid_validities.insert(folder.clone(), validity);
        }

        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  [{bar:40}] {pos}/{len} emails scanned")
                .unwrap()
                .progress_chars("=> "),
        );

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
                pb.inc(1);

                let Some(uid) = msg.uid else { continue };
                let Some(header_bytes) = msg.header() else {
                    continue;
                };
                let Some(parsed) = parser.parse(header_bytes) else {
                    continue;
                };

                // Check for List-Unsubscribe header
                let Some(unsub_header) = parsed.header_raw("List-Unsubscribe") else {
                    continue;
                };
                let unsub_header = unsub_header.to_string();

                let has_one_click = parsed.header_raw("List-Unsubscribe-Post").is_some();

                // Extract sender info
                let Some(from) = parsed.from() else {
                    continue;
                };
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
                        uids: HashMap::new(),
                        uid_validity: HashMap::new(),
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
                entry.uids.entry(folder.clone()).or_default().push(uid);

                // Store UIDVALIDITY for this folder
                if let Some(&validity) = uid_validities.get(folder.as_str()) {
                    entry.uid_validity.insert(folder.clone(), validity);
                }

                // Update display name if we got a better one
                if entry.display_name.is_empty() && !sender_name.is_empty() {
                    entry.display_name = sender_name;
                }
            }

            start = end + 1;
        }

        pb.finish();
    }

    session.logout().ok();

    let mut senders: Vec<SenderInfo> = senders.into_values().collect();
    senders.sort_by(|a, b| b.email_count.cmp(&a.email_count));
    Ok(ScanResult { senders, warnings })
}

/// Keywords that indicate an unsubscribe-related form or link
const UNSUB_KEYWORDS: &[&str] = &[
    "unsubscribe",
    "opt-out",
    "opt out",
    "remove me",
    "confirm",
    "manage preferences",
    "email preferences",
];

/// Try to follow through on a confirmation page by finding and submitting forms or links.
/// Returns Some((method, success, detail)) if a follow-through was attempted.
fn try_confirm_page(
    client: &reqwest::blocking::Client,
    page_url: &str,
    body: &str,
) -> Option<(String, bool, String)> {
    let document = Html::parse_document(body);

    // Strategy 1: Look for forms (like Klaviyo's unsubscribe form)
    let form_sel = Selector::parse("form").ok()?;
    let input_sel = Selector::parse("input").ok()?;

    for form in document.select(&form_sel) {
        // Check if this form looks unsubscribe-related
        let form_html = form.html().to_lowercase();
        let is_unsub_form = UNSUB_KEYWORDS
            .iter()
            .any(|kw| form_html.contains(kw));

        if !is_unsub_form {
            continue;
        }

        // Determine form action URL (default: same page)
        let action = form
            .value()
            .attr("action")
            .unwrap_or("");
        let form_url = if action.is_empty() || action == "." {
            page_url.to_string()
        } else if action.starts_with("http") {
            action.to_string()
        } else {
            // Resolve relative URL
            match Url::parse(page_url) {
                Ok(base) => base.join(action).map(|u| u.to_string()).unwrap_or_else(|_| page_url.to_string()),
                Err(_) => page_url.to_string(),
            }
        };

        // Collect form fields
        let mut params: Vec<(String, String)> = Vec::new();
        for input in form.select(&input_sel) {
            let name = input.value().attr("name").unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
            let value = input.value().attr("value").unwrap_or("").to_string();

            match input_type.as_str() {
                "email" => {
                    // Leave empty — the URL itself identifies the subscriber
                    params.push((name.to_string(), value));
                }
                "hidden" => {
                    params.push((name.to_string(), value));
                }
                "submit" => {
                    // Include submit button value if it has a name
                    if !value.is_empty() {
                        params.push((name.to_string(), value));
                    }
                }
                "checkbox" => {
                    // Check if it's pre-checked
                    if input.value().attr("checked").is_some() {
                        params.push((name.to_string(), value));
                    }
                }
                _ => {
                    params.push((name.to_string(), value));
                }
            }
        }

        // Submit the form
        let method = form
            .value()
            .attr("method")
            .unwrap_or("POST")
            .to_uppercase();

        let result = if method == "GET" {
            client.get(&form_url).query(&params).send()
        } else {
            client.post(&form_url).form(&params).send()
        };

        match result {
            Ok(resp) => {
                let status = resp.status();
                return Some((
                    format!("form {method}"),
                    status.is_success(),
                    format!("HTTP {status} (confirmation form)"),
                ));
            }
            Err(e) => {
                return Some((
                    format!("form {method}"),
                    false,
                    format!("Form submit error: {e}"),
                ));
            }
        }
    }

    // Strategy 2: Look for unsubscribe/confirm links
    let link_sel = Selector::parse("a[href]").ok()?;
    for link in document.select(&link_sel) {
        let text = link.text().collect::<String>().to_lowercase();
        let href = link.value().attr("href").unwrap_or("");

        let is_unsub_link = UNSUB_KEYWORDS.iter().any(|kw| text.contains(kw))
            || UNSUB_KEYWORDS.iter().any(|kw| href.to_lowercase().contains(kw));

        if !is_unsub_link || href.is_empty() {
            continue;
        }

        let link_url = if href.starts_with("http") {
            href.to_string()
        } else {
            match Url::parse(page_url) {
                Ok(base) => base.join(href).map(|u| u.to_string()).unwrap_or_default(),
                Err(_) => continue,
            }
        };

        match client.get(&link_url).send() {
            Ok(resp) => {
                let status = resp.status();
                return Some((
                    "confirm link".to_string(),
                    status.is_success(),
                    format!("HTTP {status} (confirmation link)"),
                ));
            }
            Err(e) => {
                return Some((
                    "confirm link".to_string(),
                    false,
                    format!("Confirm link error: {e}"),
                ));
            }
        }
    }

    None
}

/// Unsubscribe from the given senders by visiting their unsubscribe URLs
pub fn unsubscribe(senders: &[&SenderInfo], dry_run: bool) -> Vec<UnsubscribeResult> {
    let mut results = Vec::new();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to build HTTP client");

    let pb = ProgressBar::new(senders.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:40}] {pos}/{len} unsubscribing")
            .unwrap()
            .progress_chars("=> "),
    );

    for sender in senders {
        pb.inc(1);

        let unsub_url = sender
            .unsubscribe_urls
            .first()
            .or(sender.unsubscribe_mailto.first())
            .cloned()
            .unwrap_or_default();

        if dry_run {
            results.push(UnsubscribeResult {
                email: sender.email.clone(),
                method: "dry-run".to_string(),
                success: true,
                detail: "Would unsubscribe".to_string(),
                url: unsub_url,
            });
            continue;
        }

        // Try one-click POST first (RFC 8058)
        if sender.one_click {
            if let Some(url) = sender.unsubscribe_urls.first() {
                match client
                    .post(url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body("List-Unsubscribe=One-Click")
                    .send()
                {
                    Ok(resp) => {
                        results.push(UnsubscribeResult {
                            email: sender.email.clone(),
                            method: "one-click POST".to_string(),
                            success: resp.status().is_success(),
                            detail: format!("HTTP {}", resp.status()),
                            url: unsub_url,
                        });
                        continue;
                    }
                    Err(e) => {
                        eprintln!("  One-click failed for {}: {e}", sender.email);
                        // Fall through to GET
                    }
                }
            }
        }

        // Fall back to GET on https URLs, then try confirmation page follow-through
        if let Some(url) = sender.unsubscribe_urls.first() {
            match client.get(url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        // Check if this is a confirmation page we need to follow through on
                        if let Ok(body) = resp.text() {
                            if let Some((method, success, detail)) =
                                try_confirm_page(&client, url, &body)
                            {
                                results.push(UnsubscribeResult {
                                    email: sender.email.clone(),
                                    method,
                                    success,
                                    detail,
                                    url: unsub_url,
                                });
                                continue;
                            }
                        }
                        // No confirmation needed or no form found — the GET itself was the unsub
                        results.push(UnsubscribeResult {
                            email: sender.email.clone(),
                            method: "GET".to_string(),
                            success: true,
                            detail: format!("HTTP {status}"),
                            url: unsub_url,
                        });
                    } else {
                        results.push(UnsubscribeResult {
                            email: sender.email.clone(),
                            method: "GET".to_string(),
                            success: status.is_redirection(),
                            detail: format!("HTTP {status}"),
                            url: unsub_url,
                        });
                    }
                    continue;
                }
                Err(e) => {
                    results.push(UnsubscribeResult {
                        email: sender.email.clone(),
                        method: "GET".to_string(),
                        success: false,
                        detail: format!("Error: {e}"),
                        url: unsub_url,
                    });
                    continue;
                }
            }
        }

        // No HTTP URL available
        if !sender.unsubscribe_mailto.is_empty() {
            results.push(UnsubscribeResult {
                email: sender.email.clone(),
                method: "mailto (skipped)".to_string(),
                success: false,
                detail: "Only mailto unsubscribe available — requires sending email".to_string(),
                url: unsub_url,
            });
        } else {
            results.push(UnsubscribeResult {
                email: sender.email.clone(),
                method: "none".to_string(),
                success: false,
                detail: "No unsubscribe URL found".to_string(),
                url: unsub_url,
            });
        }
    }

    pb.finish();
    results
}

#[derive(Debug)]
pub struct UnsubscribeResult {
    pub email: String,
    pub method: String,
    pub success: bool,
    pub detail: String,
    pub url: String,
}

/// Archive emails from the given senders by moving them to the archive folder
pub fn archive(config: &Config, senders: &[&SenderInfo], dry_run: bool) -> Result<u32> {
    if dry_run {
        let total: u32 = senders.iter().map(|s| s.email_count).sum();
        eprintln!("Dry run: would archive {total} emails to '{}'", config.scan.archive_folder);
        return Ok(total);
    }

    let mut session = connect(config)?;
    let archive_folder = &config.scan.archive_folder;

    // Create archive folder if it doesn't exist (ignore error if it already exists)
    session.create(archive_folder).ok();
    session.subscribe(archive_folder).ok();

    let mut archived = 0u32;

    for sender in senders {
        for (folder, uids) in &sender.uids {
            if uids.is_empty() {
                continue;
            }

            let mailbox = session
                .select(folder)
                .with_context(|| format!("Failed to select folder: {folder}"))?;

            // Verify UIDVALIDITY hasn't changed since scan
            if let Some(&expected) = sender.uid_validity.get(folder.as_str()) {
                if let Some(current) = mailbox.uid_validity {
                    if current != expected {
                        bail!(
                            "UIDVALIDITY changed for folder '{folder}' (was {expected}, now {current}). \
                             Aborting archive to avoid moving wrong emails. Please re-scan."
                        );
                    }
                }
            }

            let uid_list: Vec<String> = uids.iter().map(|u| u.to_string()).collect();

            // Process in chunks to avoid overly long IMAP commands
            for chunk in uid_list.chunks(100) {
                let uid_set = chunk.join(",");
                session
                    .uid_mv(&uid_set, archive_folder)
                    .with_context(|| {
                        format!("Failed to move emails from {folder} to {archive_folder}")
                    })?;
                archived += chunk.len() as u32;
            }
        }
    }

    session.logout().ok();
    Ok(archived)
}
