use anyhow::Result;
use scraper::{Html, Selector};
use url::Url;

use crate::types::{Folder, FolderMessage, HttpResponse, ScanResult, SenderInfo, UnsubscribeResult};

/// Port for email providers (IMAP, Gmail API, Exchange, Apple Accounts, etc.).
///
/// Adapters implement this trait to let core scan mailboxes and archive messages.
/// All methods are synchronous -- adapters own their own concurrency internally.
pub trait EmailProvider {
    /// Scan the given folders for senders with List-Unsubscribe headers.
    fn scan(&self, folders: &[Folder]) -> Result<ScanResult>;

    /// Move the given messages to the specified destination folder.
    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32>;
}

/// Port for HTTP operations needed during unsubscribe flows.
///
/// CLI provides this via reqwest, iOS via URLSession, tests via mocks.
pub trait HttpClient {
    /// Perform an HTTP GET request.
    fn get(&self, url: &str) -> Result<HttpResponse>;

    /// Perform an HTTP POST with form-encoded key-value pairs.
    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<HttpResponse>;

    /// Perform an HTTP POST with the given content-type and raw body.
    fn post_body(&self, url: &str, content_type: &str, body: &str) -> Result<HttpResponse>;
}

// ---------------------------------------------------------------------------
// Unsubscribe orchestration
// ---------------------------------------------------------------------------

/// Keywords that indicate an unsubscribe-related form or link on a confirmation page.
const UNSUB_KEYWORDS: &[&str] = &[
    "unsubscribe",
    "opt-out",
    "opt out",
    "remove me",
    "confirm",
    "manage preferences",
    "email preferences",
];

/// Attempt to unsubscribe from each sender using their List-Unsubscribe information.
///
/// Tries methods in priority order for each sender:
/// 1. RFC 8058 one-click POST (if supported)
/// 2. HTTP GET on the unsubscribe URL, with confirmation page follow-through
/// 3. Reports mailto-only senders as skipped (sending email is a consumer concern)
///
/// Core always executes -- dry-run filtering belongs in the consumer.
pub fn unsubscribe(senders: &[&SenderInfo], http: &dyn HttpClient) -> Vec<UnsubscribeResult> {
    senders.iter().map(|sender| unsubscribe_one(sender, http)).collect()
}

/// Run the unsubscribe flow for a single sender.
fn unsubscribe_one(sender: &SenderInfo, http: &dyn HttpClient) -> UnsubscribeResult {
    let fallback_url = sender
        .unsubscribe_urls
        .first()
        .or(sender.unsubscribe_mailto.first())
        .cloned()
        .unwrap_or_default();

    // Strategy 1: RFC 8058 one-click POST
    if sender.one_click {
        if let Some(url) = sender.unsubscribe_urls.first() {
            match http.post_body(
                url,
                "application/x-www-form-urlencoded",
                "List-Unsubscribe=One-Click",
            ) {
                Ok(resp) => {
                    return UnsubscribeResult {
                        email: sender.email.clone(),
                        method: "one-click POST".to_string(),
                        success: (200..300).contains(&resp.status),
                        detail: format!("HTTP {}", resp.status),
                        url: fallback_url,
                    };
                }
                Err(_) => {
                    // Fall through to GET
                }
            }
        }
    }

    // Strategy 2: GET the unsubscribe URL, then follow through on any confirmation page
    if let Some(url) = sender.unsubscribe_urls.first() {
        match http.get(url) {
            Ok(resp) => {
                let status = resp.status;
                if (200..300).contains(&status) {
                    // Check if the page is a confirmation form we need to submit
                    if let Some((method, success, detail)) =
                        try_confirm_page(http, url, &resp.body)
                    {
                        return UnsubscribeResult {
                            email: sender.email.clone(),
                            method,
                            success,
                            detail,
                            url: fallback_url,
                        };
                    }
                    // No confirmation needed -- the GET itself was the unsubscribe
                    return UnsubscribeResult {
                        email: sender.email.clone(),
                        method: "GET".to_string(),
                        success: true,
                        detail: format!("HTTP {status}"),
                        url: fallback_url,
                    };
                } else {
                    return UnsubscribeResult {
                        email: sender.email.clone(),
                        method: "GET".to_string(),
                        success: (300..400).contains(&status),
                        detail: format!("HTTP {status}"),
                        url: fallback_url,
                    };
                }
            }
            Err(e) => {
                return UnsubscribeResult {
                    email: sender.email.clone(),
                    method: "GET".to_string(),
                    success: false,
                    detail: format!("Error: {e}"),
                    url: fallback_url,
                };
            }
        }
    }

    // Strategy 3: mailto-only senders
    if !sender.unsubscribe_mailto.is_empty() {
        return UnsubscribeResult {
            email: sender.email.clone(),
            method: "mailto (skipped)".to_string(),
            success: false,
            detail: "Only mailto unsubscribe available — requires sending email".to_string(),
            url: fallback_url,
        };
    }

    // No unsubscribe mechanism at all
    UnsubscribeResult {
        email: sender.email.clone(),
        method: "none".to_string(),
        success: false,
        detail: "No unsubscribe URL found".to_string(),
        url: fallback_url,
    }
}

/// Analyze an HTML page for unsubscribe confirmation forms or links and follow through.
///
/// Tries two strategies:
/// 1. Find and submit forms that contain unsubscribe-related keywords
/// 2. Follow links that contain unsubscribe-related keywords
///
/// Returns `Some((method, success, detail))` if a follow-through was attempted.
fn try_confirm_page(
    http: &dyn HttpClient,
    page_url: &str,
    body: &str,
) -> Option<(String, bool, String)> {
    let document = Html::parse_document(body);

    // Strategy 1: Submit unsubscribe-related forms
    if let Some(result) = try_submit_form(http, page_url, &document) {
        return Some(result);
    }

    // Strategy 2: Follow unsubscribe-related links
    try_follow_link(http, page_url, &document)
}

/// Look for forms containing unsubscribe keywords and submit the first match.
fn try_submit_form(
    http: &dyn HttpClient,
    page_url: &str,
    document: &Html,
) -> Option<(String, bool, String)> {
    let form_sel = Selector::parse("form").ok()?;
    let input_sel = Selector::parse("input").ok()?;

    for form in document.select(&form_sel) {
        let form_html = form.html().to_lowercase();
        let is_unsub_form = UNSUB_KEYWORDS.iter().any(|kw| form_html.contains(kw));
        if !is_unsub_form {
            continue;
        }

        let action = form.value().attr("action").unwrap_or("");
        let form_url = resolve_url(page_url, action);

        // Collect form fields
        let params: Vec<(String, String)> = form
            .select(&input_sel)
            .filter_map(|input| {
                let name = input.value().attr("name").unwrap_or("");
                if name.is_empty() {
                    return None;
                }
                let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
                let value = input.value().attr("value").unwrap_or("").to_string();

                match input_type.as_str() {
                    "checkbox" if input.value().attr("checked").is_none() => None,
                    "submit" if value.is_empty() => None,
                    _ => Some((name.to_string(), value)),
                }
            })
            .collect();

        let method = form
            .value()
            .attr("method")
            .unwrap_or("POST")
            .to_uppercase();

        let param_refs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let result = if method == "GET" {
            // Build the URL with query params for GET forms
            let mut get_url = form_url.clone();
            if !param_refs.is_empty() {
                let query: Vec<String> = param_refs
                    .iter()
                    .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
                    .collect();
                let sep = if get_url.contains('?') { "&" } else { "?" };
                get_url = format!("{get_url}{sep}{}", query.join("&"));
            }
            http.get(&get_url)
        } else {
            http.post_form(&form_url, &param_refs)
        };

        return match result {
            Ok(resp) => Some((
                format!("form {method}"),
                (200..300).contains(&resp.status),
                format!("HTTP {} (confirmation form)", resp.status),
            )),
            Err(e) => Some((
                format!("form {method}"),
                false,
                format!("Form submit error: {e}"),
            )),
        };
    }

    None
}

/// Look for links containing unsubscribe keywords and follow the first match.
fn try_follow_link(
    http: &dyn HttpClient,
    page_url: &str,
    document: &Html,
) -> Option<(String, bool, String)> {
    let link_sel = Selector::parse("a[href]").ok()?;

    for link in document.select(&link_sel) {
        let text = link.text().collect::<String>().to_lowercase();
        let href = link.value().attr("href").unwrap_or("");

        let is_unsub_link = UNSUB_KEYWORDS.iter().any(|kw| text.contains(kw))
            || UNSUB_KEYWORDS.iter().any(|kw| href.to_lowercase().contains(kw));

        if !is_unsub_link || href.is_empty() {
            continue;
        }

        let link_url = resolve_url(page_url, href);

        return match http.get(&link_url) {
            Ok(resp) => Some((
                "confirm link".to_string(),
                (200..300).contains(&resp.status),
                format!("HTTP {} (confirmation link)", resp.status),
            )),
            Err(e) => Some((
                "confirm link".to_string(),
                false,
                format!("Confirm link error: {e}"),
            )),
        };
    }

    None
}

/// Resolve a possibly-relative URL against a base page URL.
fn resolve_url(page_url: &str, target: &str) -> String {
    if target.is_empty() || target == "." {
        return page_url.to_string();
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    Url::parse(page_url)
        .ok()
        .and_then(|base| base.join(target).ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| page_url.to_string())
}

/// Minimal percent-encoding for URL query parameter components.
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}
