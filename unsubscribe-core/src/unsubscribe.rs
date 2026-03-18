use scraper::{Html, Selector};
use url::{Url, form_urlencoded};

use crate::ports::HttpClient;
use crate::types::{SenderInfo, UnsubscribeResult};

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
#[must_use]
pub fn unsubscribe(senders: &[&SenderInfo], http: &dyn HttpClient) -> Vec<UnsubscribeResult> {
    senders.iter().map(|sender| unsubscribe_one(sender, http)).collect()
}

/// Run the unsubscribe flow for a single sender.
fn unsubscribe_one(sender: &SenderInfo, http: &dyn HttpClient) -> UnsubscribeResult {
    let fallback_url = sender
        .best_unsubscribe_url()
        .unwrap_or_default()
        .to_string();

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
            let get_url = if param_refs.is_empty() {
                form_url.clone()
            } else {
                let query = form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(param_refs.iter().copied())
                    .finish();
                let sep = if form_url.contains('?') { "&" } else { "?" };
                format!("{form_url}{sep}{query}")
            };
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpResponse;
    use anyhow::{Result, bail};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // MockHttpClient
    // -----------------------------------------------------------------------

    /// Mock HTTP client with configurable per-URL responses and error injection.
    struct MockHttpClient {
        /// Map from URL to (status, body). If a URL is absent, the request errors.
        responses: Mutex<HashMap<String, (u16, String)>>,
        /// URLs that should return an error instead of a response.
        errors: Mutex<HashMap<String, String>>,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
                errors: Mutex::new(HashMap::new()),
            }
        }

        fn on_url(self, url: &str, status: u16, body: &str) -> Self {
            self.responses
                .lock()
                .unwrap()
                .insert(url.to_string(), (status, body.to_string()));
            self
        }

        fn error_on(self, url: &str, msg: &str) -> Self {
            self.errors
                .lock()
                .unwrap()
                .insert(url.to_string(), msg.to_string());
            self
        }

        fn respond(&self, url: &str) -> Result<HttpResponse> {
            if let Some(msg) = self.errors.lock().unwrap().get(url) {
                bail!("{msg}");
            }
            if let Some((status, body)) = self.responses.lock().unwrap().get(url) {
                Ok(HttpResponse {
                    status: *status,
                    body: body.clone(),
                })
            } else {
                bail!("No mock response configured for {url}");
            }
        }
    }

    impl HttpClient for MockHttpClient {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.respond(url)
        }
        fn get_with_headers(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
            self.respond(url)
        }
        fn post_form(&self, url: &str, _params: &[(&str, &str)]) -> Result<HttpResponse> {
            self.respond(url)
        }
        fn post_body(&self, url: &str, _content_type: &str, _body: &str) -> Result<HttpResponse> {
            self.respond(url)
        }
        fn post_body_with_headers(
            &self,
            url: &str,
            _content_type: &str,
            _body: &str,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse> {
            self.respond(url)
        }
    }

    /// Helper to build a SenderInfo for testing.
    fn make_sender(
        email: &str,
        urls: Vec<&str>,
        mailtos: Vec<&str>,
        one_click: bool,
    ) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: urls.into_iter().map(String::from).collect(),
            unsubscribe_mailto: mailtos.into_iter().map(String::from).collect(),
            one_click,
            email_count: 1,
            messages: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // Unsubscribe orchestration
    // -----------------------------------------------------------------------

    #[test]
    fn one_click_post_succeeds() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, "");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            true,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(result.success);
        assert_eq!(result.method, "one-click POST");
        assert_eq!(result.detail, "HTTP 200");
    }

    #[test]
    fn one_click_post_non_2xx_is_failure() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 500, "");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            true,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.method, "one-click POST");
    }

    #[test]
    fn one_click_post_error_falls_through_to_get() {
        let http = MockHttpClient::new()
            .error_on("https://example.com/unsub", "connection refused")
            // The GET for the same URL succeeds
            // Note: MockHttpClient uses same URL for all methods, but the
            // error is only injected once. We need a different approach.
            ;
        // Since our mock returns error for all methods on the URL, the GET
        // will also fail. Let's verify the fallthrough logic differently:
        // one_click with error -> falls to GET -> GET also errors -> failure
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            true,
        );

        let result = unsubscribe_one(&sender, &http);
        // POST errored, fell through to GET, GET also errored
        assert!(!result.success);
        assert_eq!(result.method, "GET");
        assert!(result.detail.contains("Error:"));
    }

    #[test]
    fn get_succeeds_no_confirmation_page() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, "<html><body>You are unsubscribed.</body></html>");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(result.success);
        assert_eq!(result.method, "GET");
        assert_eq!(result.detail, "HTTP 200");
    }

    #[test]
    fn get_succeeds_with_confirmation_form() {
        let form_html = r#"<html><body>
            <form action="https://example.com/confirm" method="POST">
                <input type="hidden" name="token" value="abc123">
                <input type="submit" name="action" value="Unsubscribe">
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, form_html)
            .on_url("https://example.com/confirm", 200, "Done");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(result.success);
        assert_eq!(result.method, "form POST");
        assert!(result.detail.contains("confirmation form"));
    }

    #[test]
    fn get_succeeds_with_confirmation_link() {
        let link_html = r#"<html><body>
            <a href="https://example.com/confirm-unsub">Click to unsubscribe</a>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, link_html)
            .on_url("https://example.com/confirm-unsub", 200, "Done");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(result.success);
        assert_eq!(result.method, "confirm link");
    }

    #[test]
    fn get_3xx_treated_as_success() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 302, "");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(result.success);
        assert_eq!(result.method, "GET");
    }

    #[test]
    fn get_304_treated_as_success() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 304, "");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        // 304 is in 300..400 range, so treated as success
        assert!(result.success);
    }

    #[test]
    fn get_4xx_is_failure() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 404, "Not Found");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.detail, "HTTP 404");
    }

    #[test]
    fn get_5xx_is_failure() {
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 500, "Internal Server Error");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.detail, "HTTP 500");
    }

    #[test]
    fn get_error_is_failure_with_detail() {
        let http = MockHttpClient::new()
            .error_on("https://example.com/unsub", "DNS resolution failed");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec![],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.method, "GET");
        assert!(result.detail.contains("DNS resolution failed"));
    }

    #[test]
    fn mailto_only_is_skipped() {
        let http = MockHttpClient::new();
        let sender = make_sender(
            "news@example.com",
            vec![],
            vec!["mailto:unsub@example.com"],
            false,
        );

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.method, "mailto (skipped)");
        assert!(result.detail.contains("mailto"));
    }

    #[test]
    fn no_urls_at_all() {
        let http = MockHttpClient::new();
        let sender = make_sender("news@example.com", vec![], vec![], false);

        let result = unsubscribe_one(&sender, &http);
        assert!(!result.success);
        assert_eq!(result.method, "none");
        assert!(result.detail.contains("No unsubscribe URL found"));
    }

    #[test]
    fn strategy_priority_one_click_before_get() {
        // one-click succeeds, so GET should never be reached
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, "");
        let sender = make_sender(
            "news@example.com",
            vec!["https://example.com/unsub"],
            vec!["mailto:unsub@example.com"],
            true,
        );

        let result = unsubscribe_one(&sender, &http);
        assert_eq!(result.method, "one-click POST");
        assert!(result.success);
    }

    #[test]
    fn multiple_senders_processed() {
        let http = MockHttpClient::new()
            .on_url("https://a.com/unsub", 200, "")
            .on_url("https://b.com/unsub", 200, "");
        let sender_a = make_sender("a@a.com", vec!["https://a.com/unsub"], vec![], false);
        let sender_b = make_sender("b@b.com", vec!["https://b.com/unsub"], vec![], false);
        let senders: Vec<&SenderInfo> = vec![&sender_a, &sender_b];

        let results = unsubscribe(&senders, &http);
        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);
        assert_eq!(results[0].email, "a@a.com");
        assert_eq!(results[1].email, "b@b.com");
    }

    // -----------------------------------------------------------------------
    // Confirmation page analysis
    // -----------------------------------------------------------------------

    #[test]
    fn form_with_unsubscribe_keyword_submits() {
        let html = r#"<html><body>
            <form action="https://example.com/do-unsub" method="POST">
                <input type="hidden" name="token" value="xyz">
                <button type="submit">Unsubscribe</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/do-unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (method, success, _) = result.unwrap();
        assert_eq!(method, "form POST");
        assert!(success);
    }

    #[test]
    fn form_without_keyword_skipped() {
        let html = r#"<html><body>
            <form action="https://example.com/login" method="POST">
                <input type="text" name="username">
                <button type="submit">Login</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new();

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_none());
    }

    #[test]
    fn multiple_forms_first_match_wins() {
        let html = r#"<html><body>
            <form action="https://example.com/login">
                <input type="text" name="user">
            </form>
            <form action="https://example.com/unsub1">
                <input type="hidden" name="t" value="1">
                <button>Unsubscribe</button>
            </form>
            <form action="https://example.com/unsub2">
                <input type="hidden" name="t" value="2">
                <button>Opt out</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub1", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        // First unsub form was unsub1
        let (_, success, _) = result.unwrap();
        assert!(success);
    }

    #[test]
    fn get_form_builds_query_string() {
        let html = r#"<html><body>
            <form action="https://example.com/unsub" method="GET">
                <input type="hidden" name="email" value="test@test.com">
                <input type="submit" name="action" value="Unsubscribe">
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url(
                "https://example.com/unsub?email=test%40test.com&action=Unsubscribe",
                200,
                "Done",
            );

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (method, success, _) = result.unwrap();
        assert_eq!(method, "form GET");
        assert!(success);
    }

    #[test]
    fn post_form_default_method() {
        // Forms without explicit method default to POST
        let html = r#"<html><body>
            <form action="https://example.com/unsub">
                <input type="hidden" name="token" value="abc">
                <button>Confirm unsubscribe</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (method, _, _) = result.unwrap();
        assert_eq!(method, "form POST");
    }

    #[test]
    fn form_empty_action_resolves_to_page_url() {
        let html = r#"<html><body>
            <form action="">
                <input type="hidden" name="token" value="x">
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/page", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn form_relative_action_resolved() {
        let html = r#"<html><body>
            <form action="/do-unsub">
                <input type="hidden" name="token" value="x">
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/do-unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (_, success, _) = result.unwrap();
        assert!(success);
    }

    #[test]
    fn form_absolute_action_used_directly() {
        let html = r#"<html><body>
            <form action="https://other.com/unsub">
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://other.com/unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn hidden_inputs_included() {
        let html = r#"<html><body>
            <form action="https://example.com/unsub" method="POST">
                <input type="hidden" name="token" value="secret">
                <input type="hidden" name="list_id" value="42">
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        // Both hidden inputs should be submitted; the mock just checks the URL
        let http = MockHttpClient::new()
            .on_url("https://example.com/unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn unchecked_checkboxes_excluded() {
        let html = r#"<html><body>
            <form action="https://example.com/unsub" method="GET">
                <input type="checkbox" name="keep" value="1">
                <input type="checkbox" name="remove" value="1" checked>
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        // Only "remove" should be included (it's checked)
        let http = MockHttpClient::new()
            .on_url(
                "https://example.com/unsub?remove=1",
                200,
                "Done",
            );

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn submit_buttons_with_values_included() {
        let html = r#"<html><body>
            <form action="https://example.com/unsub" method="GET">
                <input type="submit" name="action" value="Unsubscribe">
            </form>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url(
                "https://example.com/unsub?action=Unsubscribe",
                200,
                "Done",
            );

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn submit_buttons_without_values_excluded() {
        let html = r#"<html><body>
            <form action="https://example.com/unsub" method="GET">
                <input type="hidden" name="token" value="abc">
                <input type="submit" name="btn" value="">
                <button>Unsubscribe</button>
            </form>
        </body></html>"#;
        // The empty-value submit button should be excluded, only token sent
        let http = MockHttpClient::new()
            .on_url(
                "https://example.com/unsub?token=abc",
                200,
                "Done",
            );

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
    }

    #[test]
    fn no_form_or_link_returns_none() {
        let html = "<html><body><p>Plain page with no forms or links.</p></body></html>";
        let http = MockHttpClient::new();

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_none());
    }

    #[test]
    fn link_text_contains_keyword_follows() {
        let html = r#"<html><body>
            <a href="https://example.com/confirm-unsub">Click to unsubscribe</a>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/confirm-unsub", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (method, success, _) = result.unwrap();
        assert_eq!(method, "confirm link");
        assert!(success);
    }

    #[test]
    fn link_href_contains_keyword_case_insensitive() {
        let html = r#"<html><body>
            <a href="https://example.com/Unsubscribe?id=123">Click here</a>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/Unsubscribe?id=123", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (method, _, _) = result.unwrap();
        assert_eq!(method, "confirm link");
    }

    #[test]
    fn link_empty_href_skipped() {
        let html = r#"<html><body>
            <a href="">Unsubscribe</a>
        </body></html>"#;
        let http = MockHttpClient::new();

        // Empty href should be skipped even if text matches
        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_none());
    }

    #[test]
    fn link_relative_href_resolved() {
        let html = r#"<html><body>
            <a href="/confirm">Unsubscribe</a>
        </body></html>"#;
        let http = MockHttpClient::new()
            .on_url("https://example.com/confirm", 200, "Done");

        let result = try_confirm_page(&http, "https://example.com/page", html);
        assert!(result.is_some());
        let (_, success, _) = result.unwrap();
        assert!(success);
    }

    // -----------------------------------------------------------------------
    // resolve_url
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_url_empty_returns_page_url() {
        assert_eq!(
            resolve_url("https://example.com/page", ""),
            "https://example.com/page"
        );
    }

    #[test]
    fn resolve_url_dot_returns_page_url() {
        assert_eq!(
            resolve_url("https://example.com/page", "."),
            "https://example.com/page"
        );
    }

    #[test]
    fn resolve_url_absolute_passthrough() {
        assert_eq!(
            resolve_url("https://example.com/page", "https://other.com/unsub"),
            "https://other.com/unsub"
        );
    }

    #[test]
    fn resolve_url_http_absolute_passthrough() {
        assert_eq!(
            resolve_url("https://example.com/page", "http://other.com/unsub"),
            "http://other.com/unsub"
        );
    }

    #[test]
    fn resolve_url_relative_resolved() {
        let resolved = resolve_url("https://example.com/path/page", "/other");
        assert_eq!(resolved, "https://example.com/other");
    }

    #[test]
    fn resolve_url_relative_path_resolved() {
        let resolved = resolve_url("https://example.com/path/page", "sibling");
        assert_eq!(resolved, "https://example.com/path/sibling");
    }

    #[test]
    fn resolve_url_invalid_base_falls_back() {
        // Invalid base URL can't be parsed, so we fall back to page_url
        assert_eq!(
            resolve_url("not-a-url", "/relative"),
            "not-a-url"
        );
    }

}
