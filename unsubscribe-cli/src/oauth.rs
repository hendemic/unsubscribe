//! Google OAuth2 authorization code flow with PKCE and token refresh.
//!
//! Handles both the interactive browser-based consent flow for Gmail API access
//! and the non-interactive token refresh flow for ongoing API access.
//!
//! This module lives in the CLI crate because:
//! - The authorization flow is inherently interactive (opening browsers, binding ports)
//! - Token refresh requires an HTTP client and Google-specific logic
//! - iOS will use Apple's Accounts framework instead of raw HTTP token refresh
//!
//! Core and persistence never touch this.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::Rng;
use sha2::Digest;
use unsubscribe_core::HttpClient;

/// OAuth client credentials, injected at build time from environment variables.
/// Set via .cargo/config.toml (gitignored) or CI secrets.
const GOOGLE_CLIENT_ID: &str = env!("GOOGLE_CLIENT_ID");
const GOOGLE_CLIENT_SECRET: &str = env!("GOOGLE_CLIENT_SECRET");

/// Safety margin subtracted from the reported token lifetime to avoid using
/// a token right at the edge of expiry. 60 seconds is conservative enough
/// for typical clock drift and request latency.
const EXPIRY_BUFFER_SECS: u64 = 60;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Scope for reading message headers and modifying labels (archive).
const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";

/// The result of a successful OAuth authorization code flow.
#[derive(Debug)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// PKCE code verifier and challenge pair (RFC 7636).
struct PkceChallenge {
    verifier: String,
    challenge: String,
}

/// Run the full OAuth authorization code flow.
///
/// 1. Generate PKCE code verifier/challenge
/// 2. Open the system browser to Google's consent URL
/// 3. Listen on localhost for the redirect callback
/// 4. Extract the authorization code from the callback
/// 5. Exchange the code for access + refresh tokens
///
/// Returns the token pair on success. The caller is responsible for storing
/// the refresh token (via the persistence crate).
pub fn authorize(client_id: Option<&str>, client_secret: Option<&str>) -> Result<OAuthTokens> {
    let client_id = client_id.unwrap_or(GOOGLE_CLIENT_ID);
    let client_secret = client_secret.unwrap_or(GOOGLE_CLIENT_SECRET);

    let pkce = generate_pkce();
    let listener = bind_localhost_listener()
        .context("Failed to bind localhost listener for OAuth callback")?;
    let port = listener
        .local_addr()
        .context("Failed to get local address of OAuth listener")?
        .port();
    let redirect_uri = format!("http://localhost:{port}/callback");

    let auth_url = build_auth_url(client_id, &redirect_uri, &pkce.challenge);

    eprintln!("Opening browser for Google authentication...");
    eprintln!("If the browser doesn't open, visit this URL manually:\n");
    eprintln!("  {auth_url}\n");

    open_browser(&auth_url)?;

    eprintln!("Waiting for authorization...");

    let auth_code = wait_for_callback(&listener)?;

    eprintln!("Authorization received. Exchanging code for tokens...");

    let tokens = exchange_code(
        &auth_code,
        client_id,
        client_secret,
        &redirect_uri,
        &pkce.verifier,
    )?;

    Ok(tokens)
}

/// Generate a PKCE code verifier and its S256 challenge per RFC 7636.
///
/// The verifier is 32 random bytes encoded as base64url (43 characters).
/// The challenge is SHA-256(verifier) encoded as base64url.
fn generate_pkce() -> PkceChallenge {
    let random_bytes: [u8; 32] = rand::thread_rng().r#gen();
    let verifier = base64_url_encode(&random_bytes);

    let mut hasher = sha2::Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = base64_url_encode(&digest);

    PkceChallenge {
        verifier,
        challenge,
    }
}

/// Build the Google OAuth authorization URL with all required parameters.
fn build_auth_url(client_id: &str, redirect_uri: &str, code_challenge: &str) -> String {
    let mut url = url::Url::parse(GOOGLE_AUTH_URL).expect("static URL is valid");
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", GMAIL_SCOPE)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline")
        // Force consent prompt to always get a refresh token
        .append_pair("prompt", "consent");
    url.to_string()
}

/// Bind a TCP listener on localhost with a system-assigned port.
///
/// Tries port 0 (OS picks an available ephemeral port) to avoid conflicts.
fn bind_localhost_listener() -> Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("Could not bind to any localhost port")?;
    // Set a timeout so we don't block forever if the user closes the browser
    listener
        .set_nonblocking(false)
        .context("Failed to configure listener")?;
    Ok(listener)
}

/// Wait for the OAuth redirect callback on the listener.
///
/// Parses the minimal HTTP request to extract the authorization code from
/// the query string. Sends a simple HTML response so the user sees feedback
/// in the browser.
fn wait_for_callback(listener: &TcpListener) -> Result<String> {
    let (mut stream, _) = listener
        .accept()
        .context("Failed to accept OAuth callback connection")?;

    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .context("Failed to read OAuth callback request")?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the request line: "GET /callback?code=...&scope=... HTTP/1.1"
    let request_line = request.lines().next().unwrap_or("");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("");

    // Check for error response (user denied or other failure)
    if let Some(error) = extract_query_param(path, "error") {
        let description = extract_query_param(path, "error_description")
            .unwrap_or_else(|| error.clone());
        send_error_response(&mut stream, &description);
        bail!("Authorization denied: {description}");
    }

    let code = extract_query_param(path, "code")
        .context("OAuth callback did not contain an authorization code")?;

    send_success_response(&mut stream);

    Ok(code)
}

/// Extract a query parameter value from a URL path string.
fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let query = path.split_once('?').map(|(_, q)| q)?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == param)
        .map(|(_, value)| value.into_owned())
}

/// Send a minimal HTML success response to the browser.
fn send_success_response(stream: &mut impl Write) {
    let body = concat!(
        "<!DOCTYPE html><html><body>",
        "<h2>Authorization successful</h2>",
        "<p>You can close this tab and return to the terminal.</p>",
        "</body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Send a minimal HTML error response to the browser.
fn send_error_response(stream: &mut impl Write, message: &str) {
    let body = format!(
        concat!(
            "<!DOCTYPE html><html><body>",
            "<h2>Authorization failed</h2>",
            "<p>{}</p>",
            "<p>You can close this tab and return to the terminal.</p>",
            "</body></html>"
        ),
        message
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Exchange an authorization code for access and refresh tokens.
///
/// Uses reqwest (already a CLI dependency) to POST to Google's token endpoint.
fn exchange_code(
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<OAuthTokens> {
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(GOOGLE_TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ])
        .send()
        .context("Failed to contact Google's token endpoint")?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .context("Failed to parse token exchange response")?;

    if !status.is_success() {
        let error = body["error"].as_str().unwrap_or("unknown");
        let description = body["error_description"]
            .as_str()
            .unwrap_or("unknown error");
        bail!("Token exchange failed: {description} ({error})");
    }

    let access_token = body["access_token"]
        .as_str()
        .context("Token response missing access_token")?
        .to_string();

    let refresh_token = body["refresh_token"].as_str().map(|s| s.to_string());

    Ok(OAuthTokens {
        access_token,
        refresh_token,
    })
}

/// Open a URL in the system's default browser.
///
/// Uses `xdg-open` on Linux and `open` on macOS. Falls back gracefully
/// if the command is not available -- the URL is always printed to stderr
/// so the user can copy it manually.
fn open_browser(url: &str) -> Result<()> {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };

    match std::process::Command::new(command)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Could not open browser automatically: {e}");
            eprintln!("Please open the URL above manually.");
            Ok(())
        }
    }
}

/// Base64url encoding without padding, per RFC 4648 Section 5.
fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// ---------------------------------------------------------------------------
// Token refresh and caching
// ---------------------------------------------------------------------------

/// A cached access token with its expiry time.
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

/// Manages OAuth access token refresh and in-memory caching.
///
/// Holds a refresh token and exchanges it for short-lived access tokens
/// via Google's token endpoint, caching them to avoid redundant refreshes
/// within a session.
pub struct TokenRefresher {
    http_client: Box<dyn HttpClient>,
    cache: Mutex<HashMap<String, CachedAccessToken>>,
}

impl TokenRefresher {
    pub fn new(http_client: Box<dyn HttpClient>) -> Self {
        Self {
            http_client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a fresh access token for the given account.
    ///
    /// Returns a cached token if one exists and hasn't expired, otherwise
    /// exchanges the refresh token for a new access token.
    pub fn resolve_access_token(&self, account_id: &str, refresh_token: &str) -> Result<String> {
        // Check cache first
        if let Some(cached) = self.get_cached_token(account_id) {
            return Ok(cached);
        }

        let (access_token, expires_in) = refresh_access_token(
            &*self.http_client,
            refresh_token,
        )?;

        self.cache_token(account_id, &access_token, expires_in);

        Ok(access_token)
    }

    fn get_cached_token(&self, account_id: &str) -> Option<String> {
        let cache = self.cache.lock().ok()?;
        let cached = cache.get(account_id)?;
        if Instant::now() < cached.expires_at {
            Some(cached.token.clone())
        } else {
            None
        }
    }

    fn cache_token(&self, account_id: &str, token: &str, expires_in_secs: u64) {
        let effective_lifetime = expires_in_secs.saturating_sub(EXPIRY_BUFFER_SECS);
        let expires_at = Instant::now() + std::time::Duration::from_secs(effective_lifetime);

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                account_id.to_string(),
                CachedAccessToken {
                    token: token.to_string(),
                    expires_at,
                },
            );
        }
    }
}

/// Exchange a refresh token for a new access token via Google's token endpoint.
///
/// Returns `(access_token, expires_in_seconds)`.
fn refresh_access_token(
    http: &dyn HttpClient,
    refresh_token: &str,
) -> Result<(String, u64)> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", GOOGLE_CLIENT_ID),
        ("client_secret", GOOGLE_CLIENT_SECRET),
    ];

    let response = http
        .post_form(GOOGLE_TOKEN_URL, &params)
        .context("Failed to contact Google's token endpoint for token refresh")?;

    if response.status == 400 || response.status == 401 {
        if let Ok(body) = serde_json::from_str::<serde_json::Value>(&response.body) {
            let error = body["error"].as_str().unwrap_or("unknown");
            if error == "invalid_grant" {
                bail!(
                    "OAuth refresh token has been revoked or expired. \
                     Run `unsubscribe init` to re-authenticate with your email provider."
                );
            }
            bail!(
                "OAuth token refresh failed: {} ({})",
                body["error_description"].as_str().unwrap_or("unknown error"),
                error
            );
        }
        bail!(
            "OAuth token refresh failed with HTTP {}: {}",
            response.status,
            response.body
        );
    }

    if response.status >= 400 {
        bail!(
            "OAuth token refresh failed with HTTP {}: {}",
            response.status,
            response.body
        );
    }

    let body: serde_json::Value = serde_json::from_str(&response.body)
        .context("Failed to parse token refresh response")?;

    let access_token = body["access_token"]
        .as_str()
        .context("Token refresh response missing access_token")?
        .to_string();

    // Google tokens typically expire in 3600 seconds (1 hour)
    let expires_in = body["expires_in"].as_u64().unwrap_or(3600);

    Ok((access_token, expires_in))
}
