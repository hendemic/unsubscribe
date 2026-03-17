use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use unsubscribe_core::{AuthType, ConfigStore, Credential, CredentialStore, HttpClient};

use crate::config::TomlConfigStore;

const KEYRING_SERVICE: &str = "unsubscribe";

/// Keyring key suffix for OAuth refresh tokens, appended after the account ID.
const OAUTH_REFRESH_SUFFIX: &str = ":oauth_refresh";

/// Google's token endpoint for exchanging refresh tokens.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Safety margin subtracted from the reported token lifetime to avoid using
/// a token right at the edge of expiry. 60 seconds is conservative enough
/// for typical clock drift and request latency.
const EXPIRY_BUFFER_SECS: u64 = 60;

/// OAuth client credentials for Google. Embedded in the binary per the
/// installed-app convention (security relies on redirect URI and PKCE, not
/// client secret confidentiality).
///
/// These are placeholder values during development. Replace with real
/// credentials from Google Cloud Console before shipping verified builds.
pub struct OAuthClientConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// A cached access token with its expiry time.
struct CachedAccessToken {
    token: String,
    /// Instant at which this token should be considered expired.
    expires_at: Instant,
}

/// `CredentialStore` implementation backed by the OS keychain.
///
/// Handles two credential types:
///
/// **Password accounts** — resolution follows the existing priority chain:
/// 1. `password_command` from config (shell command)
/// 2. OS keychain via the `keyring` crate
/// 3. Plain text `password` in config (legacy fallback)
///
/// **OAuth accounts** — the refresh token is stored in the OS keychain.
/// On `get_credential`, the refresh token is exchanged for a fresh access
/// token via Google's token endpoint. Access tokens are cached in memory
/// with their reported expiry to avoid unnecessary refreshes (~1 hour
/// lifetime).
pub struct KeyringCredentialStore {
    config_store: TomlConfigStore,
    /// HTTP client for OAuth token refresh. None if OAuth is not needed.
    http_client: Option<Box<dyn HttpClient>>,
    /// OAuth client credentials for token refresh requests.
    oauth_config: Option<OAuthClientConfig>,
    /// In-memory cache of access tokens, keyed by account ID.
    token_cache: Mutex<HashMap<String, CachedAccessToken>>,
}

impl KeyringCredentialStore {
    /// Create a store for password-only accounts (no OAuth support).
    pub fn new(config_store: TomlConfigStore) -> Self {
        Self {
            config_store,
            http_client: None,
            oauth_config: None,
            token_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Create a store with OAuth support for accounts that need token refresh.
    pub fn with_oauth(
        config_store: TomlConfigStore,
        http_client: Box<dyn HttpClient>,
        oauth_config: OAuthClientConfig,
    ) -> Self {
        Self {
            config_store,
            http_client: Some(http_client),
            oauth_config: Some(oauth_config),
            token_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a password using the priority chain.
    fn resolve_password(&self, account_id: &str) -> Result<String> {
        let info = self
            .config_store
            .read_file_imap_config(account_id)?
            .context(format!(
                "No config found for account '{account_id}'.\n\
                 Run `unsubscribe init` to set up your config."
            ))?;

        // 1. password_command
        if let Some(cmd) = &info.password_command {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .with_context(|| format!("Failed to run password_command: {cmd}"))?;

            if !output.status.success() {
                bail!(
                    "password_command failed (exit {}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }

            let password = String::from_utf8(output.stdout)
                .context("password_command output is not valid UTF-8")?
                .trim()
                .to_string();

            if password.is_empty() {
                bail!("password_command returned empty output");
            }

            return Ok(password);
        }

        // 2. OS keychain
        match keyring::Entry::new(KEYRING_SERVICE, &info.username) {
            Ok(entry) => match entry.get_password() {
                Ok(password) => return Ok(password),
                Err(keyring::Error::NoEntry) => {} // fall through
                Err(e) => {
                    eprintln!("Warning: keychain lookup failed: {e}");
                }
            },
            Err(e) => {
                eprintln!("Warning: could not access keychain: {e}");
            }
        }

        // 3. Plain text password in config (legacy fallback)
        if let Some(password) = &info.password {
            eprintln!("Warning: using plain text password from config file.");
            eprintln!("Run `unsubscribe init` to store it securely in your OS keychain.\n");
            return Ok(password.clone());
        }

        bail!(
            "No password found. Run `unsubscribe init` to store your password,\n\
             or add password_command to your config."
        )
    }

    /// Resolve an OAuth credential by refreshing the access token.
    ///
    /// Returns a cached access token if it hasn't expired, otherwise exchanges
    /// the stored refresh token for a new access token via the token endpoint.
    fn resolve_oauth(&self, account_id: &str) -> Result<Credential> {
        // Check the in-memory cache first
        if let Some(cached) = self.get_cached_token(account_id) {
            return Ok(Credential::OAuthToken {
                access_token: cached,
                refresh_token: None,
            });
        }

        // Read the refresh token from keyring
        let refresh_token = self.get_refresh_token(account_id)?
            .context(
                "No OAuth refresh token found. Run `unsubscribe init` to authenticate \
                 with your email provider."
            )?;

        // Exchange refresh token for a new access token
        let (access_token, expires_in) = self.refresh_access_token(&refresh_token)?;

        // Cache the new access token
        self.cache_token(account_id, &access_token, expires_in);

        Ok(Credential::OAuthToken {
            access_token,
            refresh_token: None,
        })
    }

    /// Retrieve the refresh token from the OS keychain.
    fn get_refresh_token(&self, account_id: &str) -> Result<Option<String>> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        match keyring::Entry::new(KEYRING_SERVICE, &key) {
            Ok(entry) => match entry.get_password() {
                Ok(token) => Ok(Some(token)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => bail!("Failed to read OAuth refresh token from keychain: {e}"),
            },
            Err(e) => bail!("Failed to access keychain for OAuth refresh token: {e}"),
        }
    }

    /// Store a refresh token in the OS keychain.
    fn store_refresh_token(&self, account_id: &str, refresh_token: &str) -> Result<()> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        let entry = keyring::Entry::new(KEYRING_SERVICE, &key)
            .context("Failed to access OS keychain for OAuth refresh token")?;
        entry
            .set_password(refresh_token)
            .context("Failed to store OAuth refresh token in OS keychain")?;
        Ok(())
    }

    /// Delete a refresh token from the OS keychain.
    fn delete_refresh_token(&self, account_id: &str) -> Result<()> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        let entry = keyring::Entry::new(KEYRING_SERVICE, &key)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => bail!("Failed to delete OAuth refresh token from keychain: {e}"),
        }
    }

    /// Exchange a refresh token for a new access token via Google's token endpoint.
    ///
    /// Returns `(access_token, expires_in_seconds)`.
    fn refresh_access_token(&self, refresh_token: &str) -> Result<(String, u64)> {
        let http = self.http_client.as_ref().context(
            "OAuth token refresh requires an HTTP client. This is a bug — \
             the credential store was not configured with OAuth support."
        )?;
        let oauth = self.oauth_config.as_ref().context(
            "OAuth token refresh requires client credentials. This is a bug — \
             the credential store was not configured with OAuth support."
        )?;

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &oauth.client_id),
            ("client_secret", &oauth.client_secret),
        ];

        let response = http
            .post_form(GOOGLE_TOKEN_URL, &params)
            .context("Failed to contact Google's token endpoint for token refresh")?;

        if response.status == 400 || response.status == 401 {
            // Parse the error to distinguish revoked tokens from other failures
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

    /// Return a cached access token if it exists and hasn't expired.
    fn get_cached_token(&self, account_id: &str) -> Option<String> {
        let cache = self.token_cache.lock().ok()?;
        let cached = cache.get(account_id)?;
        if Instant::now() < cached.expires_at {
            Some(cached.token.clone())
        } else {
            None
        }
    }

    /// Cache an access token with the given lifetime.
    fn cache_token(&self, account_id: &str, token: &str, expires_in_secs: u64) {
        let effective_lifetime = expires_in_secs.saturating_sub(EXPIRY_BUFFER_SECS);
        let expires_at = Instant::now() + std::time::Duration::from_secs(effective_lifetime);

        if let Ok(mut cache) = self.token_cache.lock() {
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

impl CredentialStore for KeyringCredentialStore {
    fn store_credential(&self, account_id: &str, credential: &Credential) -> Result<()> {
        match credential {
            Credential::Password(password) => {
                let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)
                    .context("Failed to access OS keychain")?;
                entry
                    .set_password(password)
                    .context("Failed to store password in OS keychain")?;
                Ok(())
            }
            Credential::OAuthToken {
                refresh_token: Some(refresh_token),
                ..
            } => {
                self.store_refresh_token(account_id, refresh_token)
            }
            Credential::OAuthToken {
                refresh_token: None,
                ..
            } => {
                bail!(
                    "Cannot store OAuth credential without a refresh token. \
                     The access token alone is short-lived and not useful for storage."
                )
            }
        }
    }

    fn get_credential(&self, account_id: &str) -> Result<Option<Credential>> {
        let account = self.config_store.read_config(account_id)?;

        let Some(account) = account else {
            return Ok(None);
        };

        match account.auth_type {
            AuthType::Password => {
                let password = self.resolve_password(account_id)?;
                Ok(Some(Credential::Password(password)))
            }
            AuthType::OAuth => {
                let credential = self.resolve_oauth(account_id)?;
                Ok(Some(credential))
            }
        }
    }

    fn delete_credential(&self, account_id: &str) -> Result<()> {
        // Delete password entry (if any)
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => bail!("Failed to delete password from keychain: {e}"),
        }

        // Delete OAuth refresh token (if any)
        self.delete_refresh_token(account_id)?;

        // Clear any cached access token
        if let Ok(mut cache) = self.token_cache.lock() {
            cache.remove(account_id);
        }

        Ok(())
    }
}
