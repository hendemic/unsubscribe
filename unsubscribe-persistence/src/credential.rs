use anyhow::{Context, Result, bail};
use log::warn;

use unsubscribe_core::{AuthType, ConfigStore, Credential, CredentialStore};

use crate::KEYRING_SERVICE;
use crate::config::TomlConfigStore;

/// Keyring key suffix for OAuth refresh tokens, appended after the account ID.
const OAUTH_REFRESH_SUFFIX: &str = ":oauth_refresh";

/// Abstraction over the OS keychain so credential logic can be unit-tested
/// without a real keyring present.
///
/// The production implementation delegates to the `keyring` crate. Tests inject
/// a `MockKeyring` that stores entries in memory.
pub(crate) trait KeyringBackend {
    fn get_password(&self, service: &str, account: &str) -> Result<Option<String>>;
    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<()>;
    fn delete_password(&self, service: &str, account: &str) -> Result<()>;
}

/// Production backend that delegates to the OS keychain via the `keyring` crate.
pub(crate) struct OsKeyring;

impl KeyringBackend for OsKeyring {
    fn get_password(&self, service: &str, account: &str) -> Result<Option<String>> {
        match keyring::Entry::new(service, account) {
            Ok(entry) => match entry.get_password() {
                Ok(pw) => Ok(Some(pw)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => {
                    warn!("Keychain lookup failed: {e}");
                    Ok(None)
                }
            },
            Err(e) => {
                warn!("Could not access keychain: {e}");
                Ok(None)
            }
        }
    }

    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("Failed to access OS keychain")?;
        entry
            .set_password(password)
            .context("Failed to store password in OS keychain")
    }

    fn delete_password(&self, service: &str, account: &str) -> Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => bail!("Failed to delete credential from keychain: {e}"),
        }
    }
}

/// `CredentialStore` implementation backed by the OS keychain.
///
/// Handles two credential types:
///
/// **Password accounts** -- resolution follows the existing priority chain:
/// 1. `password_command` from config (shell command)
/// 2. OS keychain via the `keyring` crate
/// 3. Plain text `password` in config (legacy fallback)
///
/// **OAuth accounts** -- the refresh token is stored in the OS keychain.
/// On `get_credential`, the raw refresh token is returned. Token refresh
/// (exchanging a refresh token for an access token) is the caller's
/// responsibility, not persistence's.
pub struct KeyringCredentialStore {
    config_store: TomlConfigStore,
    keyring: Box<dyn KeyringBackend>,
}

impl KeyringCredentialStore {
    pub fn new(config_store: TomlConfigStore) -> Self {
        Self {
            config_store,
            keyring: Box::new(OsKeyring),
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
        if let Some(password) = self
            .keyring
            .get_password(KEYRING_SERVICE, &info.username)?
        {
            return Ok(password);
        }

        // 3. Plain text password in config (legacy fallback)
        if let Some(password) = &info.password {
            warn!("Using plain text password from config file. Run `unsubscribe init` to store it securely in your OS keychain.");
            return Ok(password.clone());
        }

        bail!(
            "No password found. Run `unsubscribe init` to store your password,\n\
             or add password_command to your config."
        )
    }

    /// Retrieve the OAuth refresh token from the OS keychain.
    fn get_refresh_token(&self, account_id: &str) -> Result<Option<String>> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        self.keyring.get_password(KEYRING_SERVICE, &key)
    }

    /// Store a refresh token in the OS keychain.
    fn store_refresh_token(&self, account_id: &str, refresh_token: &str) -> Result<()> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        self.keyring.set_password(KEYRING_SERVICE, &key, refresh_token)
    }

    /// Delete a refresh token from the OS keychain.
    fn delete_refresh_token(&self, account_id: &str) -> Result<()> {
        let key = format!("{account_id}{OAUTH_REFRESH_SUFFIX}");
        self.keyring.delete_password(KEYRING_SERVICE, &key)
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn store_credential(&self, account_id: &str, credential: &Credential) -> Result<()> {
        match credential {
            Credential::Password(password) => {
                self.keyring.set_password(KEYRING_SERVICE, account_id, password)
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
                let refresh_token = self.get_refresh_token(account_id)?
                    .context(
                        "No OAuth refresh token found. Run `unsubscribe init` to authenticate \
                         with your email provider."
                    )?;

                Ok(Some(Credential::OAuthToken {
                    access_token: String::new(),
                    refresh_token: Some(refresh_token),
                }))
            }
        }
    }

    fn delete_credential(&self, account_id: &str) -> Result<()> {
        // Delete password entry (if any)
        self.keyring.delete_password(KEYRING_SERVICE, account_id)?;

        // Delete OAuth refresh token (if any)
        self.delete_refresh_token(account_id)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;
    use unsubscribe_core::CredentialStore;

    // ─── Mock keyring ────────────────────────────────────────────────────────────

    /// In-memory keyring for unit tests. Uses interior mutability so `KeyringBackend`
    /// can take `&self` while entries mutate.
    struct MockKeyring {
        entries: RefCell<HashMap<(String, String), String>>,
    }

    impl MockKeyring {
        fn empty() -> Self {
            Self {
                entries: RefCell::new(HashMap::new()),
            }
        }

        fn with_entry(service: &str, account: &str, password: &str) -> Self {
            let mut map = HashMap::new();
            map.insert((service.into(), account.into()), password.into());
            Self {
                entries: RefCell::new(map),
            }
        }
    }

    impl KeyringBackend for MockKeyring {
        fn get_password(&self, service: &str, account: &str) -> Result<Option<String>> {
            Ok(self
                .entries
                .borrow()
                .get(&(service.into(), account.into()))
                .cloned())
        }

        fn set_password(&self, service: &str, account: &str, password: &str) -> Result<()> {
            self.entries
                .borrow_mut()
                .insert((service.into(), account.into()), password.into());
            Ok(())
        }

        fn delete_password(&self, service: &str, account: &str) -> Result<()> {
            self.entries
                .borrow_mut()
                .remove(&(service.into(), account.into()));
            Ok(())
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    /// Create a TomlConfigStore in a tempdir with a given config.toml content.
    fn store_with_config(dir: &TempDir, toml: &str) -> TomlConfigStore {
        let path = dir.path().join("config.toml");
        fs::write(&path, toml).unwrap();
        TomlConfigStore::new(dir.path())
    }

    /// Build a `KeyringCredentialStore` with a controllable mock keyring.
    fn credential_store(
        config_store: TomlConfigStore,
        keyring: impl KeyringBackend + 'static,
    ) -> KeyringCredentialStore {
        KeyringCredentialStore {
            config_store,
            keyring: Box::new(keyring),
        }
    }

    /// Minimal TOML config with auth_type = "password".
    fn password_config_toml(username: &str) -> String {
        format!(
            r#"
[account]
username = "{username}"
auth_type = "password"
"#
        )
    }

    /// Minimal TOML config with a `password_command` field.
    fn command_config_toml(username: &str, cmd: &str) -> String {
        format!(
            r#"
[account]
username = "{username}"
password_command = "{cmd}"
"#
        )
    }

    /// Minimal TOML config with a plain-text password field.
    fn plaintext_password_config_toml(username: &str, password: &str) -> String {
        format!(
            r#"
[account]
username = "{username}"
password = "{password}"
"#
        )
    }

    /// Minimal TOML config with auth_type = "oauth".
    fn oauth_config_toml(username: &str) -> String {
        format!(
            r#"
[account]
username = "{username}"
auth_type = "oauth"
provider = "gmail"
"#
        )
    }

    // ─── resolve_password: password_command ──────────────────────────────────────

    #[test]
    fn password_command_success_returns_stdout() {
        let dir = TempDir::new().unwrap();
        let toml = command_config_toml("cmd@example.com", "echo secretpassword");
        let config_store = store_with_config(&dir, &toml);
        let store = credential_store(config_store, MockKeyring::empty());

        let result = store.resolve_password("any").unwrap();
        assert_eq!(result, "secretpassword");
    }

    #[test]
    fn password_command_nonzero_exit_returns_error() {
        let dir = TempDir::new().unwrap();
        let toml = command_config_toml("cmd@example.com", "exit 1");
        let config_store = store_with_config(&dir, &toml);
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store.resolve_password("any").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("password_command failed"),
            "expected failure message, got: {msg}"
        );
    }

    #[test]
    fn password_command_empty_output_returns_error() {
        let dir = TempDir::new().unwrap();
        // `true` exits 0 but produces no output.
        let toml = command_config_toml("cmd@example.com", "true");
        let config_store = store_with_config(&dir, &toml);
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store.resolve_password("any").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("empty output"),
            "expected empty-output error, got: {msg}"
        );
    }

    // ─── resolve_password: keyring fallback ──────────────────────────────────────

    #[test]
    fn keyring_entry_returned_when_no_password_command() {
        let dir = TempDir::new().unwrap();
        let toml = password_config_toml("kr@example.com");
        let config_store = store_with_config(&dir, &toml);
        let keyring = MockKeyring::with_entry(KEYRING_SERVICE, "kr@example.com", "keyring_pass");
        let store = credential_store(config_store, keyring);

        let result = store.resolve_password("any").unwrap();
        assert_eq!(result, "keyring_pass");
    }

    // ─── resolve_password: plaintext fallback ────────────────────────────────────

    #[test]
    fn plaintext_password_used_when_no_command_and_no_keyring_entry() {
        let dir = TempDir::new().unwrap();
        let toml = plaintext_password_config_toml("pt@example.com", "plaintextpw");
        let config_store = store_with_config(&dir, &toml);
        // Keyring has no entry, so we should fall through to plaintext.
        let store = credential_store(config_store, MockKeyring::empty());

        let result = store.resolve_password("any").unwrap();
        assert_eq!(result, "plaintextpw");
    }

    // ─── resolve_password: no password found ─────────────────────────────────────

    #[test]
    fn no_password_found_returns_error() {
        let dir = TempDir::new().unwrap();
        // Config has no password_command, no keyring entry, no plaintext password.
        let toml = password_config_toml("none@example.com");
        let config_store = store_with_config(&dir, &toml);
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store.resolve_password("any").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("No password found"),
            "expected no-password-found error, got: {msg}"
        );
    }

    #[test]
    fn missing_config_file_returns_error_with_helpful_message() {
        let dir = TempDir::new().unwrap();
        // No config.toml written at all.
        let config_store = TomlConfigStore::new(dir.path());
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store.resolve_password("no_account").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("No config found"),
            "expected no-config error, got: {msg}"
        );
    }

    // ─── get_credential: dispatch by AuthType ────────────────────────────────────

    #[test]
    fn get_credential_returns_password_credential_for_password_auth_type() {
        let dir = TempDir::new().unwrap();
        let toml = password_config_toml("pw@example.com");
        let config_store = store_with_config(&dir, &toml);
        let keyring = MockKeyring::with_entry(KEYRING_SERVICE, "pw@example.com", "thepw");
        let store = credential_store(config_store, keyring);

        match store.get_credential("pw@example.com").unwrap().unwrap() {
            Credential::Password(pw) => assert_eq!(pw, "thepw"),
            other => panic!("expected Password credential, got {other:?}"),
        }
    }

    #[test]
    fn get_credential_returns_none_when_config_missing() {
        let dir = TempDir::new().unwrap();
        let config_store = TomlConfigStore::new(dir.path());
        let store = credential_store(config_store, MockKeyring::empty());

        let result = store.get_credential("nobody@example.com").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_credential_returns_oauth_token_for_oauth_auth_type() {
        let dir = TempDir::new().unwrap();
        let toml = oauth_config_toml("oauth@example.com");
        let config_store = store_with_config(&dir, &toml);

        // Refresh token is stored under "{account_id}:oauth_refresh".
        let refresh_key = format!("oauth@example.com{OAUTH_REFRESH_SUFFIX}");
        let keyring = MockKeyring::with_entry(KEYRING_SERVICE, &refresh_key, "refresh_tok");
        let store = credential_store(config_store, keyring);

        match store.get_credential("oauth@example.com").unwrap().unwrap() {
            Credential::OAuthToken { refresh_token, .. } => {
                assert_eq!(refresh_token.as_deref(), Some("refresh_tok"));
            }
            other => panic!("expected OAuthToken credential, got {other:?}"),
        }
    }

    #[test]
    fn get_credential_errors_when_oauth_token_missing_from_keyring() {
        let dir = TempDir::new().unwrap();
        let toml = oauth_config_toml("oauth@example.com");
        let config_store = store_with_config(&dir, &toml);
        // Keyring has no refresh token stored.
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store.get_credential("oauth@example.com").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("No OAuth refresh token"),
            "expected missing-token error, got: {msg}"
        );
    }

    // ─── store_credential / delete_credential ────────────────────────────────────

    #[test]
    fn store_then_get_credential_round_trip_for_password() {
        // Write a password config, store the credential, then get_credential
        // must return it — exercising the full store→keyring→resolve_password path.
        let dir = TempDir::new().unwrap();
        let toml = password_config_toml("rt@example.com");
        let config_store = store_with_config(&dir, &toml);
        let store = credential_store(config_store, MockKeyring::empty());

        store
            .store_credential("rt@example.com", &Credential::Password("storedpw".into()))
            .unwrap();

        match store.get_credential("rt@example.com").unwrap().unwrap() {
            Credential::Password(pw) => assert_eq!(pw, "storedpw"),
            other => panic!("expected Password credential, got {other:?}"),
        }
    }

    #[test]
    fn store_credential_oauth_without_refresh_token_returns_error() {
        let dir = TempDir::new().unwrap();
        let config_store = TomlConfigStore::new(dir.path());
        let store = credential_store(config_store, MockKeyring::empty());

        let err = store
            .store_credential(
                "acct@example.com",
                &Credential::OAuthToken {
                    access_token: "short_lived".into(),
                    refresh_token: None,
                },
            )
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("without a refresh token"),
            "expected no-refresh-token error, got: {msg}"
        );
    }

    #[test]
    fn password_command_priority_beats_keyring_entry() {
        // Even if the keyring has an entry, password_command should win.
        let dir = TempDir::new().unwrap();
        let toml = command_config_toml("priority@example.com", "echo fromcommand");
        let config_store = store_with_config(&dir, &toml);
        let keyring =
            MockKeyring::with_entry(KEYRING_SERVICE, "priority@example.com", "fromkeyring");
        let store = credential_store(config_store, keyring);

        let result = store.resolve_password("any").unwrap();
        assert_eq!(result, "fromcommand", "password_command must take priority over keyring");
    }
}
