use anyhow::{Context, Result, bail};
use log::warn;

use unsubscribe_core::{AuthType, ConfigStore, Credential, CredentialStore};

use crate::KEYRING_SERVICE;
use crate::config::TomlConfigStore;

/// Keyring key suffix for OAuth refresh tokens, appended after the account ID.
const OAUTH_REFRESH_SUFFIX: &str = ":oauth_refresh";

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
}

impl KeyringCredentialStore {
    pub fn new(config_store: TomlConfigStore) -> Self {
        Self { config_store }
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
                    warn!("Keychain lookup failed: {e}");
                }
            },
            Err(e) => {
                warn!("Could not access keychain: {e}");
            }
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
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => bail!("Failed to delete password from keychain: {e}"),
        }

        // Delete OAuth refresh token (if any)
        self.delete_refresh_token(account_id)?;

        Ok(())
    }
}
