use anyhow::{Context, Result};

use unsubscribe_core::{Credential, CredentialStore};

use crate::config::{PasswordResolutionInfo, TomlConfigStore};

const KEYRING_SERVICE: &str = "unsubscribe";

/// `CredentialStore` implementation backed by the OS keychain.
///
/// Password resolution follows the existing priority chain:
/// 1. `password_command` from config (shell command)
/// 2. OS keychain via the `keyring` crate
/// 3. Plain text `password` in config (legacy fallback)
///
/// The config store is consulted for password_command and plaintext fallback
/// during `get_credential`, keeping the same behavior as the original CLI.
pub struct KeyringCredentialStore {
    config_store: TomlConfigStore,
}

impl KeyringCredentialStore {
    pub fn new(config_store: TomlConfigStore) -> Self {
        Self { config_store }
    }

    /// Resolve a password using the priority chain, given config info.
    fn resolve_password(&self, info: &PasswordResolutionInfo) -> Result<String> {
        // 1. password_command
        if let Some(cmd) = &info.password_command {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .with_context(|| format!("Failed to run password_command: {cmd}"))?;

            if !output.status.success() {
                anyhow::bail!(
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
                anyhow::bail!("password_command returned empty output");
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

        anyhow::bail!(
            "No password found. Run `unsubscribe init` to store your password,\n\
             or add password_command to your config."
        )
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
            Credential::OAuthToken { .. } => {
                anyhow::bail!("OAuth token storage not yet implemented in keyring store")
            }
        }
    }

    fn get_credential(&self, account_id: &str) -> Result<Option<Credential>> {
        let info = self.config_store.read_file_imap_config(account_id)?;

        match info {
            Some(info) => {
                let password = self.resolve_password(&info)?;
                Ok(Some(Credential::Password(password)))
            }
            None => Ok(None),
        }
    }

    fn delete_credential(&self, account_id: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("Failed to delete from keychain: {e}")),
        }
    }
}
