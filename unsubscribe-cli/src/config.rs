use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use unsubscribe_core::{ConfigStore, Credential, CredentialStore};
use unsubscribe_persistence::{KeyringCredentialStore, TomlConfigStore};

/// Runtime config with a resolved password, ready for use by CLI commands.
#[derive(Debug, Clone)]
pub struct Config {
    pub imap: ImapConfig,
    pub scan: ScanConfig,
}

#[derive(Debug, Clone)]
pub struct ImapConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub folders: Vec<String>,
    pub archive_folder: String,
}

impl Config {
    pub fn default_path() -> PathBuf {
        TomlConfigStore::default_dir().join("config.toml")
    }

    /// Load config and resolve the password through the persistence layer.
    pub fn load(path: &Path) -> Result<Self> {
        let config_dir = path
            .parent()
            .context("Config path has no parent directory")?;

        let config_store = TomlConfigStore::new(config_dir);
        let credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));

        // Read account config -- use empty string as account_id since the
        // single-account layout uses `config.toml` directly.
        let account = config_store
            .read_config("")?
            .context(format!(
                "Failed to read config: {}\n\nRun `unsubscribe init` to set up your config.",
                path.display()
            ))?;

        // Resolve credential through the priority chain
        let credential = credential_store
            .get_credential(&account.account_id)?
            .context(
                "No password found. Run `unsubscribe init` to store your password,\n\
                 or add password_command to your config.",
            )?;

        let password = match credential {
            Credential::Password(p) => p,
            Credential::OAuthToken { .. } => {
                anyhow::bail!("OAuth tokens are not yet supported for IMAP connections")
            }
        };

        Ok(Config {
            imap: ImapConfig {
                host: account.host,
                port: account.port.unwrap_or(993),
                username: account.username,
                password,
            },
            scan: ScanConfig {
                folders: account.scan_folders,
                archive_folder: account.archive_folder,
            },
        })
    }

    /// Store the IMAP password in the OS keychain via the persistence layer.
    pub fn store_password(username: &str, password: &str) -> Result<()> {
        let config_dir = TomlConfigStore::default_dir();
        let config_store = TomlConfigStore::new(&config_dir);
        let credential_store = KeyringCredentialStore::new(config_store);
        credential_store.store_credential(username, &Credential::Password(password.to_string()))
    }

    /// Delete the IMAP password from the OS keychain via the persistence layer.
    pub fn delete_password(username: &str) -> Result<()> {
        let config_dir = TomlConfigStore::default_dir();
        let config_store = TomlConfigStore::new(&config_dir);
        let credential_store = KeyringCredentialStore::new(config_store);
        credential_store.delete_credential(username)
    }

    /// Write a config file (used by `init`). Does NOT write the password to disk.
    pub fn write_init(
        path: &Path,
        host: &str,
        port: u16,
        username: &str,
        folders: Vec<String>,
        archive_folder: &str,
    ) -> Result<()> {
        let config_dir = path
            .parent()
            .context("Config path has no parent directory")?;

        let config_store = TomlConfigStore::new(config_dir);
        config_store.write_init(host, port, username, folders, archive_folder)
    }
}
