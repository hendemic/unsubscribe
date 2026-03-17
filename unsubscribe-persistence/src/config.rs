use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use unsubscribe_core::{AccountConfig, ConfigStore};

const KEYRING_SERVICE: &str = "unsubscribe";

/// On-disk TOML structure -- matches the existing config format exactly.
#[derive(Debug, Serialize, Deserialize)]
struct FileConfig {
    imap: FileImapConfig,
    #[serde(default)]
    scan: FileScanConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileImapConfig {
    host: String,
    port: u16,
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileScanConfig {
    #[serde(default = "default_folders")]
    folders: Vec<String>,
    #[serde(default = "default_archive_folder")]
    archive_folder: String,
}

fn default_folders() -> Vec<String> {
    vec!["INBOX".to_string()]
}

fn default_archive_folder() -> String {
    "Unsubscribed".to_string()
}

impl Default for FileScanConfig {
    fn default() -> Self {
        Self {
            folders: default_folders(),
            archive_folder: default_archive_folder(),
        }
    }
}

/// `ConfigStore` implementation backed by TOML files on disk.
///
/// Each account's config lives at `{base_dir}/{account_id}/config.toml`.
/// For backward compatibility, a single default config path can be used
/// when only one account exists.
pub struct TomlConfigStore {
    config_dir: PathBuf,
}

impl TomlConfigStore {
    /// Create a store rooted at the given directory.
    ///
    /// For the CLI, this is typically `~/.config/email-unsubscribe/`.
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
        }
    }

    /// The default config directory following XDG conventions.
    pub fn default_dir() -> PathBuf {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let mut home =
                    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
                home.push(".config");
                home
            });
        config_dir.join("email-unsubscribe")
    }

    /// Path to the config file for a given account.
    ///
    /// For backward compatibility, this is `{config_dir}/config.toml` directly
    /// (the original single-account layout).
    fn config_path(&self, _account_id: &str) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Read the raw file config (for credential resolution).
    pub fn read_file_imap_config(
        &self,
        account_id: &str,
    ) -> Result<Option<PasswordResolutionInfo>> {
        let path = self.config_path(account_id);
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let file: FileConfig = toml::from_str(&contents).context("Failed to parse config")?;

        Ok(Some(PasswordResolutionInfo {
            username: file.imap.username,
            password: file.imap.password,
            password_command: file.imap.password_command,
        }))
    }

    /// Write a config file with a header comment about password storage.
    pub fn write_init(
        &self,
        host: &str,
        port: u16,
        username: &str,
        folders: Vec<String>,
        archive_folder: &str,
    ) -> Result<()> {
        let file = FileConfig {
            imap: FileImapConfig {
                host: host.to_string(),
                port,
                username: username.to_string(),
                password: None,
                password_command: None,
            },
            scan: FileScanConfig {
                folders,
                archive_folder: archive_folder.to_string(),
            },
        };

        let toml_str = toml::to_string_pretty(&file).context("Failed to serialize config")?;

        let content = format!(
            "# Password is stored in your OS keychain ({KEYRING_SERVICE})\n\
             # To use a command instead, add:\n\
             #   password_command = \"pass show email/imap\"\n\n\
             {toml_str}"
        );

        let path = self.config_dir.join("config.toml");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        Ok(())
    }
}

/// Info needed by the credential store to resolve passwords from config.
pub struct PasswordResolutionInfo {
    pub username: String,
    pub password: Option<String>,
    pub password_command: Option<String>,
}

impl ConfigStore for TomlConfigStore {
    fn read_config(&self, account_id: &str) -> Result<Option<AccountConfig>> {
        let path = self.config_path(account_id);
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Failed to read config: {}\n\nRun `unsubscribe init` to set up your config.",
                path.display(),
            )
        })?;
        let file: FileConfig = toml::from_str(&contents).context("Failed to parse config")?;

        Ok(Some(AccountConfig {
            account_id: file.imap.username.clone(),
            host: file.imap.host,
            port: Some(file.imap.port),
            username: file.imap.username,
            scan_folders: file.scan.folders,
            archive_folder: file.scan.archive_folder,
        }))
    }

    fn write_config(&self, config: &AccountConfig) -> Result<()> {
        let port = config.port.unwrap_or(993);

        // Preserve existing password/password_command fields if they exist
        let path = self.config_path(&config.account_id);
        let (existing_password, existing_command) = if path.exists() {
            let contents = std::fs::read_to_string(&path).unwrap_or_default();
            if let Ok(file) = toml::from_str::<FileConfig>(&contents) {
                (file.imap.password, file.imap.password_command)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let file = FileConfig {
            imap: FileImapConfig {
                host: config.host.clone(),
                port,
                username: config.username.clone(),
                password: existing_password,
                password_command: existing_command,
            },
            scan: FileScanConfig {
                folders: config.scan_folders.clone(),
                archive_folder: config.archive_folder.clone(),
            },
        };

        let toml_str = toml::to_string_pretty(&file).context("Failed to serialize config")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, toml_str)?;
        Ok(())
    }
}
