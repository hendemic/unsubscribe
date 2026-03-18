use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use unsubscribe_core::{AccountConfig, AuthType, ConfigStore, ProviderType};

use crate::KEYRING_SERVICE;

/// On-disk TOML structure -- matches the existing config format exactly.
///
/// The `[account]` section is the canonical name. The `[imap]` alias provides
/// backward compatibility with configs written before this rename.
#[derive(Debug, Serialize, Deserialize)]
struct FileConfig {
    #[serde(alias = "imap")]
    account: FileAccountConfig,
    #[serde(default)]
    scan: FileScanConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileAccountConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_command: Option<String>,
    /// "password" (default) or "oauth". Controls how credentials are resolved.
    #[serde(default = "default_auth_type")]
    auth_type: String,
    /// "imap" (default) or "gmail". Controls which provider adapter to use.
    /// Existing configs without this field default to "imap" for backwards compatibility.
    #[serde(default = "default_provider")]
    provider: String,
}

fn default_provider() -> String {
    "imap".to_string()
}

fn default_auth_type() -> String {
    "password".to_string()
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
            username: file.account.username,
            password: file.account.password,
            password_command: file.account.password_command,
        }))
    }

    /// Write a config file with a header comment about credential storage.
    pub fn write_init(
        &self,
        host: Option<&str>,
        port: Option<u16>,
        username: &str,
        provider_type: &ProviderType,
        auth_type: &AuthType,
        folders: Vec<String>,
        archive_folder: &str,
    ) -> Result<()> {
        let auth_type_str = match auth_type {
            AuthType::OAuth => "oauth".to_string(),
            AuthType::Password => "password".to_string(),
        };

        let provider_str = match provider_type {
            ProviderType::Gmail => "gmail".to_string(),
            ProviderType::Imap => "imap".to_string(),
        };

        let file = FileConfig {
            account: FileAccountConfig {
                host: host.map(str::to_string),
                port,
                username: username.to_string(),
                password: None,
                password_command: None,
                auth_type: auth_type_str,
                provider: provider_str,
            },
            scan: FileScanConfig {
                folders,
                archive_folder: archive_folder.to_string(),
            },
        };

        let toml_str = toml::to_string_pretty(&file).context("Failed to serialize config")?;

        let header = match provider_type {
            ProviderType::Gmail => format!(
                "# Gmail account authenticated via OAuth.\n\
                 # Tokens are stored in your OS keychain ({KEYRING_SERVICE}).\n\
                 # Run `unsubscribe reauth` to re-authenticate.\n\n"
            ),
            ProviderType::Imap => format!(
                "# Password is stored in your OS keychain ({KEYRING_SERVICE})\n\
                 # To use a command instead, add:\n\
                 #   password_command = \"pass show email/imap\"\n\n"
            ),
        };

        let content = format!("{header}{toml_str}");

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

        let auth_type = match file.account.auth_type.as_str() {
            "oauth" => AuthType::OAuth,
            _ => AuthType::Password,
        };

        let provider_type = match file.account.provider.as_str() {
            "gmail" => ProviderType::Gmail,
            _ => ProviderType::Imap,
        };

        Ok(Some(AccountConfig {
            account_id: file.account.username.clone(),
            provider_type,
            host: file.account.host,
            port: file.account.port,
            username: file.account.username,
            auth_type,
            scan_folders: file.scan.folders,
            archive_folder: file.scan.archive_folder,
        }))
    }

    fn write_config(&self, config: &AccountConfig) -> Result<()> {
        // Preserve existing password/password_command fields if they exist
        let path = self.config_path(&config.account_id);
        let (existing_password, existing_command) = if path.exists() {
            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("Failed to read existing config: {}", path.display())))
                }
            };
            if let Ok(file) = toml::from_str::<FileConfig>(&contents) {
                (file.account.password, file.account.password_command)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let auth_type_str = match config.auth_type {
            AuthType::OAuth => "oauth".to_string(),
            AuthType::Password => "password".to_string(),
        };

        let provider_str = match config.provider_type {
            ProviderType::Gmail => "gmail".to_string(),
            ProviderType::Imap => "imap".to_string(),
        };

        let file = FileConfig {
            account: FileAccountConfig {
                host: config.host.clone(),
                port: config.port,
                username: config.username.clone(),
                password: existing_password,
                password_command: existing_command,
                auth_type: auth_type_str,
                provider: provider_str,
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
