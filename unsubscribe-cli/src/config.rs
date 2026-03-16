use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "unsubscribe";

/// Runtime config — password is always resolved to a plain String
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

/// On-disk config — password is optional (may come from keyring or command)
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

impl Config {
    pub fn default_path() -> PathBuf {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let mut home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
                home.push(".config");
                home
            });
        config_dir.join("email-unsubscribe").join("config.toml")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}\n\nRun `unsubscribe init` to set up your config.",
                path.display(),
            ))?;
        let file: FileConfig = toml::from_str(&contents).context("Failed to parse config")?;

        let password = resolve_password(&file.imap)?;

        Ok(Config {
            imap: ImapConfig {
                host: file.imap.host,
                port: file.imap.port,
                username: file.imap.username,
                password,
            },
            scan: ScanConfig {
                folders: file.scan.folders,
                archive_folder: file.scan.archive_folder,
            },
        })
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

        // Add a comment about password storage
        let content = format!(
            "# Password is stored in your OS keychain ({KEYRING_SERVICE})\n\
             # To use a command instead, add:\n\
             #   password_command = \"pass show email/imap\"\n\n\
             {toml_str}"
        );

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Store the IMAP password in the OS keychain
    pub fn store_password(username: &str, password: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, username)
            .context("Failed to access OS keychain")?;
        entry
            .set_password(password)
            .context("Failed to store password in OS keychain")?;
        Ok(())
    }

    /// Delete the IMAP password from the OS keychain
    pub fn delete_password(username: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, username)
            .context("Failed to access OS keychain")?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // already gone
            Err(e) => Err(anyhow::anyhow!("Failed to delete from keychain: {e}")),
        }
    }
}

/// Resolve the IMAP password from (in priority order):
/// 1. `password_command` in config
/// 2. OS keychain via keyring
/// 3. Plain text `password` in config (legacy/fallback)
fn resolve_password(imap: &FileImapConfig) -> Result<String> {
    // 1. password_command
    if let Some(cmd) = &imap.password_command {
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
    match keyring::Entry::new(KEYRING_SERVICE, &imap.username) {
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
    if let Some(password) = &imap.password {
        eprintln!("Warning: using plain text password from config file.");
        eprintln!("Run `unsubscribe init` to store it securely in your OS keychain.\n");
        return Ok(password.clone());
    }

    anyhow::bail!(
        "No password found. Run `unsubscribe init` to store your password,\n\
         or add password_command to your config."
    )
}
