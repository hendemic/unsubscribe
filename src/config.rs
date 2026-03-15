use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub imap: ImapConfig,
    #[serde(default)]
    pub scan: ScanConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    /// IMAP folders to scan (default: just INBOX)
    #[serde(default = "default_folders")]
    pub folders: Vec<String>,
    /// Folder to archive unsubscribed emails into
    #[serde(default = "default_archive_folder")]
    pub archive_folder: String,
}

fn default_folders() -> Vec<String> {
    vec!["INBOX".to_string()]
}

fn default_archive_folder() -> String {
    "Unsubscribed".to_string()
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            folders: default_folders(),
            archive_folder: default_archive_folder(),
        }
    }
}

impl Config {
    /// Returns the default config path: `$XDG_CONFIG_HOME/email-unsubscribe/config.toml`
    /// (typically `~/.config/email-unsubscribe/config.toml`)
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
            .with_context(|| format!("Failed to read config: {}\n\nTo get started, create it with:\n  mkdir -p {}\n  cp config.toml.example {}",
                path.display(),
                path.parent().map(|p| p.display().to_string()).unwrap_or_default(),
                path.display(),
            ))?;
        toml::from_str(&contents).context("Failed to parse config")
    }
}
