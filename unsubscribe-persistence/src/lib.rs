mod cache;
mod config;
mod credential;
mod data;
mod history;
mod lock;
pub mod settings;
mod sqlite;

pub use cache::{SqliteCacheStore, CACHE_DB_FILE};
pub use config::TomlConfigStore;
pub use credential::KeyringCredentialStore;
pub use data::FileDataStore;
pub use history::{SqliteHistoryStore, HISTORY_DB_FILE};
pub use lock::{LockInfo, LockOutcome, RunLock};
pub use settings::{split_folders, SettingKey, SettingKind, Settings};

/// Keyring service name used across all credential and config operations.
///
/// Public so consumers can tell the user where their credentials live without
/// duplicating the literal.
pub const KEYRING_SERVICE: &str = "unsubscribe";

/// The XDG data directory this app stores its files in.
///
/// Shared by the file-backed store and the SQLite stores so there is one
/// answer to "where does our data live" for uninstall and for tests.
pub fn data_dir() -> std::path::PathBuf {
    let dir = std::env::var("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let mut home =
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
            home.push(".local/share");
            home
        });
    dir.join("email-unsubscribe")
}
