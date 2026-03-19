mod config;
mod credential;
mod data;

pub use config::TomlConfigStore;
pub use credential::KeyringCredentialStore;
pub use data::FileDataStore;

/// Keyring service name used across all credential and config operations.
pub(crate) const KEYRING_SERVICE: &str = "unsubscribe";
