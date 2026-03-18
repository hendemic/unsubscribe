mod config;
mod credential;

pub use config::TomlConfigStore;
pub use credential::KeyringCredentialStore;

/// Keyring service name used across all credential and config operations.
pub(crate) const KEYRING_SERVICE: &str = "unsubscribe";
