mod config;
mod credential;
mod data;

pub use config::TomlConfigStore;
pub use credential::KeyringCredentialStore;
pub use data::FileDataStore;

/// Keyring service name used across all credential and config operations.
///
/// Public so consumers can tell the user where their credentials live without
/// duplicating the literal.
pub const KEYRING_SERVICE: &str = "unsubscribe";
