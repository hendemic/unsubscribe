use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use toml_edit::{value, Array, DocumentMut, Item, Table};

use unsubscribe_core::{
    AccountConfig, AuthType, ConfigStore, PreferenceField, Preferences, ProviderType,
};

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
    /// Optional user preferences. Absent section and absent keys both fall back
    /// to `Preferences::default()`; present-but-invalid values are an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preferences: Option<FilePreferences>,
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
    /// SMTP host for sending unsubscribe emails (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    smtp_host: Option<String>,
    /// SMTP port for sending unsubscribe emails (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    smtp_port: Option<u16>,
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

/// On-disk shape of `[preferences]`. Each key is optional so a partially
/// written section still gets defaults for the keys it omits.
#[derive(Debug, Default, Serialize, Deserialize)]
struct FilePreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_emails: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stale_after_months: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_max_age_days: Option<u32>,
}

impl FilePreferences {
    /// Fill in defaults for omitted keys, then range-check the result.
    fn resolve(&self) -> Result<Preferences> {
        let defaults = Preferences::default();
        let prefs = Preferences {
            min_emails: self.min_emails.unwrap_or(defaults.min_emails),
            stale_after_months: self.stale_after_months.unwrap_or(defaults.stale_after_months),
            cache_max_age_days: self.cache_max_age_days.unwrap_or(defaults.cache_max_age_days),
        };
        prefs
            .validate()
            .map_err(|e| anyhow!("Invalid [preferences] in config: {e}"))?;
        Ok(prefs)
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
        smtp_host: Option<&str>,
        smtp_port: Option<u16>,
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
                smtp_host: smtp_host.map(str::to_string),
                smtp_port,
            },
            scan: FileScanConfig {
                folders,
                archive_folder: archive_folder.to_string(),
            },
            // `init` writes no [preferences]; defaults apply until the user
            // sets one, either by hand or through `unsubscribe config`.
            preferences: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use unsubscribe_core::{AccountConfig, AuthType, ConfigStore, ProviderType};

    /// Write a config.toml with the given content into the tempdir and return the store.
    fn store_with_content(dir: &TempDir, toml: &str) -> TomlConfigStore {
        let path = dir.path().join("config.toml");
        fs::write(&path, toml).unwrap();
        TomlConfigStore::new(dir.path())
    }

    // ─── read_config ────────────────────────────────────────────────────────────

    #[test]
    fn read_config_returns_none_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());
        let result = store.read_config("irrelevant").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_config_parses_full_toml() {
        let dir = TempDir::new().unwrap();
        let toml = r#"
[account]
host = "imap.example.com"
port = 993
username = "user@example.com"
auth_type = "password"
provider = "imap"

[scan]
folders = ["INBOX", "Promotions"]
archive_folder = "Done"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();

        assert_eq!(config.host.as_deref(), Some("imap.example.com"));
        assert_eq!(config.port, Some(993));
        assert_eq!(config.username, "user@example.com");
        assert_eq!(config.auth_type, AuthType::Password);
        assert_eq!(config.provider_type, ProviderType::Imap);
        assert_eq!(config.scan_folders, vec!["INBOX", "Promotions"]);
        assert_eq!(config.archive_folder, "Done");
    }

    #[test]
    fn read_config_applies_defaults_for_minimal_toml() {
        let dir = TempDir::new().unwrap();
        // Only required field is username; everything else should default.
        let toml = r#"
[account]
username = "minimal@example.com"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();

        assert_eq!(config.host, None);
        assert_eq!(config.port, None);
        assert_eq!(config.auth_type, AuthType::Password);
        assert_eq!(config.provider_type, ProviderType::Imap);
        assert_eq!(config.scan_folders, vec!["INBOX"]);
        assert_eq!(config.archive_folder, "Unsubscribed");
    }

    #[test]
    fn read_config_accepts_legacy_imap_section_alias() {
        // Configs written before the [account] rename used [imap].
        let dir = TempDir::new().unwrap();
        let toml = r#"
[imap]
username = "legacy@example.com"
host = "imap.legacy.net"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();

        assert_eq!(config.username, "legacy@example.com");
        assert_eq!(config.host.as_deref(), Some("imap.legacy.net"));
    }

    #[test]
    fn read_config_maps_oauth_auth_type() {
        let dir = TempDir::new().unwrap();
        let toml = r#"
[account]
username = "oauth@example.com"
auth_type = "oauth"
provider = "gmail"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();

        assert_eq!(config.auth_type, AuthType::OAuth);
        assert_eq!(config.provider_type, ProviderType::Gmail);
    }

    #[test]
    fn read_config_unknown_auth_type_falls_back_to_password() {
        // Any unrecognised auth_type string should default to Password, not panic.
        let dir = TempDir::new().unwrap();
        let toml = r#"
[account]
username = "x@example.com"
auth_type = "xoauth2_future_value"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();
        assert_eq!(config.auth_type, AuthType::Password);
    }

    #[test]
    fn read_config_returns_error_for_malformed_toml() {
        let dir = TempDir::new().unwrap();
        let store = store_with_content(&dir, "this is not [ valid toml !!!");
        let result = store.read_config("any");
        assert!(result.is_err());
    }

    #[test]
    fn read_config_sets_account_id_to_username() {
        let dir = TempDir::new().unwrap();
        let toml = r#"
[account]
username = "id@example.com"
"#;
        let store = store_with_content(&dir, toml);
        let config = store.read_config("any").unwrap().unwrap();
        // account_id is derived from username, not from the argument.
        assert_eq!(config.account_id, "id@example.com");
    }

    // ─── write_config / round-trip ───────────────────────────────────────────────

    #[test]
    fn write_then_read_config_produces_identical_values() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());

        let original = AccountConfig {
            account_id: "rt@example.com".into(),
            provider_type: ProviderType::Imap,
            host: Some("imap.rt.com".into()),
            port: Some(993),
            username: "rt@example.com".into(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".into(), "Bulk Mail".into()],
            archive_folder: "Archive".into(),
            smtp_host: None,
            smtp_port: None,
        };

        store.write_config(&original).unwrap();
        let read_back = store.read_config("rt@example.com").unwrap().unwrap();

        assert_eq!(read_back.host, original.host);
        assert_eq!(read_back.port, original.port);
        assert_eq!(read_back.username, original.username);
        assert_eq!(read_back.auth_type, original.auth_type);
        assert_eq!(read_back.provider_type, original.provider_type);
        assert_eq!(read_back.scan_folders, original.scan_folders);
        assert_eq!(read_back.archive_folder, original.archive_folder);
    }

    #[test]
    fn write_config_preserves_existing_plaintext_password() {
        // write_config must not strip a password field already in the file.
        let dir = TempDir::new().unwrap();
        let initial_toml = r#"
[account]
username = "pw@example.com"
password = "s3cret"
"#;
        let store = store_with_content(&dir, initial_toml);

        // Overwrite with write_config (which has no password field).
        let config = AccountConfig {
            account_id: "pw@example.com".into(),
            provider_type: ProviderType::Imap,
            host: None,
            port: None,
            username: "pw@example.com".into(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".into()],
            archive_folder: "Unsubscribed".into(),
            smtp_host: None,
            smtp_port: None,
        };
        store.write_config(&config).unwrap();

        let raw = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(raw.contains("s3cret"), "password should be preserved after write_config");
    }

    #[test]
    fn write_config_creates_parent_directories() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        let store = TomlConfigStore::new(&nested);

        let config = AccountConfig {
            account_id: "mkdir@example.com".into(),
            provider_type: ProviderType::Imap,
            host: None,
            port: None,
            username: "mkdir@example.com".into(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".into()],
            archive_folder: "Unsubscribed".into(),
            smtp_host: None,
            smtp_port: None,
        };
        store.write_config(&config).unwrap();
        assert!(nested.join("config.toml").exists());
    }

    // ─── write_init ──────────────────────────────────────────────────────────────

    #[test]
    fn write_init_produces_valid_toml_with_imap_header() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());

        store
            .write_init(
                Some("imap.example.com"),
                Some(993),
                "init@example.com",
                &ProviderType::Imap,
                &AuthType::Password,
                vec!["INBOX".into()],
                "Unsubscribed",
                None,
                None,
            )
            .unwrap();

        let raw = fs::read_to_string(dir.path().join("config.toml")).unwrap();

        // Header comment should mention the keyring service.
        assert!(raw.contains(KEYRING_SERVICE), "header should mention keyring service name");

        // Should be parseable as valid TOML.
        let parsed: FileConfig = toml::from_str(
            // Strip leading comment lines so toml parser accepts it cleanly.
            &raw.lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .expect("write_init should produce valid TOML");

        assert_eq!(parsed.account.username, "init@example.com");
        assert_eq!(parsed.account.host.as_deref(), Some("imap.example.com"));
        assert_eq!(parsed.account.port, Some(993));
    }

    #[test]
    fn write_init_produces_gmail_header_for_gmail_provider() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());

        store
            .write_init(
                None,
                None,
                "gmail@example.com",
                &ProviderType::Gmail,
                &AuthType::OAuth,
                vec!["INBOX".into()],
                "Unsubscribed",
                None,
                None,
            )
            .unwrap();

        let raw = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(
            raw.contains("Gmail"),
            "IMAP header should not appear for Gmail provider"
        );
    }

    #[test]
    fn write_init_does_not_include_password_field() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());

        store
            .write_init(
                Some("imap.example.com"),
                Some(993),
                "nopw@example.com",
                &ProviderType::Imap,
                &AuthType::Password,
                vec!["INBOX".into()],
                "Unsubscribed",
                None,
                None,
            )
            .unwrap();

        let raw = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        // password is skipped when None (skip_serializing_if).
        assert!(
            !raw.contains("password ="),
            "write_init must not write a password field"
        );
    }
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
            smtp_host: file.account.smtp_host,
            smtp_port: file.account.smtp_port,
        }))
    }

    fn write_config(&self, config: &AccountConfig) -> Result<()> {
        let auth_type_str = match config.auth_type {
            AuthType::OAuth => "oauth",
            AuthType::Password => "password",
        };
        let provider_str = match config.provider_type {
            ProviderType::Gmail => "gmail",
            ProviderType::Imap => "imap",
        };

        // Edited in place rather than re-serialized, so comments, key order,
        // and keys this struct does not model (password, password_command,
        // anything a future version adds) all survive the write.
        edit_document(&self.config_path(&config.account_id), |doc| {
            let section = account_section_name(doc);
            let account = table_mut(doc, section)?;
            set_opt_str(account, "host", config.host.as_deref());
            set_opt_int(account, "port", config.port);
            set_str(account, "username", &config.username);
            set_str(account, "auth_type", auth_type_str);
            set_str(account, "provider", provider_str);
            set_opt_str(account, "smtp_host", config.smtp_host.as_deref());
            set_opt_int(account, "smtp_port", config.smtp_port);

            let scan = table_mut(doc, SCAN_SECTION)?;
            set_str_array(scan, "folders", &config.scan_folders);
            set_str(scan, "archive_folder", &config.archive_folder);
            Ok(())
        })
    }

    fn read_preferences(&self) -> Result<Preferences> {
        let path = self.config_path("");
        if !path.exists() {
            return Ok(Preferences::default());
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let file: FileConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        file.preferences.unwrap_or_default().resolve()
    }

    fn write_preferences(&self, preferences: &Preferences) -> Result<()> {
        preferences
            .validate()
            .map_err(|e| anyhow!("Refusing to write invalid preferences: {e}"))?;

        edit_document(&self.config_path(""), |doc| {
            let created = !doc.contains_key(PREFERENCES_SECTION);
            let table = table_mut(doc, PREFERENCES_SECTION)?;
            if created {
                table.decor_mut().set_prefix(PREFERENCES_HEADER_COMMENT);
            }
            for field in PreferenceField::ALL {
                set_int(table, field.key(), preferences.get(field));
            }
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Comment-preserving TOML editing
// ---------------------------------------------------------------------------

const ACCOUNT_SECTION: &str = "account";
/// Section name used by configs written before the `[account]` rename.
const LEGACY_ACCOUNT_SECTION: &str = "imap";
const SCAN_SECTION: &str = "scan";
const PREFERENCES_SECTION: &str = "preferences";

/// Written above a `[preferences]` section the first time one is created, so a
/// hand-edited config explains itself.
const PREFERENCES_HEADER_COMMENT: &str = "\n# Behavior settings. Edit here or run `unsubscribe config`.\n";

/// Read `path`, hand the parsed document to `apply`, and write it back.
///
/// A missing file starts from an empty document. The file is left untouched --
/// mtime included -- when `apply` produces no textual change, which is what
/// keeps an unchanged save byte-identical.
fn edit_document(path: &Path, apply: impl FnOnce(&mut DocumentMut) -> Result<()>) -> Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("Failed to read existing config: {}", path.display())))
        }
    };

    let mut doc: DocumentMut = existing
        .parse()
        .with_context(|| format!("Failed to parse config: {}", path.display()))?;
    apply(&mut doc)?;

    let updated = doc.to_string();
    if updated == existing && path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, updated)
        .with_context(|| format!("Failed to write config: {}", path.display()))?;
    Ok(())
}

/// Which section holds account settings in this document: the legacy `[imap]`
/// name when that is what the file already uses, `[account]` otherwise.
fn account_section_name(doc: &DocumentMut) -> &'static str {
    if !doc.contains_key(ACCOUNT_SECTION) && doc.contains_key(LEGACY_ACCOUNT_SECTION) {
        LEGACY_ACCOUNT_SECTION
    } else {
        ACCOUNT_SECTION
    }
}

/// Borrow a top-level table, creating it if absent.
fn table_mut<'a>(doc: &'a mut DocumentMut, name: &str) -> Result<&'a mut Table> {
    if !doc.contains_key(name) {
        let mut table = Table::new();
        // Without this, an empty table is elided from the rendered document.
        table.set_implicit(false);
        doc.insert(name, Item::Table(table));
    }
    doc[name]
        .as_table_mut()
        .ok_or_else(|| anyhow!("`{name}` in config is not a table"))
}

/// Each setter is a no-op when the stored value already matches, so that keys
/// the user never changed keep their original formatting and comments.
fn set_str(table: &mut Table, key: &str, new: &str) {
    if table.get(key).and_then(Item::as_str) == Some(new) {
        return;
    }
    table[key] = value(new);
}

fn set_opt_str(table: &mut Table, key: &str, new: Option<&str>) {
    match new {
        Some(v) => set_str(table, key, v),
        None => {
            table.remove(key);
        }
    }
}

fn set_int(table: &mut Table, key: &str, new: u32) {
    if table.get(key).and_then(Item::as_integer) == Some(i64::from(new)) {
        return;
    }
    table[key] = value(i64::from(new));
}

fn set_opt_int(table: &mut Table, key: &str, new: Option<u16>) {
    match new {
        Some(v) => set_int(table, key, u32::from(v)),
        None => {
            table.remove(key);
        }
    }
}

fn set_str_array(table: &mut Table, key: &str, items: &[String]) {
    let unchanged = table
        .get(key)
        .and_then(Item::as_array)
        .is_some_and(|existing| {
            existing.len() == items.len()
                && existing
                    .iter()
                    .zip(items)
                    .all(|(a, b)| a.as_str() == Some(b.as_str()))
        });
    if unchanged {
        return;
    }
    table[key] = value(items.iter().collect::<Array>());
}

// ---------------------------------------------------------------------------
// Preferences: defaulting and validation on read/write
// ---------------------------------------------------------------------------

#[cfg(test)]
mod preferences_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use unsubscribe_core::{ConfigStore, Preferences};

    /// A config file with only the one key `read_config` insists on, so that
    /// whatever `[preferences]` the test adds is the only thing under test.
    const MINIMAL_ACCOUNT: &str = "[account]\nusername = \"user@example.com\"\n";

    fn store_with(dir: &TempDir, toml: &str) -> TomlConfigStore {
        fs::write(dir.path().join("config.toml"), toml).unwrap();
        TomlConfigStore::new(dir.path())
    }

    fn store_with_preferences(dir: &TempDir, section: &str) -> TomlConfigStore {
        store_with(dir, &format!("{MINIMAL_ACCOUNT}\n[preferences]\n{section}"))
    }

    /// Full error chain, so a `.context()` wrapper cannot hide the message.
    fn error_text(result: Result<Preferences>) -> String {
        format!("{:#}", result.expect_err("expected an error"))
    }

    // ─── defaults ───────────────────────────────────────────────────────────

    #[test]
    fn missing_config_file_yields_defaults() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path());
        let prefs = store.read_preferences().unwrap();
        // Spelled out rather than compared to `Preferences::default()`: these
        // are the documented defaults, and a change to them should be noticed.
        assert_eq!(prefs.min_emails, 3);
        assert_eq!(prefs.stale_after_months, 12);
        assert_eq!(prefs.cache_max_age_days, 7);
    }

    #[test]
    fn config_without_preferences_section_yields_defaults() {
        let dir = TempDir::new().unwrap();
        let store = store_with(&dir, MINIMAL_ACCOUNT);
        let prefs = store.read_preferences().unwrap();
        assert_eq!(prefs.min_emails, 3);
        assert_eq!(prefs.stale_after_months, 12);
        assert_eq!(prefs.cache_max_age_days, 7);
    }

    #[test]
    fn empty_preferences_section_yields_defaults() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "");
        let prefs = store.read_preferences().unwrap();
        assert_eq!(prefs.min_emails, 3);
        assert_eq!(prefs.stale_after_months, 12);
        assert_eq!(prefs.cache_max_age_days, 7);
    }

    #[test]
    fn partial_preferences_use_present_keys_and_default_the_rest() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "stale_after_months = 4\n");
        let prefs = store.read_preferences().unwrap();
        assert_eq!(prefs.stale_after_months, 4, "the key that was present");
        assert_eq!(prefs.min_emails, 3, "absent key falls back to the default");
        assert_eq!(prefs.cache_max_age_days, 7, "absent key falls back to the default");
    }

    #[test]
    fn all_preference_keys_are_read_from_the_file() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(
            &dir,
            "min_emails = 1\nstale_after_months = 24\ncache_max_age_days = 30\n",
        );
        let prefs = store.read_preferences().unwrap();
        assert_eq!(prefs.min_emails, 1);
        assert_eq!(prefs.stale_after_months, 24);
        assert_eq!(prefs.cache_max_age_days, 30);
    }

    // ─── bad values are reported, never silently defaulted ──────────────────

    #[test]
    fn string_valued_preference_is_an_error_not_a_default() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "min_emails = \"three\"\n");
        let message = error_text(store.read_preferences());
        assert!(
            message.contains("min_emails"),
            "error should name the offending key, got: {message}"
        );
    }

    #[test]
    fn boolean_valued_preference_is_an_error() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "cache_max_age_days = true\n");
        let message = error_text(store.read_preferences());
        assert!(
            message.contains("cache_max_age_days"),
            "error should name the offending key, got: {message}"
        );
    }

    #[test]
    fn negative_preference_is_an_error() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "min_emails = -1\n");
        let message = error_text(store.read_preferences());
        assert!(
            message.contains("min_emails"),
            "error should name the offending key, got: {message}"
        );
    }

    #[test]
    fn fractional_preference_is_an_error() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "stale_after_months = 1.5\n");
        assert!(store.read_preferences().is_err());
    }

    #[test]
    fn zero_stale_after_months_is_rejected_with_its_range() {
        // 0 months would mark every sender stale, so the range starts at 1.
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "stale_after_months = 0\n");
        let message = error_text(store.read_preferences());
        assert!(message.contains("stale_after_months"), "got: {message}");
        assert!(message.contains("between 1 and 1200"), "got: {message}");
    }

    #[test]
    fn zero_cache_max_age_days_is_rejected() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "cache_max_age_days = 0\n");
        let message = error_text(store.read_preferences());
        assert!(message.contains("cache_max_age_days"), "got: {message}");
        assert!(message.contains("between 1 and 3650"), "got: {message}");
    }

    #[test]
    fn zero_min_emails_is_accepted_because_it_disables_the_filter() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "min_emails = 0\n");
        assert_eq!(store.read_preferences().unwrap().min_emails, 0);
    }

    #[test]
    fn preference_at_the_upper_bound_is_accepted() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(
            &dir,
            "min_emails = 1000000\nstale_after_months = 1200\ncache_max_age_days = 3650\n",
        );
        let prefs = store.read_preferences().unwrap();
        assert_eq!(prefs.min_emails, 1_000_000);
        assert_eq!(prefs.stale_after_months, 1200);
        assert_eq!(prefs.cache_max_age_days, 3650);
    }

    #[test]
    fn preference_one_past_the_upper_bound_is_rejected() {
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "cache_max_age_days = 3651\n");
        let message = error_text(store.read_preferences());
        assert!(message.contains("3651"), "error should quote the value, got: {message}");
    }

    #[test]
    fn a_pasted_timestamp_is_reported_rather_than_accepted() {
        // The failure the finite upper bounds exist to catch.
        let dir = TempDir::new().unwrap();
        let store = store_with_preferences(&dir, "stale_after_months = 1774000000\n");
        assert!(store.read_preferences().is_err());
    }

    // ─── writing ────────────────────────────────────────────────────────────

    #[test]
    fn written_preferences_are_read_back_unchanged() {
        let dir = TempDir::new().unwrap();
        let store = store_with(&dir, MINIMAL_ACCOUNT);
        let wanted = Preferences {
            min_emails: 11,
            stale_after_months: 2,
            cache_max_age_days: 90,
        };
        store.write_preferences(&wanted).unwrap();
        assert_eq!(store.read_preferences().unwrap(), wanted);
    }

    #[test]
    fn writing_out_of_range_preferences_is_refused() {
        let dir = TempDir::new().unwrap();
        let store = store_with(&dir, MINIMAL_ACCOUNT);
        let invalid = Preferences {
            min_emails: 3,
            stale_after_months: 0,
            cache_max_age_days: 7,
        };
        let message = format!("{:#}", store.write_preferences(&invalid).unwrap_err());
        assert!(message.contains("stale_after_months"), "got: {message}");
    }

    #[test]
    fn a_refused_write_leaves_the_file_untouched() {
        let dir = TempDir::new().unwrap();
        let store = store_with(&dir, MINIMAL_ACCOUNT);
        let invalid = Preferences {
            min_emails: 3,
            stale_after_months: 3000,
            cache_max_age_days: 7,
        };
        assert!(store.write_preferences(&invalid).is_err());
        let on_disk = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert_eq!(on_disk, MINIMAL_ACCOUNT);
    }
}

// ---------------------------------------------------------------------------
// Comment-preserving writes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod comment_preserving_write_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use unsubscribe_core::{ConfigStore, Preferences};

    /// A hand-annotated config of the kind a user ends up with: a header
    /// comment, blank lines between sections, a credential command, a key this
    /// version does not model, and a whole section it has never heard of.
    const ANNOTATED: &str = r#"# Password is stored in your OS keychain (email-unsubscribe)
# To use a command instead, add:
#   password_command = "pass show email/imap"

[account]
host = "imap.example.com"
port = 993
username = "user@example.com"
password = "hunter2"
password_command = "pass show email/imap"
auth_type = "password"
provider = "imap"
# Not a key this version writes; a hand edit or a newer build left it here.
nickname = "work"

[scan]
# Folders swept for List-Unsubscribe headers.
folders = ["INBOX", "Promotions"]
archive_folder = "Unsubscribed"

[preferences]
min_emails = 5
stale_after_months = 6
cache_max_age_days = 3

# A section this version does not model at all.
[experimental]
enabled = true
"#;

    /// The same file before `[preferences]` existed.
    const ANNOTATED_WITHOUT_PREFERENCES: &str = r#"# Password is stored in your OS keychain (email-unsubscribe)

[account]
host = "imap.example.com"
port = 993
username = "user@example.com"
auth_type = "password"
provider = "imap"

[scan]
# Folders swept for List-Unsubscribe headers.
folders = ["INBOX"]
archive_folder = "Unsubscribed"
"#;

    /// A config written before the `[account]` rename.
    const LEGACY_IMAP: &str = r#"# Written by an older version, which called the section [imap].
[imap]
host = "imap.legacy.net"
port = 993
username = "legacy@example.com"
password_command = "pass show email/legacy"
auth_type = "password"
provider = "imap"

[scan]
folders = ["INBOX"]
archive_folder = "Unsubscribed"
"#;

    struct Fixture {
        _dir: TempDir,
        path: PathBuf,
        store: TomlConfigStore,
    }

    impl Fixture {
        fn new(contents: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("config.toml");
            fs::write(&path, contents).unwrap();
            let store = TomlConfigStore::new(dir.path());
            Self { _dir: dir, path, store }
        }

        fn text(&self) -> String {
            fs::read_to_string(&self.path).unwrap()
        }
    }

    // ─── an unchanged save changes nothing ──────────────────────────────────

    #[test]
    fn writing_back_an_unchanged_account_leaves_the_file_byte_identical() {
        let fixture = Fixture::new(ANNOTATED);
        let account = fixture.store.read_config("").unwrap().unwrap();
        fixture.store.write_config(&account).unwrap();
        assert_eq!(fixture.text(), ANNOTATED);
    }

    #[test]
    fn writing_back_unchanged_preferences_leaves_the_file_byte_identical() {
        let fixture = Fixture::new(ANNOTATED);
        let preferences = fixture.store.read_preferences().unwrap();
        fixture.store.write_preferences(&preferences).unwrap();
        assert_eq!(fixture.text(), ANNOTATED);
    }

    #[test]
    fn writing_back_an_unchanged_legacy_config_leaves_the_file_byte_identical() {
        let fixture = Fixture::new(LEGACY_IMAP);
        let account = fixture.store.read_config("").unwrap().unwrap();
        fixture.store.write_config(&account).unwrap();
        assert_eq!(fixture.text(), LEGACY_IMAP);
    }

    // ─── changing one value changes exactly one line ────────────────────────

    #[test]
    fn changing_the_archive_folder_rewrites_only_that_line() {
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.archive_folder = "Archive".to_string();
        fixture.store.write_config(&account).unwrap();

        let expected = ANNOTATED.replace(
            r#"archive_folder = "Unsubscribed""#,
            r#"archive_folder = "Archive""#,
        );
        assert_eq!(fixture.text(), expected);
    }

    #[test]
    fn changing_the_scan_folders_rewrites_only_that_line() {
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.scan_folders = vec!["INBOX".into(), "Newsletters".into(), "Bulk".into()];
        fixture.store.write_config(&account).unwrap();

        let expected = ANNOTATED.replace(
            r#"folders = ["INBOX", "Promotions"]"#,
            r#"folders = ["INBOX", "Newsletters", "Bulk"]"#,
        );
        assert_eq!(fixture.text(), expected);
    }

    #[test]
    fn changing_one_preference_rewrites_only_that_line() {
        let fixture = Fixture::new(ANNOTATED);
        let mut preferences = fixture.store.read_preferences().unwrap();
        preferences.min_emails = 9;
        fixture.store.write_preferences(&preferences).unwrap();

        let expected = ANNOTATED.replace("min_emails = 5", "min_emails = 9");
        assert_eq!(fixture.text(), expected);
    }

    #[test]
    fn reordering_the_scan_folders_is_written_out() {
        // Order is meaningful to the user, so an equal-set reorder must persist.
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.scan_folders = vec!["Promotions".into(), "INBOX".into()];
        fixture.store.write_config(&account).unwrap();

        let reread = fixture.store.read_config("").unwrap().unwrap();
        assert_eq!(reread.scan_folders, vec!["Promotions", "INBOX"]);
    }

    // ─── what must never be lost ────────────────────────────────────────────

    #[test]
    fn credentials_in_the_file_survive_a_write() {
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.host = Some("imap.new.example.com".to_string());
        fixture.store.write_config(&account).unwrap();

        let resolution = fixture
            .store
            .read_file_imap_config("")
            .unwrap()
            .expect("config should still be readable");
        assert_eq!(resolution.password.as_deref(), Some("hunter2"));
        assert_eq!(
            resolution.password_command.as_deref(),
            Some("pass show email/imap")
        );
    }

    #[test]
    fn unknown_keys_and_sections_survive_a_write() {
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.port = Some(1993);
        fixture.store.write_config(&account).unwrap();

        let text = fixture.text();
        assert!(text.contains(r#"nickname = "work""#), "unknown key dropped:\n{text}");
        assert!(text.contains("[experimental]"), "unknown section dropped:\n{text}");
        assert!(text.contains("enabled = true"), "unknown section body dropped:\n{text}");
    }

    #[test]
    fn comments_survive_a_write() {
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.username = "renamed@example.com".to_string();
        fixture.store.write_config(&account).unwrap();

        let text = fixture.text();
        for comment in ANNOTATED.lines().filter(|l| l.trim_start().starts_with('#')) {
            assert!(text.contains(comment), "lost comment {comment:?}:\n{text}");
        }
    }

    #[test]
    fn preferences_survive_an_account_write() {
        // The two write paths touch different sections; neither may clobber
        // the other's.
        let fixture = Fixture::new(ANNOTATED);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.username = "renamed@example.com".to_string();
        fixture.store.write_config(&account).unwrap();

        let preferences = fixture.store.read_preferences().unwrap();
        assert_eq!(preferences.min_emails, 5);
        assert_eq!(preferences.stale_after_months, 6);
        assert_eq!(preferences.cache_max_age_days, 3);
    }

    #[test]
    fn account_settings_survive_a_preferences_write() {
        let fixture = Fixture::new(ANNOTATED);
        let mut preferences = fixture.store.read_preferences().unwrap();
        preferences.cache_max_age_days = 21;
        fixture.store.write_preferences(&preferences).unwrap();

        let account = fixture.store.read_config("").unwrap().unwrap();
        assert_eq!(account.username, "user@example.com");
        assert_eq!(account.host.as_deref(), Some("imap.example.com"));
        assert_eq!(account.scan_folders, vec!["INBOX", "Promotions"]);
    }

    // ─── legacy [imap] section ──────────────────────────────────────────────

    #[test]
    fn a_legacy_config_is_written_back_under_its_own_section_header() {
        let fixture = Fixture::new(LEGACY_IMAP);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.host = Some("imap.moved.net".to_string());
        fixture.store.write_config(&account).unwrap();

        let text = fixture.text();
        assert!(text.contains("[imap]"), "legacy section header lost:\n{text}");
        assert!(
            !text.contains("[account]"),
            "a duplicate [account] section was added:\n{text}"
        );
        assert_eq!(
            fixture.store.read_config("").unwrap().unwrap().host.as_deref(),
            Some("imap.moved.net"),
        );
    }

    #[test]
    fn a_legacy_config_keeps_its_password_command() {
        let fixture = Fixture::new(LEGACY_IMAP);
        let mut account = fixture.store.read_config("").unwrap().unwrap();
        account.archive_folder = "Archive".to_string();
        fixture.store.write_config(&account).unwrap();

        let resolution = fixture.store.read_file_imap_config("").unwrap().unwrap();
        assert_eq!(
            resolution.password_command.as_deref(),
            Some("pass show email/legacy")
        );
    }

    #[test]
    fn preferences_can_be_added_to_a_legacy_config() {
        let fixture = Fixture::new(LEGACY_IMAP);
        fixture
            .store
            .write_preferences(&Preferences {
                min_emails: 2,
                stale_after_months: 3,
                cache_max_age_days: 4,
            })
            .unwrap();

        let text = fixture.text();
        assert!(text.contains("[imap]"), "legacy section header lost:\n{text}");
        let preferences = fixture.store.read_preferences().unwrap();
        assert_eq!(preferences.min_emails, 2);
    }

    // ─── creating the [preferences] section ─────────────────────────────────

    #[test]
    fn adding_preferences_appends_without_disturbing_the_rest_of_the_file() {
        let fixture = Fixture::new(ANNOTATED_WITHOUT_PREFERENCES);
        fixture
            .store
            .write_preferences(&Preferences {
                min_emails: 4,
                stale_after_months: 8,
                cache_max_age_days: 14,
            })
            .unwrap();

        let text = fixture.text();
        assert!(
            text.starts_with(ANNOTATED_WITHOUT_PREFERENCES),
            "the original file is no longer an untouched prefix:\n{text}"
        );
        assert!(text.contains("[preferences]"), "section not created:\n{text}");
    }

    #[test]
    fn a_created_preferences_section_explains_itself() {
        let fixture = Fixture::new(ANNOTATED_WITHOUT_PREFERENCES);
        fixture.store.write_preferences(&Preferences::default()).unwrap();
        let text = fixture.text();
        assert!(
            text.contains("unsubscribe config"),
            "a hand-edited config should say where these came from:\n{text}"
        );
    }

    #[test]
    fn a_created_preferences_section_writes_every_key() {
        let fixture = Fixture::new(ANNOTATED_WITHOUT_PREFERENCES);
        fixture
            .store
            .write_preferences(&Preferences {
                min_emails: 4,
                stale_after_months: 8,
                cache_max_age_days: 14,
            })
            .unwrap();

        let text = fixture.text();
        assert!(text.contains("min_emails = 4"), "{text}");
        assert!(text.contains("stale_after_months = 8"), "{text}");
        assert!(text.contains("cache_max_age_days = 14"), "{text}");
    }

    #[test]
    fn the_header_comment_is_written_only_once() {
        let fixture = Fixture::new(ANNOTATED_WITHOUT_PREFERENCES);
        fixture.store.write_preferences(&Preferences::default()).unwrap();
        fixture
            .store
            .write_preferences(&Preferences {
                min_emails: 42,
                ..Preferences::default()
            })
            .unwrap();

        let text = fixture.text();
        assert_eq!(
            text.matches("Behavior settings").count(),
            1,
            "the explanatory comment was duplicated:\n{text}"
        );
    }

    // ─── a config file that does not exist yet ──────────────────────────────

    #[test]
    #[ignore = "bug: write_preferences on a missing config file writes a \
                preferences-only config.toml that read_preferences then rejects \
                for a missing [account] section"]
    fn writing_preferences_without_a_config_file_creates_a_readable_one() {
        let dir = TempDir::new().unwrap();
        let store = TomlConfigStore::new(dir.path().join("nested"));
        store
            .write_preferences(&Preferences {
                min_emails: 6,
                stale_after_months: 6,
                cache_max_age_days: 6,
            })
            .unwrap();

        assert_eq!(store.read_preferences().unwrap().min_emails, 6);
    }

    // ─── a file that cannot be parsed is not overwritten ────────────────────

    #[test]
    fn an_unparseable_config_is_reported_rather_than_replaced() {
        let broken = "[account\nusername = oops";
        let fixture = Fixture::new(broken);
        let result = fixture.store.write_preferences(&Preferences::default());
        assert!(result.is_err(), "a broken config should not be silently rewritten");
        assert_eq!(fixture.text(), broken, "the user's file was clobbered");
    }
}
