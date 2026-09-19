//! `config` command: read and change settings, from a script or a screen.
//!
//! Every key is validated by the shared schema in the config layer, and every
//! write goes through the comment-preserving editor, so `config set` and the
//! settings screen leave the same file behind. Credentials are deliberately
//! absent: `config` can say where they live and nothing more.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use unsubscribe_core::{AccountConfig, ConfigStore, Credential, CredentialStore, Preferences, ProviderType};
use unsubscribe_persistence::{
    SettingKey, SqliteCacheStore, TomlConfigStore, KEYRING_SERVICE,
};

use crate::commands::setup::cmd_reauth;
use crate::exit::{Exit, ExitError};
use crate::json as json_out;
use crate::make_credential_store;
use crate::note;
use crate::output;
use crate::terminal::{Tty, BOLD, DIM, RESET, YELLOW};
use crate::tui::config::{run, SettingsIo};

/// What `config` was asked to do. Bare `config` has no action.
#[derive(Debug, Clone, Subcommand)]
pub enum ConfigAction {
    /// Print every setting, its value, and whether it is a default
    List,
    /// Print one setting's value
    Get {
        /// Dotted key, e.g. `scan.folders`
        key: String,
    },
    /// Validate and write one setting
    Set {
        /// Dotted key, e.g. `preferences.min_emails`
        key: String,
        /// The new value. List settings accept several values or one
        /// comma-separated string
        #[arg(required = true, num_args = 1..)]
        value: Vec<String>,
    },
    /// Remove an optional setting, restoring its default
    Unset {
        /// Dotted key, e.g. `account.smtp_host`
        key: String,
    },
    /// Print where the config file and data directory live
    Path,
}

pub fn cmd_config(
    config_dir: &Path,
    action: Option<ConfigAction>,
    as_json: bool,
    tty: Tty,
) -> Result<Exit> {
    // `config path` answers a question about a config that may not exist yet,
    // so it runs before the file is required.
    if let Some(ConfigAction::Path) = action {
        return cmd_path(config_dir, as_json);
    }

    let config_path = config_dir.join("config.toml");
    if !config_path.exists() {
        return Err(ExitError::usage(format!(
            "No config file found at {}. Run `unsubscribe init` to set one up.",
            config_path.display()
        ))
        .into());
    }
    let store = TomlConfigStore::new(config_dir);

    match action {
        Some(ConfigAction::List) => cmd_list(&store, as_json),
        Some(ConfigAction::Get { key }) => cmd_get(&store, &key, as_json),
        Some(ConfigAction::Set { key, value }) => cmd_set(&store, &key, &value),
        Some(ConfigAction::Unset { key }) => cmd_unset(&store, &key),
        Some(ConfigAction::Path) => unreachable!("handled above"),
        // A screen needs someone to look at it. Without one, the useful
        // reading of a bare `config` is "show me the settings".
        None if !tty.stdout || !tty.stdin => cmd_list(&store, as_json),
        None => open_settings_screen(config_dir, &store).map(|()| Exit::Success),
    }
}

fn open_settings_screen(config_dir: &Path, store: &TomlConfigStore) -> Result<()> {
    let account = store.read_config("")?.with_context(|| {
        format!(
            "Failed to read config: {}",
            config_dir.join("config.toml").display()
        )
    })?;
    let preferences = store.read_preferences()?;

    let io_ops = ConfigIo::new(config_dir, &account);

    run(&account, &preferences, &io_ops)
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmd_list(store: &TomlConfigStore, as_json: bool) -> Result<Exit> {
    let settings = store.read_settings()?;
    let explicit = store.explicit_settings()?;
    let rows: Vec<(SettingKey, String, bool)> = SettingKey::ALL
        .into_iter()
        .map(|key| {
            let value = settings.get(key);
            (key, value, !explicit.contains(&key))
        })
        .collect();

    if as_json {
        let settings_json: Vec<Value> = rows
            .iter()
            .map(|(key, value, is_default)| {
                json!({
                    "key": key.key(),
                    "label": key.label(),
                    "value": value,
                    "is_default": is_default,
                })
            })
            .collect();
        let mut doc = json_out::document("config", &settings.username);
        doc.insert("settings".to_string(), json!(settings_json));
        doc.insert(
            "credentials".to_string(),
            json!({ "location": format!("OS keychain ({KEYRING_SERVICE})") }),
        );
        doc.insert(
            "config_file".to_string(),
            json!(store.config_file().display().to_string()),
        );
        output::emit_json(&Value::Object(doc))?;
        return Ok(Exit::Success);
    }

    for (key, value, is_default) in &rows {
        let marker = if *is_default {
            format!(" {DIM}(default){RESET}")
        } else {
            String::new()
        };
        let shown = if value.is_empty() { "-" } else { value.as_str() };
        println!("{:<32} {shown}{marker}", key.key());
    }
    note!(
        "\n{DIM}Credentials are stored in the OS keychain ({KEYRING_SERVICE}) \
         and are never shown or changed here.{RESET}"
    );
    Ok(Exit::Success)
}

fn cmd_get(store: &TomlConfigStore, name: &str, as_json: bool) -> Result<Exit> {
    let key = parse_key(name)?;
    let settings = store.read_settings()?;
    let value = settings.get(key);
    let is_default = !store.explicit_settings()?.contains(&key);

    if as_json {
        let mut doc = json_out::document("config", &settings.username);
        doc.insert(
            "setting".to_string(),
            json!({
                "key": key.key(),
                "value": value,
                "is_default": is_default,
            }),
        );
        output::emit_json(&Value::Object(doc))?;
        return Ok(Exit::Success);
    }

    println!("{value}");
    Ok(Exit::Success)
}

fn cmd_set(store: &TomlConfigStore, name: &str, values: &[String]) -> Result<Exit> {
    let key = parse_key(name)?;
    let value = join_values(key, values)?;
    store
        .set_setting(key, &value)
        .map_err(|e| ExitError::usage(format!("{e:#}")))?;

    note!("{BOLD}{}{RESET} = {}", key.key(), store.read_settings()?.get(key));
    warn_if_credentials_affected(key);
    Ok(Exit::Success)
}

fn cmd_unset(store: &TomlConfigStore, name: &str) -> Result<Exit> {
    let key = parse_key(name)?;
    store
        .unset_setting(key)
        .map_err(|e| ExitError::usage(format!("{e:#}")))?;

    note!(
        "{BOLD}{}{RESET} unset; the default ({}) applies.",
        key.key(),
        display_default(key)
    );
    warn_if_credentials_affected(key);
    Ok(Exit::Success)
}

fn cmd_path(config_dir: &Path, as_json: bool) -> Result<Exit> {
    let config_file = config_dir.join("config.toml");
    let data_dir = unsubscribe_persistence::data_dir();

    if as_json {
        let mut doc = json_out::document("config", "");
        doc.insert(
            "paths".to_string(),
            json!({
                "config_file": config_file.display().to_string(),
                "data_dir": data_dir.display().to_string(),
                "cache_db": SqliteCacheStore::default_path().display().to_string(),
            }),
        );
        output::emit_json(&Value::Object(doc))?;
        return Ok(Exit::Success);
    }

    println!("config_file  {}", config_file.display());
    println!("data_dir     {}", data_dir.display());
    Ok(Exit::Success)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a dotted key, listing what exists when it is not one.
fn parse_key(name: &str) -> Result<SettingKey> {
    SettingKey::parse(name).ok_or_else(|| {
        let known: Vec<&str> = SettingKey::ALL.into_iter().map(SettingKey::key).collect();
        ExitError::usage(format!(
            "Unknown setting `{name}`.\n\nKnown settings:\n  {}",
            known.join("\n  ")
        ))
        .into()
    })
}

/// Fold the values given into the single string the schema validates.
///
/// A list accepts both spellings -- several arguments or one comma-separated
/// string -- because both are natural and neither is worth refusing.
fn join_values(key: SettingKey, values: &[String]) -> Result<String> {
    match values {
        [single] => Ok(single.clone()),
        many if key.is_list() => Ok(many.join(",")),
        many => Err(ExitError::usage(format!(
            "`{}` takes one value, but {} were given.",
            key.key(),
            many.len()
        ))
        .into()),
    }
}

/// Say what a key falls back to, for the message after an unset.
fn display_default(key: SettingKey) -> String {
    let default = key.default_value();
    if default.is_empty() {
        "unset".to_string()
    } else {
        default
    }
}

/// Changing who the account is leaves the stored credentials pointing at
/// someone else, and only `reauth` can fix that.
fn warn_if_credentials_affected(key: SettingKey) {
    if key.affects_credentials() {
        note!(
            "{YELLOW}This changes how the account is identified. \
             Run `unsubscribe reauth` to re-authenticate.{RESET}"
        );
    }
}

/// The settings screen's side effects, against the real config directory.
///
/// Public to the crate so the app shell can open the same screen with the same
/// side effects rather than a second, subtly different wiring.
pub(crate) struct ConfigIo {
    config_dir: PathBuf,
    /// The account as last persisted. Folder listing authenticates as this
    /// account, not as whatever the user is part-way through typing.
    account: RefCell<AccountConfig>,
}

impl ConfigIo {
    pub(crate) fn new(config_dir: &Path, account: &AccountConfig) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            account: RefCell::new(account.clone()),
        }
    }

    fn store(&self) -> TomlConfigStore {
        TomlConfigStore::new(&self.config_dir)
    }

    fn reload(&self) -> Result<(AccountConfig, Preferences)> {
        let store = self.store();
        let account = store.read_config("")?.context("Failed to re-read config")?;
        let preferences = store.read_preferences()?;
        Ok((account, preferences))
    }
}

impl SettingsIo for ConfigIo {
    fn save(&self, account: &AccountConfig, preferences: &Preferences) -> Result<()> {
        let store = self.store();
        store.write_config(account)?;
        // Only written when something changed, so an unchanged save leaves an
        // annotated config byte-identical.
        if store.read_preferences().ok().as_ref() != Some(preferences) {
            store.write_preferences(preferences)?;
        }
        *self.account.borrow_mut() = account.clone();
        Ok(())
    }

    fn list_folders(&self) -> Result<Vec<String>> {
        let account = self.account.borrow().clone();

        // Gmail scans all mail rather than named folders, so there is nothing
        // to pick from; an empty list sends the picker to free-text entry.
        if account.provider_type == ProviderType::Gmail {
            return Ok(Vec::new());
        }

        let credential = make_credential_store(&self.config_dir)
            .get_credential(&account.account_id)?
            .context("No credentials found. Run `unsubscribe reauth` to authenticate.")?;
        let password = match credential {
            Credential::Password(p) => p,
            Credential::OAuthToken { .. } => {
                bail!("IMAP provider requires a password, but an OAuth token was found.")
            }
        };
        let host = account
            .host
            .as_deref()
            .context("IMAP account is missing a host.")?;

        unsubscribe_email::ImapProvider::new(
            host.to_string(),
            account.port.unwrap_or(993),
            account.username.clone(),
            password,
        )
        .list_folders()
    }

    fn reauthenticate(&self) -> Result<(AccountConfig, Preferences)> {
        cmd_reauth(&self.config_dir)?;
        let reloaded = self.reload()?;
        *self.account.borrow_mut() = reloaded.0.clone();
        Ok(reloaded)
    }

    fn credential_location(&self) -> String {
        format!("OS keychain ({KEYRING_SERVICE}) — never shown or edited here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The kind of annotated file a user ends up with, which a save on their
    /// behalf must not quietly rewrite.
    const ANNOTATED: &str = r#"# Password is stored in your OS keychain (email-unsubscribe)
# To use a command instead, add:
#   password_command = "pass show email/imap"

[account]
host = "imap.example.com"
port = 993
username = "user@example.com"
password_command = "pass show email/imap"
auth_type = "password"
provider = "imap"

[scan]
# Folders swept for List-Unsubscribe headers.
folders = ["INBOX", "Promotions"]
archive_folder = "Unsubscribed"

[preferences]
min_emails = 5
stale_after_months = 6
cache_max_age_days = 21
grace_period_days = 14
"#;

    struct Fixture {
        _dir: TempDir,
        path: PathBuf,
        io_ops: ConfigIo,
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, ANNOTATED).unwrap();

        let account = TomlConfigStore::new(dir.path())
            .read_config("")
            .unwrap()
            .unwrap();
        let io_ops = ConfigIo {
            config_dir: dir.path().to_path_buf(),
            account: RefCell::new(account),
        };
        Fixture { _dir: dir, path, io_ops }
    }

    impl Fixture {
        fn text(&self) -> String {
            std::fs::read_to_string(&self.path).unwrap()
        }

        fn current(&self) -> (AccountConfig, Preferences) {
            self.io_ops.reload().unwrap()
        }
    }

    #[test]
    fn saving_without_changing_anything_leaves_the_file_byte_identical() {
        let fixture = fixture();
        let (account, preferences) = fixture.current();
        fixture.io_ops.save(&account, &preferences).unwrap();
        assert_eq!(fixture.text(), ANNOTATED);
    }

    #[test]
    fn saving_a_changed_account_setting_touches_only_that_line() {
        let fixture = fixture();
        let (mut account, preferences) = fixture.current();
        account.archive_folder = "Archive".to_string();
        fixture.io_ops.save(&account, &preferences).unwrap();

        let expected = ANNOTATED.replace(
            r#"archive_folder = "Unsubscribed""#,
            r#"archive_folder = "Archive""#,
        );
        assert_eq!(fixture.text(), expected);
    }

    #[test]
    fn saving_a_changed_preference_touches_only_that_line() {
        let fixture = fixture();
        let (account, mut preferences) = fixture.current();
        preferences.stale_after_months = 3;
        fixture.io_ops.save(&account, &preferences).unwrap();

        let expected = ANNOTATED.replace("stale_after_months = 6", "stale_after_months = 3");
        assert_eq!(fixture.text(), expected);
    }

    #[test]
    fn a_saved_password_command_is_never_lost() {
        let fixture = fixture();
        let (mut account, preferences) = fixture.current();
        account.username = "renamed@example.com".to_string();
        fixture.io_ops.save(&account, &preferences).unwrap();

        assert!(
            fixture.text().contains(r#"password_command = "pass show email/imap""#),
            "the credential command was dropped:\n{}",
            fixture.text(),
        );
    }

    #[test]
    fn a_save_updates_the_account_the_folder_listing_authenticates_as() {
        // Folder listing must not use a username the user only half-typed,
        // but after a save the new one is what is on disk.
        let fixture = fixture();
        let (mut account, preferences) = fixture.current();
        account.username = "renamed@example.com".to_string();
        fixture.io_ops.save(&account, &preferences).unwrap();

        assert_eq!(fixture.io_ops.account.borrow().username, "renamed@example.com");
    }

    #[test]
    fn a_gmail_account_has_no_folders_to_list() {
        let fixture = fixture();
        fixture.io_ops.account.borrow_mut().provider_type = ProviderType::Gmail;
        assert_eq!(fixture.io_ops.list_folders().unwrap(), Vec::<String>::new());
    }
}
