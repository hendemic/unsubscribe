//! `config` command: the settings screen, wired to the real config store,
//! credential store, and provider.

use anyhow::{bail, Context, Result};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use unsubscribe_core::{AccountConfig, ConfigStore, Credential, CredentialStore, Preferences, ProviderType};
use unsubscribe_persistence::{TomlConfigStore, KEYRING_SERVICE};

use crate::commands::setup::cmd_reauth;
use crate::make_credential_store;
use crate::tui::config::{run, SettingsIo};

pub fn cmd_config(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");
    if !config_path.exists() {
        bail!(
            "No config file found at {}. Run `unsubscribe init` to set one up.",
            config_path.display()
        );
    }

    let store = TomlConfigStore::new(config_dir);
    let account = store
        .read_config("")?
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    let preferences = store.read_preferences()?;

    let io_ops = ConfigIo::new(config_dir, &account);

    run(&account, &preferences, &io_ops)
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
