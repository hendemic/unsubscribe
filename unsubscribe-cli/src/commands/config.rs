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

    let io_ops = ConfigIo {
        config_dir: config_dir.to_path_buf(),
        account: RefCell::new(account.clone()),
    };

    run(&account, &preferences, &io_ops)
}

/// The settings screen's side effects, against the real config directory.
struct ConfigIo {
    config_dir: PathBuf,
    /// The account as last persisted. Folder listing authenticates as this
    /// account, not as whatever the user is part-way through typing.
    account: RefCell<AccountConfig>,
}

impl ConfigIo {
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
