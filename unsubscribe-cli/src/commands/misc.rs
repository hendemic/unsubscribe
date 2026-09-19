//! Small standalone commands: `warnings`, `list-folders`, and `completions`.

use anyhow::{bail, Context, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use unsubscribe_core::{AccountConfig, Credential, DataStore, ProviderType};
use unsubscribe_persistence::FileDataStore;

use crate::terminal::{BOLD, GREEN, RESET, YELLOW};
use crate::Cli;

pub fn cmd_warnings() -> Result<()> {
    let store = FileDataStore::new();
    let warnings = store.read_warnings()?;
    if warnings.is_empty() {
        println!("{GREEN}No warnings from last scan.{RESET}");
    } else {
        println!("{BOLD}Unparseable List-Unsubscribe headers from last scan:{RESET}\n");
        for line in &warnings {
            println!("  {YELLOW}{line}{RESET}");
        }
    }
    Ok(())
}

pub fn cmd_list_folders(account: &AccountConfig, credential: &Credential) -> Result<()> {
    if account.provider_type == ProviderType::Gmail {
        eprintln!(
            "{YELLOW}Gmail does not use folder-based scanning.{RESET}\n\
             Gmail scans all mail automatically, ignoring the folders setting."
        );
        return Ok(());
    }

    let password = match credential {
        Credential::Password(p) => p.clone(),
        Credential::OAuthToken { .. } => {
            bail!("IMAP provider requires a password, but an OAuth token was found.")
        }
    };
    let host = account
        .host
        .as_deref()
        .context("IMAP account is missing a host. Run `unsubscribe init` to reconfigure.")?;

    let provider = unsubscribe_email::ImapProvider::new(
        host.to_string(),
        account.port.unwrap_or(993),
        account.username.clone(),
        password,
    );

    let folders = provider.list_folders()?;
    for folder in &folders {
        println!("{folder}");
    }
    Ok(())
}

pub fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "unsubscribe", &mut std::io::stdout());
    Ok(())
}
