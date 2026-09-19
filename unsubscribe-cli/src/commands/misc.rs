//! Small standalone commands: `warnings`, `list-folders`, and `completions`.

use anyhow::{bail, Context, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use serde_json::{json, Value};
use unsubscribe_core::{AccountConfig, Credential, DataStore, ProviderType};
use unsubscribe_persistence::FileDataStore;

use crate::exit::Exit;
use crate::json as json_out;
use crate::note;
use crate::output;
use crate::terminal::{BOLD, GREEN, RESET, YELLOW};
use crate::Cli;

pub fn cmd_warnings(account: &str, as_json: bool) -> Result<Exit> {
    let store = FileDataStore::new();
    let warnings = store.read_warnings()?;

    if as_json {
        let mut doc = json_out::document("warnings", account);
        doc.insert("warnings".to_string(), json!(warnings));
        doc.insert("count".to_string(), json!(warnings.len()));
        output::emit_json(&Value::Object(doc))?;
        return Ok(Exit::Success);
    }

    if warnings.is_empty() {
        note!("{GREEN}No warnings from last scan.{RESET}");
    } else {
        note!("{BOLD}Unparseable List-Unsubscribe headers from last scan:{RESET}\n");
        for line in &warnings {
            println!("  {YELLOW}{line}{RESET}");
        }
    }
    Ok(Exit::Success)
}

pub fn cmd_list_folders(
    account: &AccountConfig,
    credential: &Credential,
    as_json: bool,
) -> Result<Exit> {
    if account.provider_type == ProviderType::Gmail {
        if as_json {
            let mut doc = json_out::document("list-folders", &account.account_id);
            doc.insert("folders".to_string(), json!([]));
            doc.insert(
                "note".to_string(),
                json!("gmail scans all mail; folders are not used"),
            );
            output::emit_json(&Value::Object(doc))?;
            return Ok(Exit::Success);
        }
        note!(
            "{YELLOW}Gmail does not use folder-based scanning.{RESET}\n\
             Gmail scans all mail automatically, ignoring the folders setting."
        );
        return Ok(Exit::Success);
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
    if as_json {
        let mut doc = json_out::document("list-folders", &account.account_id);
        doc.insert("folders".to_string(), json!(folders));
        output::emit_json(&Value::Object(doc))?;
        return Ok(Exit::Success);
    }
    for folder in &folders {
        println!("{folder}");
    }
    Ok(Exit::Success)
}

pub fn cmd_completions(shell: Shell) -> Result<Exit> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "unsubscribe", &mut std::io::stdout());
    Ok(Exit::Success)
}
