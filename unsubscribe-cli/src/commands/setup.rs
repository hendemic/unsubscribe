//! Account setup commands: `init` (interactive first-time setup), `reauth`
//! (re-authenticate an existing account), and `uninstall`.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use unsubscribe_core::{AccountConfig, AuthType, ConfigStore, Credential, CredentialStore, ProviderType};
use unsubscribe_persistence::{FileDataStore, KeyringCredentialStore, TomlConfigStore};

use crate::terminal::{prompt, prompt_password, BOLD, DIM, GREEN, RESET, YELLOW};
use crate::{make_credential_store, oauth};

// ---------------------------------------------------------------------------
// Init command: interactive provider selection and setup
// ---------------------------------------------------------------------------

pub fn cmd_init(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    if config_path.exists() {
        eprintln!(
            "{YELLOW}Config already exists at {}{RESET}",
            config_path.display()
        );
        eprint!("Overwrite? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    eprintln!("{BOLD}Setting up unsubscribe{RESET}\n");
    eprintln!("  Select your email provider:\n");
    eprintln!("    {BOLD}1{RESET}  Gmail");
    eprintln!("    {BOLD}2{RESET}  Other (IMAP)\n");

    let choice = prompt("Provider", "2")?;

    match choice.as_str() {
        "1" => init_gmail(config_dir),
        "2" | _ => init_imap(config_dir),
    }
}

/// Initialize a Gmail account via OAuth.
fn init_gmail(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    eprintln!("\n{BOLD}Gmail setup{RESET}\n");
    eprintln!("  We will open your browser for Google sign-in.");
    eprintln!("  Grant read and modify access so we can scan and archive emails.\n");

    let username = prompt("Gmail address", "")?;
    let archive = prompt("Archive label", "Unsubscribed")?;

    eprintln!();
    let tokens = oauth::authorize(None, None)?;

    let config_store = TomlConfigStore::new(config_dir);
    let credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));

    // Store the refresh token in the OS keychain
    let credential = Credential::OAuthToken {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    };
    credential_store.store_credential(&username, &credential)?;
    eprintln!("  {GREEN}OAuth tokens stored in OS keychain{RESET}");

    config_store.write_init(
        None,
        None,
        &username,
        &ProviderType::Gmail,
        &AuthType::OAuth,
        vec!["INBOX".to_string()],
        &archive,
        None,
        None,
    )?;

    eprintln!(
        "{GREEN}Config written to {}{RESET}",
        config_path.display()
    );
    eprintln!("\nRun {BOLD}unsubscribe scan{RESET} to test your connection.");
    Ok(())
}

/// Initialize an IMAP account with host/port/password.
fn init_imap(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");

    eprintln!("\n{BOLD}IMAP setup{RESET}\n");

    let host = prompt("IMAP host", "imap.zoho.com")?;
    let port = prompt("IMAP port", "993")?;
    let username = prompt("Email address", "")?;
    let password = prompt_password("App password")?;
    if password.is_empty() {
        bail!("App password is required");
    }
    let folders = prompt("Folders to scan (comma-separated)", "INBOX")?;
    let archive = prompt("Archive folder", "Unsubscribed")?;

    // Derive SMTP defaults from IMAP host
    let smtp_default = host.replace("imap.", "smtp.");
    let smtp_host_input = prompt("SMTP host (for mailto unsubscribe)", &smtp_default)?;
    let smtp_port_input = prompt("SMTP port", "465")?;

    let port: u16 = port.parse().context("Invalid port number")?;
    let smtp_port: u16 = smtp_port_input.parse().context("Invalid SMTP port number")?;

    let folders_vec: Vec<String> = folders
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let config_store = TomlConfigStore::new(config_dir);
    let credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));

    // Store password in OS keychain
    credential_store.store_credential(&username, &Credential::Password(password))?;
    eprintln!("\n  {GREEN}Password stored in OS keychain{RESET}");

    // Write config file (without password)
    config_store.write_init(
        Some(&host),
        Some(port),
        &username,
        &ProviderType::Imap,
        &AuthType::Password,
        folders_vec,
        &archive,
        Some(&smtp_host_input),
        Some(smtp_port),
    )?;

    eprintln!(
        "{GREEN}Config written to {}{RESET}",
        config_path.display()
    );
    eprintln!("\nRun {BOLD}unsubscribe scan{RESET} to test your connection.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Reauth command: provider-aware re-authentication
// ---------------------------------------------------------------------------

pub fn cmd_reauth(config_dir: &Path) -> Result<()> {
    let config_path = config_dir.join("config.toml");
    if !config_path.exists() {
        bail!("No config file found. Run `unsubscribe init` first.");
    }

    let config_store = TomlConfigStore::new(config_dir);
    let account = config_store
        .read_config("")?
        .context("Failed to read config")?;

    match account.provider_type {
        ProviderType::Gmail => reauth_gmail(config_dir, &account),
        ProviderType::Imap => reauth_imap(config_dir, &account),
    }
}

/// Re-authenticate a Gmail account by re-running the OAuth flow.
fn reauth_gmail(config_dir: &Path, account: &AccountConfig) -> Result<()> {
    eprintln!("{BOLD}Re-authenticate Gmail account{RESET}");
    eprintln!(
        "{DIM}Current account: {}{RESET}\n",
        account.username
    );
    eprintln!("Opening browser for Google sign-in...\n");

    let tokens = oauth::authorize(None, None)?;

    let credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));

    let credential = Credential::OAuthToken {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    };
    credential_store.store_credential(&account.username, &credential)?;

    eprintln!("\n{GREEN}Gmail authentication updated.{RESET}");
    Ok(())
}

/// Re-authenticate an IMAP account by prompting for new credentials.
fn reauth_imap(config_dir: &Path, account: &AccountConfig) -> Result<()> {
    // Load existing password for "keep current" default
    let credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));
    let existing_password = credential_store
        .get_credential(&account.account_id)?
        .and_then(|c| match c {
            Credential::Password(p) => Some(p),
            _ => None,
        })
        .unwrap_or_default();

    eprintln!("{BOLD}Update IMAP credentials{RESET}");
    eprintln!("{DIM}Press Enter to keep current value{RESET}\n");

    let host_default = account.host.as_deref().unwrap_or("imap.zoho.com");
    let host = prompt("IMAP host", host_default)?;
    let port_default = account.port.unwrap_or(993).to_string();
    let port = prompt("IMAP port", &port_default)?;
    let username = prompt("Email address", &account.username)?;
    let password = prompt_password("App password (enter new or press Enter to keep current)")?;

    let port: u16 = port.parse().context("Invalid port number")?;

    // Preserve current scan config
    let folders = account.scan_folders.clone();
    let archive = account.archive_folder.clone();

    // If password was entered, use it; otherwise keep existing
    let password = if password.is_empty() {
        existing_password
    } else {
        password
    };

    let config_store = TomlConfigStore::new(config_dir);
    let new_credential_store = KeyringCredentialStore::new(TomlConfigStore::new(config_dir));

    // Delete old keychain entry if username changed
    if username != account.username {
        let _ = new_credential_store.delete_credential(&account.username);
    }

    new_credential_store.store_credential(&username, &Credential::Password(password))?;
    config_store.write_init(
        Some(&host),
        Some(port),
        &username,
        &ProviderType::Imap,
        &AuthType::Password,
        folders,
        &archive,
        account.smtp_host.as_deref(),
        account.smtp_port,
    )?;

    eprintln!("\n{GREEN}Credentials updated.{RESET}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

pub fn cmd_uninstall(config_dir: &Path) -> Result<()> {
    let data_store = FileDataStore::new();
    eprintln!("{BOLD}This will remove:{RESET}");
    eprintln!("  - Config:  {}", config_dir.display());
    eprintln!("  - Data:    {}", data_store.data_dir().display());
    eprintln!("  - Keychain entry");
    eprintln!(
        "  - Binary:  {}",
        std::env::current_exe().unwrap_or_default().display()
    );

    eprint!("\n{BOLD}Are you sure?{RESET} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        eprintln!("Aborted.");
        return Ok(());
    }

    // Remove keychain entry (best-effort, config may not exist)
    let config_store = TomlConfigStore::new(config_dir);
    if let Ok(Some(account)) = config_store.read_config("") {
        let credential_store = make_credential_store(config_dir);
        let _ = credential_store.delete_credential(&account.username);
        eprintln!("  {GREEN}Removed keychain entry{RESET}");
    }

    // Remove config directory
    if config_dir.exists() {
        std::fs::remove_dir_all(config_dir)?;
        eprintln!("  {GREEN}Removed {}{RESET}", config_dir.display());
    }

    // Remove data directory
    let data = data_store.data_dir().to_path_buf();
    if data.exists() {
        std::fs::remove_dir_all(&data)?;
        eprintln!("  {GREEN}Removed {}{RESET}", data.display());
    }

    // Remove binary (must be last since we're running it)
    if let Ok(exe) = std::env::current_exe() {
        if exe.exists() {
            std::fs::remove_file(&exe)?;
            eprintln!("  {GREEN}Removed {}{RESET}", exe.display());
        }
    }

    eprintln!("\n{GREEN}Uninstalled.{RESET}");
    Ok(())
}
