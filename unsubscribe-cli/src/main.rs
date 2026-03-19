mod http;
mod oauth;
mod progress;
mod tui;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::{Path, PathBuf};
use unsubscribe_core::{
    AccountConfig, AuthType, CacheMeta, CachedScan, ConfigStore, Credential, CredentialStore,
    DataStore, EmailProvider, Folder, ProviderType, ScanWatermark, SenderInfo, UnsubscribeResult,
};
use unsubscribe_persistence::{FileDataStore, KeyringCredentialStore, TomlConfigStore};

// ANSI color helpers
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

#[derive(Parser)]
#[command(name = "unsubscribe", about = "Bulk unsubscribe from email lists", version)]
struct Cli {
    /// Path to config file (default: ~/.config/email-unsubscribe/config.toml)
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan mailbox, select senders, unsubscribe, and archive
    Run {
        /// Don't actually unsubscribe or archive — just show what would happen
        #[arg(long)]
        dry_run: bool,
        /// Only include senders with at least this many emails
        #[arg(short, long, default_value = "3")]
        min_emails: u32,
        /// Use cached scan results instead of rescanning
        #[arg(long)]
        cached: bool,
    },
    /// Only scan and list senders with unsubscribe links
    Scan {
        /// Only include senders with at least this many emails
        #[arg(short, long, default_value = "3")]
        min_emails: u32,
    },
    /// Export scan results to CSV
    Export {
        /// Output CSV file path
        #[arg(short, long, default_value = "unsubscribe_senders.csv")]
        output: PathBuf,
        /// Only include senders with at least this many emails
        #[arg(long, default_value = "3")]
        min_emails: u32,
        /// Use cached scan results instead of rescanning
        #[arg(long)]
        cached: bool,
    },
    /// List available IMAP folders (useful for configuring scan_folders)
    ///
    /// Gmail accounts do not use folder-based scanning; this command is a no-op for them.
    ListFolders,
    /// Show recent scan warnings (unparseable headers)
    Warnings,
    /// Update to the latest release from GitHub
    Update {
        /// Include pre-releases when checking for updates
        #[arg(long)]
        pre: bool,
    },
    /// Create config file with interactive setup
    Init,
    /// Update credentials (re-authenticate with your email provider)
    Reauth,
    /// Remove config, data, keychain entry, and binary
    Uninstall,
    /// Generate shell completion script
    Completions {
        /// Shell to generate completions for (bash, zsh, fish)
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_dir = cli
        .config
        .as_deref()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(TomlConfigStore::default_dir);
    let config_path = config_dir.join("config.toml");

    match &cli.command {
        Commands::Warnings => return cmd_warnings(),
        Commands::Update { pre } => return cmd_update(*pre),
        Commands::Init => return cmd_init(&config_dir),
        Commands::Reauth => return cmd_reauth(&config_dir),
        Commands::Uninstall => return cmd_uninstall(&config_dir),
        Commands::Completions { shell } => return cmd_completions(*shell),
        _ => {}
    }

    if !config_path.exists() {
        bail!(
            "No config file found at {}. Run `unsubscribe init` to set up your config.",
            config_path.display()
        );
    }

    let (account, credential) = load_account(&config_dir)?;
    let store = FileDataStore::new();

    match cli.command {
        Commands::Run {
            dry_run,
            min_emails,
            cached,
        } => cmd_run(&account, &credential, &store, dry_run, min_emails, cached),
        Commands::Scan { min_emails } => cmd_scan(&account, &credential, &store, min_emails),
        Commands::Export {
            output,
            min_emails,
            cached,
        } => cmd_export(&account, &credential, &store, &output, min_emails, cached),
        Commands::ListFolders => cmd_list_folders(&account, &credential),
        Commands::Warnings
        | Commands::Update { .. }
        | Commands::Init
        | Commands::Reauth
        | Commands::Uninstall
        | Commands::Completions { .. } => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Account loading and provider dispatch
// ---------------------------------------------------------------------------

/// Load account config and resolve credentials through the persistence layer.
///
/// For OAuth accounts, this exchanges the stored refresh token for a fresh
/// access token before returning. The token is cached in memory for the
/// lifetime of the session.
fn load_account(config_dir: &Path) -> Result<(AccountConfig, Credential)> {
    let config_store = TomlConfigStore::new(config_dir);

    let account = config_store
        .read_config("")?
        .context(format!(
            "Failed to read config: {}\n\nRun `unsubscribe init` to set up your config.",
            config_dir.join("config.toml").display()
        ))?;

    let credential_store = make_credential_store(config_dir);

    let credential = credential_store
        .get_credential(&account.account_id)?
        .context(
            "No credentials found. Run `unsubscribe init` to set up your account,\n\
             or `unsubscribe reauth` to re-authenticate.",
        )?;

    // For OAuth accounts, the credential store returns the raw refresh token.
    // Exchange it for a fresh access token before handing it to the provider.
    let credential = match credential {
        Credential::OAuthToken {
            refresh_token: Some(refresh_token),
            ..
        } => {
            let http_client = Box::new(http::ReqwestHttpClient::new()?);
            let refresher = oauth::TokenRefresher::new(http_client);
            let access_token = refresher.resolve_access_token(
                &account.account_id,
                &refresh_token,
            )?;
            Credential::OAuthToken {
                access_token,
                refresh_token: None,
            }
        }
        other => other,
    };

    Ok((account, credential))
}

/// Build a credential store for reading/writing raw credentials from the keychain.
fn make_credential_store(config_dir: &Path) -> KeyringCredentialStore {
    KeyringCredentialStore::new(TomlConfigStore::new(config_dir))
}

/// Create the appropriate email provider based on the account's provider type.
fn make_provider(
    account: &AccountConfig,
    credential: &Credential,
) -> Result<Box<dyn EmailProvider>> {
    match account.provider_type {
        ProviderType::Imap => {
            let password = match credential {
                Credential::Password(p) => p.clone(),
                Credential::OAuthToken { .. } => {
                    bail!("IMAP provider requires a password, but an OAuth token was found.\n\
                           Run `unsubscribe init` to reconfigure your account.")
                }
            };
            let host = account.host.as_deref().context(
                "IMAP account is missing a host. Run `unsubscribe init` to reconfigure."
            )?;
            Ok(Box::new(unsubscribe_email::ImapProvider::new(
                host.to_string(),
                account.port.unwrap_or(993),
                account.username.clone(),
                password,
            )))
        }
        ProviderType::Gmail => {
            let access_token = match credential {
                Credential::OAuthToken { access_token, .. } => access_token.clone(),
                Credential::Password(_) => {
                    bail!("Gmail provider requires OAuth authentication, but a password was found.\n\
                           Run `unsubscribe init` to reconfigure your account.")
                }
            };
            let http_client = http::ReqwestHttpClient::new()?;
            Ok(Box::new(unsubscribe_email::GmailProvider::with_archive_label(
                access_token,
                http_client,
                &account.archive_folder,
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

fn do_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    min_emails: u32,
) -> Result<(Vec<SenderInfo>, Vec<String>)> {
    eprintln!("{BOLD}Scanning mailbox...{RESET}\n");
    let provider = make_provider(account, credential)?;
    let folders: Vec<Folder> = account.scan_folders.iter().map(|f| Folder::new(f)).collect();
    let progress = progress::CliScanProgress::new();
    let scan_result = provider.scan(&folders, &progress)?;

    // Persist warnings via DataStore
    store.write_warnings(&scan_result.warnings)?;

    // Build watermark from scan results.
    // MessageId format for IMAP: "folder:uid:uidvalidity"
    // MessageId format for Gmail: opaque string (watermark via adapter_state instead)
    let mut highest_uid = std::collections::HashMap::new();
    let mut uid_validity_map = std::collections::HashMap::new();
    for sender in &scan_result.senders {
        for msg in &sender.messages {
            let folder_key = msg.folder.as_str().to_string();
            // Try to parse IMAP-style message IDs for watermark
            let parts: Vec<&str> = msg.message_id.as_str().rsplitn(3, ':').collect();
            if parts.len() == 3 {
                if let (Ok(validity), Ok(uid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                {
                    let current = highest_uid.entry(folder_key.clone()).or_insert(0u32);
                    if uid > *current {
                        *current = uid;
                    }
                    uid_validity_map.insert(folder_key, validity);
                }
            }
        }
    }

    // Cache results for --cached use
    let cache = CachedScan {
        meta: CacheMeta {
            scanned_at: now_iso8601(),
            format_version: 1,
            account: account.account_id.clone(),
        },
        senders: scan_result.senders.clone(),
        watermark: ScanWatermark {
            highest_uid,
            uid_validity: uid_validity_map,
            adapter_state: None,
        },
    };
    store.write_scan_cache(&cache)?;

    let senders: Vec<_> = scan_result
        .senders
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    Ok((senders, scan_result.warnings))
}

/// Load cached scan results, applying min_emails filter.
fn load_cached_scan(
    store: &dyn DataStore,
    account: &str,
    min_emails: u32,
) -> Result<(Vec<SenderInfo>, String)> {
    let cache = store
        .read_scan_cache(account)?
        .ok_or_else(|| {
            anyhow::anyhow!("No cached scan results found. Run `unsubscribe scan` first.")
        })?;

    let senders: Vec<_> = cache
        .senders
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    Ok((senders, cache.meta.scanned_at))
}

fn print_warnings_summary(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n{YELLOW}{} email(s) had unparseable or missing List-Unsubscribe headers.{RESET}",
        warnings.len()
    );
    eprintln!("{DIM}Run `unsubscribe warnings` to see details.{RESET}\n");
}

// ---------------------------------------------------------------------------
// Init command: interactive provider selection and setup
// ---------------------------------------------------------------------------

fn cmd_init(config_dir: &Path) -> Result<()> {
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

    let port: u16 = port.parse().context("Invalid port number")?;

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

fn cmd_reauth(config_dir: &Path) -> Result<()> {
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
    )?;

    eprintln!("\n{GREEN}Credentials updated.{RESET}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn cmd_uninstall(config_dir: &Path) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Completions command
// ---------------------------------------------------------------------------

fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "unsubscribe", &mut std::io::stdout());
    Ok(())
}

// ---------------------------------------------------------------------------
// Warnings command
// ---------------------------------------------------------------------------

fn cmd_warnings() -> Result<()> {
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

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------

fn cmd_update(pre: bool) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    eprintln!("{BOLD}Checking for updates...{RESET}");

    let client = reqwest::blocking::Client::new();

    let release: serde_json::Value = if pre {
        let resp = client
            .get("https://api.github.com/repos/hendemic/unsubscribe/releases")
            .header("User-Agent", "unsubscribe")
            .send()
            .context("Failed to check for updates")?;

        let releases: Vec<serde_json::Value> =
            resp.json().context("Failed to parse releases list")?;

        releases
            .into_iter()
            .next()
            .context("No releases found. Check https://github.com/hendemic/unsubscribe/releases")?
    } else {
        let resp = client
            .get("https://api.github.com/repos/hendemic/unsubscribe/releases/latest")
            .header("User-Agent", "unsubscribe")
            .send()
            .context("Failed to check for updates")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("No releases found. Check https://github.com/hendemic/unsubscribe/releases");
        }

        resp.json().context("Failed to parse release info")?
    };
    let latest_tag = release["tag_name"]
        .as_str()
        .context("No tag_name in release")?;
    let latest_version = latest_tag.trim_start_matches('v');

    let current_semver =
        semver::Version::parse(current).context("Failed to parse current version")?;
    let latest_semver =
        semver::Version::parse(latest_version).context("Failed to parse release version")?;

    if latest_semver <= current_semver {
        eprintln!("{GREEN}Already up to date (v{current}).{RESET}");
        return Ok(());
    }

    eprintln!(
        "Update available: {DIM}v{current}{RESET} → {BOLD}{latest_tag}{RESET}"
    );

    // Determine the right binary for this platform
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        (os, arch) => bail!(
            "Automatic updates are not supported on {os}-{arch}. \
             Download the latest release manually from https://github.com/hendemic/unsubscribe/releases"
        ),
    };

    let asset_name = format!("unsubscribe-{target}");
    let checksum_name = format!("{asset_name}.sha256");
    let assets = release["assets"]
        .as_array()
        .context("No assets in release")?;

    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .with_context(|| format!("No binary for {target} in this release"))?;
    let download_url = asset["browser_download_url"]
        .as_str()
        .context("No download URL for asset")?;

    // Require a checksum file — releases without one are not trusted.
    let checksum_asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&checksum_name))
        .with_context(|| {
            format!(
                "No checksum file ({checksum_name}) found for this release. \
                 Cannot verify download integrity. Aborting update."
            )
        })?;
    let checksum_url = checksum_asset["browser_download_url"]
        .as_str()
        .context("No download URL for checksum asset")?;

    eprintln!("Downloading {CYAN}{asset_name}{RESET}...");
    let bytes = client
        .get(download_url)
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to download update")?
        .bytes()
        .context("Failed to read update binary")?;

    // Fetch and verify SHA256 checksum before touching the filesystem.
    let checksum_raw = client
        .get(checksum_url)
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to download checksum file")?
        .text()
        .context("Failed to read checksum file")?;

    // sha256sum output format: "<hex>  <filename>"
    let expected_hex = checksum_raw
        .split_whitespace()
        .next()
        .context("Checksum file is empty or malformed")?;

    use sha2::{Digest, Sha256};
    let actual_hex = format!("{:x}", Sha256::digest(&bytes));

    if actual_hex != expected_hex {
        bail!(
            "Checksum verification failed.\n  expected: {expected_hex}\n  actual:   {actual_hex}\n\
             The downloaded binary may be corrupted or tampered with. Aborting update."
        );
    }

    eprintln!("{GREEN}Checksum verified.{RESET}");

    // Replace current binary only after integrity is confirmed.
    let current_exe = std::env::current_exe().context("Cannot determine current binary path")?;
    let tmp = current_exe.with_extension("tmp");
    std::fs::write(&tmp, &bytes).context("Failed to write update")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp, &current_exe).context("Failed to replace binary")?;

    eprintln!("{GREEN}Updated to {latest_tag}!{RESET}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan / Run / Export commands
// ---------------------------------------------------------------------------

fn cmd_list_folders(account: &AccountConfig, credential: &Credential) -> Result<()> {
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

fn cmd_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    min_emails: u32,
) -> Result<()> {
    let (senders, warnings) = do_scan(account, credential, store, min_emails)?;

    if senders.is_empty() {
        println!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        print_warnings_summary(&warnings);
        return Ok(());
    }

    println!(
        "\n{BOLD}{CYAN}Found {} senders with unsubscribe links:{RESET}\n",
        senders.len()
    );
    println!(
        "{DIM}{:<45} {:<35} {:>7} {:>8}{RESET}",
        "Name", "Email", "Method", "Emails"
    );
    println!("{DIM}{}{RESET}", "-".repeat(100));

    for s in &senders {
        let name = if s.display_name.is_empty() {
            "-"
        } else {
            &s.display_name
        };
        let stale_marker = if is_stale(s) { " [stale]" } else { "" };
        let (method, method_color) = if s.one_click {
            ("1-click", GREEN)
        } else if !s.unsubscribe_urls.is_empty() {
            ("http", CYAN)
        } else {
            ("mailto", YELLOW)
        };
        println!(
            " {:<44} {DIM}{:<34}{RESET} {method_color}{:>7}{RESET} {:>8}{DIM}{stale_marker}{RESET}",
            truncate(name, 44),
            truncate(&s.email, 34),
            method,
            s.email_count
        );
    }

    let total_emails: u32 = senders.iter().map(|s| s.email_count).sum();
    let stale_count = senders.iter().filter(|s| is_stale(s)).count();
    let stale_note = if stale_count > 0 {
        format!(" ({stale_count} stale)")
    } else {
        String::new()
    };
    println!(
        "\n{BOLD}Total:{RESET} {} senders{stale_note}, {} emails",
        senders.len(),
        total_emails
    );

    print_warnings_summary(&warnings);

    Ok(())
}

fn cmd_run(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    dry_run: bool,
    min_emails: u32,
    cached: bool,
) -> Result<()> {
    if dry_run {
        eprintln!("{BOLD}{YELLOW}=== DRY RUN MODE — no changes will be made ==={RESET}\n");
    }

    // Phase 1: Scan (or load from cache)
    let (senders, warnings) = if cached {
        let (senders, timestamp) = load_cached_scan(store, &account.account_id, min_emails)?;
        eprintln!("{BOLD}Using cached scan from {timestamp}{RESET}\n");
        (senders, Vec::new())
    } else {
        do_scan(account, credential, store, min_emails)?
    };

    if senders.is_empty() {
        println!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        if !cached {
            print_warnings_summary(&warnings);
        }
        return Ok(());
    }

    eprintln!(
        "\n{BOLD}Found {} senders{RESET} with unsubscribe links.\n",
        senders.len()
    );

    // Phase 2: TUI selection
    eprintln!("{BOLD}Opening selection screen...{RESET}\n");
    let selections = match tui::select_senders(senders)? {
        Some(s) => s,
        None => {
            eprintln!("{YELLOW}Cancelled.{RESET}");
            return Ok(());
        }
    };

    // Partition selected senders: active ones get HTTP unsubscribe + archive,
    // stale ones (last message >12 months ago) get archive-only.
    let selected: Vec<&SenderInfo> = selections
        .iter()
        .filter(|(_, selected)| *selected)
        .map(|(sender, _)| sender)
        .collect();

    if selected.is_empty() {
        eprintln!("{YELLOW}No senders selected.{RESET}");
        return Ok(());
    }

    let (to_unsub, to_archive_only): (Vec<&SenderInfo>, Vec<&SenderInfo>) =
        selected.iter().partition(|s| !is_stale(s));

    let total_emails: u32 = selected.iter().map(|s| s.email_count).sum();
    if !to_unsub.is_empty() {
        eprintln!(
            "Will unsubscribe from {BOLD}{}{RESET} active senders ({} emails).",
            to_unsub.len(),
            to_unsub.iter().map(|s| s.email_count).sum::<u32>()
        );
    }
    if !to_archive_only.is_empty() {
        eprintln!(
            "Will archive {BOLD}{}{RESET} stale senders without unsubscribing ({} emails).",
            to_archive_only.len(),
            to_archive_only.iter().map(|s| s.email_count).sum::<u32>()
        );
    }
    eprintln!("Total: {total_emails} emails.\n");

    // Phase 3: Unsubscribe — only active (non-stale) senders get HTTP unsubscribe.
    // Results are written incrementally so a later archive failure does not lose
    // the record of which senders were already unsubscribed.
    let log_path = data_dir().join("unsubscribe_log.csv");
    std::fs::create_dir_all(log_path.parent().expect("path has parent"))?;

    // Remove any previous run's log to start fresh.
    if log_path.exists() {
        std::fs::remove_file(&log_path)
            .with_context(|| format!("Failed to clear previous action log: {}", log_path.display()))?;
    }

    let results: Vec<UnsubscribeResult> = if to_unsub.is_empty() {
        // All selected senders are stale — skip unsubscribe entirely.
        Vec::new()
    } else if dry_run {
        eprintln!("{BOLD}Unsubscribing...{RESET}\n");
        to_unsub
            .iter()
            .map(|s| {
                let url = s
                    .best_unsubscribe_url()
                    .unwrap_or_default()
                    .to_string();
                UnsubscribeResult {
                    email: s.email.clone(),
                    method: "dry-run".to_string(),
                    success: true,
                    detail: "Would unsubscribe".to_string(),
                    url,
                }
            })
            .collect()
    } else {
        eprintln!("{BOLD}Unsubscribing...{RESET}\n");
        let http_client = http::ReqwestHttpClient::new()?;
        let pb = ProgressBar::new(to_unsub.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(" [{bar:40.cyan/dim}] \x1b[36m{pos}\x1b[0m/{len} unsubscribing")
                .expect("valid template")
                .progress_chars("=> "),
        );

        let results: Vec<UnsubscribeResult> = to_unsub
            .iter()
            .map(|sender| {
                let result = unsubscribe_core::unsubscribe(&[sender], &http_client)
                    .into_iter()
                    .next()
                    .expect("one sender produces one result");
                pb.inc(1);
                // Best-effort incremental write — a write failure is warned but
                // does not abort the unsubscribe run.
                if let Err(e) = append_log_entry(&result, &log_path) {
                    eprintln!("{YELLOW}Warning: could not write to action log: {e}{RESET}");
                }
                result
            })
            .collect();

        pb.finish();
        results
    };

    if !results.is_empty() {
        let success_count = results.iter().filter(|r| r.success).count();
        let fail_count = results.iter().filter(|r| !r.success).count();

        eprintln!(
            "\n{BOLD}Results:{RESET} {GREEN}{success_count} succeeded{RESET}, {RED}{fail_count} failed{RESET}\n"
        );

        for r in &results {
            if r.success {
                eprintln!("  {GREEN}[OK]{RESET}   {:<40} {DIM}{}{RESET}", r.email, r.detail);
            } else {
                eprintln!("  {RED}[FAIL]{RESET} {:<40} {DIM}{}{RESET}", r.email, r.detail);
            }
        }

        if !dry_run {
            eprintln!("{DIM}Action log written to {}{RESET}", log_path.display());
        }
    }

    // Phase 4: Archive — includes both unsubscribed senders and archive-only (stale) senders.
    // Failures are reported with the log path so the user knows their unsubscribe results
    // are preserved.
    eprintln!("\n{BOLD}Archiving emails...{RESET}\n");

    // Combine all selected senders for archiving: those unsubscribed and stale-archive-only.
    let all_to_archive: Vec<&SenderInfo> = to_unsub.iter().copied()
        .chain(to_archive_only.iter().copied())
        .collect();

    let archived: u32 = if dry_run {
        let total: u32 = all_to_archive.iter().map(|s| s.email_count).sum();
        eprintln!(
            "Dry run: would archive {total} emails to '{}'",
            account.archive_folder
        );
        total
    } else {
        let provider = make_provider(account, credential)?;
        let messages: Vec<_> = all_to_archive.iter().flat_map(|s| s.messages.clone()).collect();
        let destination = Folder::new(&account.archive_folder);
        match provider.archive(&messages, &destination) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("{RED}Archive failed:{RESET} {e}");
                if !to_unsub.is_empty() {
                    eprintln!(
                        "{YELLOW}Unsubscribe results are preserved in:{RESET} {}",
                        log_path.display()
                    );
                }
                eprintln!("{DIM}You may archive manually or re-run after resolving the issue.{RESET}");
                return Err(e);
            }
        }
    };

    eprintln!(
        "{GREEN}Archived {archived} emails{RESET} to '{}'.",
        account.archive_folder
    );

    if !cached {
        print_warnings_summary(&warnings);
    }

    Ok(())
}

fn cmd_export(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    output: &Path,
    min_emails: u32,
    cached: bool,
) -> Result<()> {
    let senders = if cached {
        let (senders, timestamp) = load_cached_scan(store, &account.account_id, min_emails)?;
        eprintln!("{DIM}Using cached scan from {timestamp}{RESET}");
        senders
    } else {
        let (senders, _) = do_scan(account, credential, store, min_emails)?;
        senders
    };

    let mut wtr =
        csv::Writer::from_path(output).context("Failed to create CSV")?;

    wtr.write_record(["name", "email", "domain", "method", "emails", "url", "stale"])?;

    for s in &senders {
        let method = if s.one_click {
            "one-click"
        } else if !s.unsubscribe_urls.is_empty() {
            "http"
        } else {
            "mailto"
        };
        let url = s
            .best_unsubscribe_url()
            .unwrap_or_default()
            .to_string();
        let stale = is_stale(s).to_string();

        wtr.write_record([
            &s.display_name,
            &s.email,
            &s.domain,
            method,
            &s.email_count.to_string(),
            &url,
            &stale,
        ])?;
    }

    wtr.flush()?;
    println!("{GREEN}Exported {} senders{RESET} to {output:?}", senders.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs as i64 / 86400;
    let time_of_day = secs as i64 % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_civil(days + 719468);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// A sender is considered stale if their most recent message is older than 12 months.
fn is_stale(sender: &SenderInfo) -> bool {
    const STALE_THRESHOLD_SECS: i64 = 365 * 24 * 60 * 60;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match sender.last_seen {
        Some(ts) => now - ts > STALE_THRESHOLD_SECS,
        None => false,
    }
}

fn data_dir() -> PathBuf {
    let dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
            home.push(".local/share");
            home
        });
    dir.join("email-unsubscribe")
}

/// Append a single result row to the action log CSV.
fn append_log_entry(result: &UnsubscribeResult, path: &Path) -> Result<()> {
    let is_new = !path.exists();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open action log: {}", path.display()))?;
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(file);
    if is_new {
        wtr.write_record(["email", "method", "success", "detail", "url"])?;
    }
    wtr.write_record([
        &result.email,
        &result.method,
        &result.success.to_string(),
        &result.detail,
        &result.url,
    ])?;
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_log(results: &[UnsubscribeResult], path: &Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["email", "method", "success", "detail", "url"])?;
    for r in results {
        wtr.write_record([&r.email, &r.method, &r.success.to_string(), &r.detail, &r.url])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Convert day count to civil date (algorithm from Howard Hinnant).
fn days_to_civil(day_count: i64) -> (i64, u32, u32) {
    let era = if day_count >= 0 {
        day_count
    } else {
        day_count - 146096
    } / 146097;
    let doe = (day_count - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

fn prompt(label: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        eprint!("  {BOLD}{label}{RESET}: ");
    } else {
        eprint!("  {BOLD}{label}{RESET} {DIM}[{default}]{RESET}: ");
    }
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() && !default.is_empty() {
        Ok(default.to_string())
    } else if input.is_empty() {
        bail!("{label} is required");
    } else {
        Ok(input.to_string())
    }
}

fn prompt_password(label: &str) -> Result<String> {
    eprint!("  {BOLD}{label}{RESET}: ");
    std::io::stderr().flush()?;

    // Disable echo for password input
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios = unsafe {
            let mut t = std::mem::zeroed::<libc::termios>();
            libc::tcgetattr(fd, &mut t);
            t
        };
        let orig = termios;
        termios.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

        let mut input = String::new();
        let result = std::io::stdin().read_line(&mut input);

        // Restore echo
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
        eprintln!(); // newline after hidden input

        result?;
        Ok(input.trim().to_string())
    }

    #[cfg(not(unix))]
    {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::UnsubscribeResult;

    fn make_result(email: &str, method: &str, success: bool, detail: &str, url: &str) -> UnsubscribeResult {
        UnsubscribeResult {
            email: email.to_string(),
            method: method.to_string(),
            success,
            detail: detail.to_string(),
            url: url.to_string(),
        }
    }

    #[test]
    fn write_log_produces_correct_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        write_log(&[], &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert_eq!(first_line, "email,method,success,detail,url");
    }

    #[test]
    fn write_log_empty_results_only_writes_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        write_log(&[], &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "only the header row should be present");
    }

    #[test]
    fn write_log_round_trips_with_csv_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        let results = vec![
            make_result("user@example.com", "one-click POST", true, "HTTP 200", "https://example.com/unsub"),
            make_result("other@lists.io", "GET", false, "HTTP 404", "https://lists.io/unsub"),
        ];

        write_log(&results, &path).unwrap();

        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let records: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();

        assert_eq!(records.len(), 2);
        assert_eq!(&records[0][0], "user@example.com");
        assert_eq!(&records[0][1], "one-click POST");
        assert_eq!(&records[0][2], "true");
        assert_eq!(&records[0][3], "HTTP 200");
        assert_eq!(&records[0][4], "https://example.com/unsub");
        assert_eq!(&records[1][0], "other@lists.io");
        assert_eq!(&records[1][2], "false");
    }

    #[test]
    fn write_log_escapes_commas_in_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        // A detail string containing a comma must be quoted in the CSV output
        let results = vec![make_result(
            "user@example.com",
            "GET",
            true,
            "redirect, then confirmed",
            "https://example.com/unsub",
        )];

        write_log(&results, &path).unwrap();

        // Round-trip via CSV reader — the field must survive intact
        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let record = rdr.records().next().unwrap().unwrap();
        assert_eq!(&record[3], "redirect, then confirmed");
    }

    #[test]
    fn write_log_escapes_quotes_in_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        let results = vec![make_result(
            "user@example.com",
            "GET",
            false,
            r#"Error: "connection refused""#,
            "https://example.com/unsub",
        )];

        write_log(&results, &path).unwrap();

        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let record = rdr.records().next().unwrap().unwrap();
        assert_eq!(&record[3], r#"Error: "connection refused""#);
    }
}
