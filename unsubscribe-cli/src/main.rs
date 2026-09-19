mod action_log;
mod commands;
mod http;
mod oauth;
mod progress;
mod terminal;
mod time;
mod tui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::{Path, PathBuf};
use unsubscribe_core::{
    AccountConfig, ConfigStore, Credential, CredentialStore, EmailProvider, HistoryStore,
    ProviderType,
};
use unsubscribe_persistence::{
    FileDataStore, KeyringCredentialStore, SqliteCacheStore, SqliteHistoryStore, TomlConfigStore,
};

#[derive(Parser)]
#[command(name = "unsubscribe", about = "Bulk unsubscribe from email lists", version)]
pub(crate) struct Cli {
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
        /// Send unsubscribe emails for mailto-only senders
        #[arg(long)]
        mailto: bool,
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
        Commands::Warnings => return commands::misc::cmd_warnings(),
        Commands::Update { pre } => return commands::update::cmd_update(*pre),
        Commands::Init => return commands::setup::cmd_init(&config_dir),
        Commands::Reauth => return commands::setup::cmd_reauth(&config_dir),
        Commands::Uninstall => return commands::setup::cmd_uninstall(&config_dir),
        Commands::Completions { shell } => return commands::misc::cmd_completions(*shell),
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
    // A corrupt cache should be reported, not worked around silently -- but it
    // costs the user nothing to fix, so say so.
    let cache_store = SqliteCacheStore::open_default().with_context(|| {
        format!(
            "Failed to open the scan cache at {}.\n\n\
             The cache is disposable: deleting that file is safe and the next scan rebuilds it.",
            SqliteCacheStore::default_path().display()
        )
    })?;

    // The history is enrichment, not a prerequisite: when it cannot be opened
    // the commands fall back to the view they had before it existed.
    let history_store = match SqliteHistoryStore::open_default() {
        Ok(store) => Some(store),
        Err(e) => {
            eprintln!("Warning: unsubscribe history unavailable: {e}");
            None
        }
    };
    let history = history_store
        .as_ref()
        .map(|store| store as &dyn HistoryStore);

    match cli.command {
        Commands::Run {
            dry_run,
            min_emails,
            cached,
            mailto,
        } => commands::run::cmd_run(
            &account,
            &credential,
            &store,
            &cache_store,
            history,
            dry_run,
            min_emails,
            cached,
            mailto,
        ),
        Commands::Scan { min_emails } => {
            commands::scan::cmd_scan(
                &account,
                &credential,
                &store,
                &cache_store,
                history,
                min_emails,
            )
        }
        Commands::Export {
            output,
            min_emails,
            cached,
        } => commands::scan::cmd_export(
            &account,
            &credential,
            &store,
            &cache_store,
            &output,
            min_emails,
            cached,
        ),
        Commands::ListFolders => commands::misc::cmd_list_folders(&account, &credential),
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
pub(crate) fn make_credential_store(config_dir: &Path) -> KeyringCredentialStore {
    KeyringCredentialStore::new(TomlConfigStore::new(config_dir))
}

/// Create the appropriate email provider based on the account's provider type.
pub(crate) fn make_provider(
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

/// Create the appropriate email sender for mailto unsubscribe based on provider type.
///
/// Gmail users get `GmailSender` (sends via Gmail API). IMAP users get `SmtpSender`
/// once SMTP support is added. Until then, IMAP users cannot use `--mailto`.
pub(crate) fn make_email_sender(
    account: &AccountConfig,
    credential: &Credential,
) -> Result<Box<dyn unsubscribe_core::EmailSender>> {
    match account.provider_type {
        ProviderType::Gmail => {
            let access_token = match credential {
                Credential::OAuthToken { access_token, .. } => access_token.clone(),
                Credential::Password(_) => {
                    bail!(
                        "Gmail provider requires OAuth authentication for sending emails.\n\
                         Run `unsubscribe reauth` to re-authenticate."
                    )
                }
            };
            let http_client = http::ReqwestHttpClient::new()?;
            Ok(Box::new(unsubscribe_email::GmailSender::new(
                &account.username,
                access_token,
                http_client,
            )))
        }
        ProviderType::Imap => {
            let password = match credential {
                Credential::Password(p) => p.clone(),
                Credential::OAuthToken { .. } => {
                    bail!(
                        "IMAP provider requires a password for SMTP sending.\n\
                         Run `unsubscribe reauth` to reconfigure your account."
                    )
                }
            };
            let imap_host = account.host.as_deref().unwrap_or("localhost");
            let smtp_host = account
                .smtp_host
                .clone()
                .unwrap_or_else(|| unsubscribe_email::SmtpSender::derive_smtp_host(imap_host));
            let smtp_port = account.smtp_port.unwrap_or(465);

            Ok(Box::new(unsubscribe_email::SmtpSender::new(
                &account.username,
                smtp_host,
                smtp_port,
                &account.username,
                password,
            )))
        }
    }
}
