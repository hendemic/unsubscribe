mod action_log;
mod commands;
mod exit;
mod http;
mod json;
mod oauth;
mod output;
mod progress;
mod terminal;
mod time;
mod tui;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::{Path, PathBuf};
use unsubscribe_core::{
    decide_run_mode, AccountConfig, ConfigStore, Credential, CredentialStore, EmailProvider,
    HistoryStore, Preferences, ProviderType, RunMode, SelectionPolicy,
};
use unsubscribe_persistence::{
    FileDataStore, KeyringCredentialStore, SqliteCacheStore, SqliteHistoryStore, TomlConfigStore,
};

use crate::commands::run::RunRequest;
use crate::exit::{exit_code, Exit, ExitError, EXIT_CODE_HELP};
use crate::terminal::{decide_colors, Tty, RED, RESET};

#[derive(Parser)]
#[command(
    name = "unsubscribe",
    about = "Bulk unsubscribe from email lists",
    version,
    after_help = EXIT_CODE_HELP,
)]
pub(crate) struct Cli {
    /// Path to config file (default: ~/.config/email-unsubscribe/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Write the command's result to stdout as a single JSON document
    #[arg(long, global = true)]
    json: bool,

    /// Suppress progress and status messages (errors are still reported)
    #[arg(long, global = true)]
    quiet: bool,

    /// Disable ANSI colours (also honours the NO_COLOR environment variable)
    #[arg(long, global = true)]
    no_color: bool,

    /// With no subcommand, the full-screen app opens (same as `tui`).
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Open the full-screen app (the default with no subcommand)
    Tui,
    /// Scan mailbox, select senders, unsubscribe, and archive
    ///
    /// With no selection flag and a terminal, this opens the selection screen.
    /// Any selection flag makes the run non-interactive: no screen, no
    /// prompts, and an exit code a script can branch on.
    Run {
        /// Don't actually unsubscribe or archive — just show what would happen
        #[arg(long)]
        dry_run: bool,
        /// Only include senders with at least this many emails
        /// [default: the `min_emails` preference, or 3]
        #[arg(short, long)]
        min_emails: Option<u32>,
        /// Use cached scan results without asking
        #[arg(long)]
        cached: bool,
        /// Rescan the mailbox without asking, ignoring any cached scan
        #[arg(long, conflicts_with = "cached")]
        rescan: bool,
        /// Select senders that ignored a previous unsubscribe
        #[arg(long)]
        resumed: bool,
        /// Select every non-stale sender not previously unsubscribed from
        #[arg(long)]
        all_active: bool,
        /// Select stale senders, which are archived without an attempt
        #[arg(long)]
        stale: bool,
        /// Select one sender by address (repeatable)
        #[arg(long = "sender", value_name = "EMAIL")]
        senders: Vec<String>,
        /// Select senders listed in a file, one address per line (`#` comments)
        #[arg(long, value_name = "PATH")]
        senders_file: Option<PathBuf>,
        /// Answer every confirmation with yes
        #[arg(short = 'y', long)]
        yes: bool,
        /// Refuse to act on more than this many senders in one non-interactive
        /// run. 0 lifts the cap
        #[arg(long, value_name = "N", default_value_t = 50)]
        max_senders: u32,
    },
    /// Only scan and list senders with unsubscribe links
    Scan {
        /// Only include senders with at least this many emails
        /// [default: the `min_emails` preference, or 3]
        #[arg(short, long)]
        min_emails: Option<u32>,
    },
    /// Export scan results to CSV
    Export {
        /// Output CSV file path
        #[arg(short, long, default_value = "unsubscribe_senders.csv")]
        output: PathBuf,
        /// Only include senders with at least this many emails
        /// [default: the `min_emails` preference, or 3]
        #[arg(long)]
        min_emails: Option<u32>,
        /// Use cached scan results without asking
        #[arg(long)]
        cached: bool,
        /// Rescan the mailbox without asking, ignoring any cached scan
        #[arg(long, conflicts_with = "cached")]
        rescan: bool,
    },
    /// List available IMAP folders (useful for configuring scan_folders)
    ///
    /// Gmail accounts do not use folder-based scanning; this command is a no-op for them.
    ListFolders,
    /// Show what has been asked of each sender, and what it did
    ///
    /// Reads the recorded history and the last scan; never contacts the
    /// mailbox.
    History {
        /// Only senders whose address or list id contains this text
        #[arg(long, value_name = "EMAIL")]
        sender: Option<String>,
        /// Only senders that ignored a previous unsubscribe
        #[arg(long)]
        resumed: bool,
        /// Only senders with activity on or after this date (YYYY-MM-DD)
        #[arg(long, value_name = "DATE")]
        since: Option<String>,
        /// Show every attempt and resumption, not just a summary row
        #[arg(long)]
        timeline: bool,
    },
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
    /// Read and change settings
    ///
    /// With no subcommand and a terminal, this opens the settings screen;
    /// without one it behaves as `config list`.
    Config {
        #[command(subcommand)]
        action: Option<commands::config::ConfigAction>,
    },
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

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // Output policy is settled before anything can print.
    let tty = Tty::detect();
    terminal::set_colors_enabled(decide_colors(
        cli.no_color,
        std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty()),
        tty.stderr,
    ));
    output::set_quiet(cli.quiet);

    let result = dispatch(cli, tty);
    if let Err(e) = &result {
        eprintln!("{RED}Error:{RESET} {e:#}");
    }
    std::process::ExitCode::from(exit_code(&result))
}

fn dispatch(cli: Cli, tty: Tty) -> Result<Exit> {
    let config_dir = cli
        .config
        .as_deref()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(TomlConfigStore::default_dir);
    let config_path = config_dir.join("config.toml");

    // The app is the default front-end, so it is routed before anything else
    // -- including the config-file check, which it answers with the `init`
    // wizard rather than an error.
    let command = match cli.command {
        None if !tui::app::is_interactive() => {
            Cli::command().print_help()?;
            eprintln!();
            return Err(ExitError::usage(
                "unsubscribe needs a terminal to open its app. Pick a subcommand above.",
            )
            .into());
        }
        None | Some(Commands::Tui) => return tui::app::launch(&config_dir).map(succeeded),
        Some(command) => command,
    };

    match &command {
        Commands::Warnings => {
            return commands::misc::cmd_warnings(&account_id_hint(&config_dir), cli.json)
        }
        Commands::Update { pre } => return commands::update::cmd_update(*pre).map(succeeded),
        Commands::Init => return commands::setup::cmd_init(&config_dir).map(succeeded),
        // Routed before the config-file check below so it can give its own
        // pointer to `init` rather than the generic one.
        Commands::Config { action } => {
            return commands::config::cmd_config(&config_dir, action.clone(), cli.json, tty)
        }
        Commands::Reauth => return commands::setup::cmd_reauth(&config_dir).map(succeeded),
        Commands::Uninstall => return commands::setup::cmd_uninstall(&config_dir).map(succeeded),
        Commands::Completions { shell } => return commands::misc::cmd_completions(*shell),
        _ => {}
    }

    if !config_path.exists() {
        return Err(ExitError::usage(format!(
            "No config file found at {}. Run `unsubscribe init` to set up your config.",
            config_path.display()
        ))
        .into());
    }

    let config_store = TomlConfigStore::new(&config_dir);
    let preferences = config_store.read_preferences()?;
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
            note!("Warning: unsubscribe history unavailable: {e}");
            None
        }
    };
    let history = history_store
        .as_ref()
        .map(|store| store as &dyn HistoryStore);

    // `history` reads records and the last scan and contacts nothing, so it
    // runs before credentials are resolved: a report should not need a keyring
    // to be unlocked.
    if let Commands::History {
        sender,
        resumed,
        since,
        timeline,
    } = &command
    {
        let account = config_store.read_config("")?.with_context(|| {
            format!("Failed to read config: {}", config_path.display())
        })?;
        return commands::history::cmd_history(
            &account,
            &cache_store,
            history,
            &preferences,
            &commands::history::HistoryRequest {
                sender: sender.clone(),
                resumed: *resumed,
                since: since.clone(),
                timeline: *timeline,
                json: cli.json,
            },
        );
    }

    // Built before credentials are resolved: a `run` with nothing to select by
    // and no terminal to ask at should say so, rather than failing first on a
    // keyring nobody is there to unlock.
    let run_request = match &command {
        Commands::Run {
            dry_run,
            cached,
            rescan,
            resumed,
            all_active,
            stale,
            senders,
            senders_file,
            yes,
            max_senders,
            ..
        } => {
            let request = RunRequest {
                dry_run: *dry_run,
                cached: *cached,
                rescan: *rescan,
                yes: *yes,
                json: cli.json,
                policy: selection_policy(
                    *resumed,
                    *all_active,
                    *stale,
                    senders.clone(),
                    senders_file.as_deref(),
                    *max_senders,
                )?,
                tty,
            };
            if decide_run_mode(&request.policy, tty.stdin) == RunMode::SelectionRequired {
                return Err(ExitError::usage(commands::run::SELECTION_REQUIRED).into());
            }
            Some(request)
        }
        _ => None,
    };

    // Everything below talks to the mailbox, so credentials are resolved here.
    // A failure at this point is always an authentication problem.
    let (account, credential) = load_account(&config_dir)
        .map_err(|e| ExitError::new(Exit::Auth, format!("{e:#}")))?;

    match command {
        Commands::Run { min_emails, .. } => commands::run::cmd_run(
            &account,
            &credential,
            &store,
            &cache_store,
            history,
            &with_min_emails(preferences, min_emails),
            &run_request.expect("the run request is built for the run command"),
        ),
        Commands::Scan { min_emails } => commands::scan::cmd_scan(
            &account,
            &credential,
            &store,
            &cache_store,
            history,
            &with_min_emails(preferences, min_emails),
            cli.json,
            tty,
        ),
        Commands::Export {
            output,
            min_emails,
            cached,
            rescan,
        } => commands::scan::cmd_export(
            &account,
            &credential,
            &store,
            &cache_store,
            &with_min_emails(preferences, min_emails),
            &output,
            cached,
            rescan,
            tty,
        ),
        Commands::ListFolders => commands::misc::cmd_list_folders(&account, &credential, cli.json),
        Commands::History { .. }
        | Commands::Tui
        | Commands::Warnings
        | Commands::Update { .. }
        | Commands::Init
        | Commands::Config { .. }
        | Commands::Reauth
        | Commands::Uninstall
        | Commands::Completions { .. } => unreachable!(),
    }
}

/// A command that reports nothing but "it worked".
const fn succeeded(_: ()) -> Exit {
    Exit::Success
}

/// Assemble the selection policy from the flags that describe it.
///
/// The file and the repeated flag are one list: a caller keeping a long list on
/// disk should still be able to add one address on the command line. Reading
/// the file is the only I/O here; the rule for turning the result into a
/// selection lives in core.
fn selection_policy(
    resumed: bool,
    all_active: bool,
    stale: bool,
    mut senders: Vec<String>,
    senders_file: Option<&Path>,
    max_senders: u32,
) -> Result<SelectionPolicy> {
    if let Some(path) = senders_file {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            ExitError::usage(format!(
                "Failed to read senders file {}: {e}",
                path.display()
            ))
        })?;
        senders.extend(unsubscribe_core::parse_senders_file(&contents));
    }
    Ok(SelectionPolicy {
        resumed,
        all_active,
        stale,
        senders,
        max_senders,
    })
}

/// The account id, for commands that report before the config is loaded.
///
/// Best effort: `warnings` works without a config, and an empty account is a
/// truthful answer when there is nothing configured yet.
fn account_id_hint(config_dir: &Path) -> String {
    TomlConfigStore::new(config_dir)
        .read_config("")
        .ok()
        .flatten()
        .map(|account| account.account_id)
        .unwrap_or_default()
}

/// Apply a `--min-emails` flag on top of the configured preferences.
///
/// The flag wins when given; otherwise the `[preferences]` value (or its
/// default) stands.
fn with_min_emails(preferences: Preferences, flag: Option<u32>) -> Preferences {
    match flag {
        Some(min_emails) => Preferences {
            min_emails,
            ..preferences
        },
        None => preferences,
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
pub(crate) fn load_account(config_dir: &Path) -> Result<(AccountConfig, Credential)> {
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
/// Gmail users get `GmailSender` (sends via Gmail API). IMAP users get `SmtpSender`,
/// using the configured (or derived) SMTP host. Mailto unsubscribe is attempted
/// automatically alongside HTTP; callers should treat a failure here as
/// non-fatal and skip mailto-only senders rather than aborting the run.
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    /// Parse an argv, or panic with clap's own message.
    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("argv should parse")
    }

    /// The subcommand an argv names. Panics for the no-subcommand form, which
    /// opens the app rather than naming a command.
    fn command(args: &[&str]) -> Commands {
        parse(args).command.expect("argv should name a subcommand")
    }

    #[test]
    fn the_command_definition_is_internally_consistent() {
        // clap's own audit: duplicate flags, dangling `conflicts_with`
        // targets, bad defaults. Nothing else exercises the definitions.
        Cli::command().debug_assert();
    }

    #[test]
    fn run_rejects_cached_and_rescan_together() {
        let result = Cli::try_parse_from(["unsubscribe", "run", "--cached", "--rescan"]);
        assert!(result.is_err(), "--cached and --rescan contradict each other");
    }

    #[test]
    fn export_rejects_cached_and_rescan_together() {
        let result = Cli::try_parse_from(["unsubscribe", "export", "--cached", "--rescan"]);
        assert!(result.is_err(), "--cached and --rescan contradict each other");
    }

    #[test]
    fn run_accepts_each_cache_flag_on_its_own() {
        match command(["unsubscribe", "run", "--cached"].as_ref()) {
            Commands::Run { cached, rescan, .. } => {
                assert!(cached);
                assert!(!rescan);
            }
            _ => panic!("expected the `run` subcommand"),
        }
        match command(["unsubscribe", "run", "--rescan"].as_ref()) {
            Commands::Run { cached, rescan, .. } => {
                assert!(!cached);
                assert!(rescan);
            }
            _ => panic!("expected the `run` subcommand"),
        }
    }

    #[test]
    fn export_accepts_each_cache_flag_on_its_own() {
        match command(["unsubscribe", "export", "--cached"].as_ref()) {
            Commands::Export { cached, rescan, .. } => {
                assert!(cached);
                assert!(!rescan);
            }
            _ => panic!("expected the `export` subcommand"),
        }
        match command(["unsubscribe", "export", "--rescan"].as_ref()) {
            Commands::Export { cached, rescan, .. } => {
                assert!(!cached);
                assert!(rescan);
            }
            _ => panic!("expected the `export` subcommand"),
        }
    }

    #[test]
    fn neither_cache_flag_is_the_default() {
        match command(["unsubscribe", "run"].as_ref()) {
            Commands::Run {
                cached,
                rescan,
                dry_run,
                min_emails,
                ..
            } => {
                assert!(!cached);
                assert!(!rescan);
                assert!(!dry_run);
                assert_eq!(min_emails, None);
            }
            _ => panic!("expected the `run` subcommand"),
        }
    }

    #[test]
    fn scan_has_no_cache_flags() {
        // `scan` always rescans, so offering the flags would be a lie.
        assert!(Cli::try_parse_from(["unsubscribe", "scan", "--cached"]).is_err());
        assert!(Cli::try_parse_from(["unsubscribe", "scan", "--rescan"]).is_err());
    }
}

/// Tests for the `--min-emails` flag's precedence over `[preferences]`.
#[cfg(test)]
mod with_min_emails_tests {
    use super::*;

    /// Deliberately not `Preferences::default()`: distinct values make it
    /// visible if the override copies the wrong field.
    fn configured() -> Preferences {
        Preferences {
            min_emails: 5,
            stale_after_months: 6,
            cache_max_age_days: 21,
            grace_period_days: 14,
        }
    }

    #[test]
    fn the_flag_overrides_the_configured_minimum() {
        let result = with_min_emails(configured(), Some(25));
        assert_eq!(result.min_emails, 25);
    }

    #[test]
    fn the_configured_minimum_stands_when_the_flag_is_absent() {
        let result = with_min_emails(configured(), None);
        assert_eq!(result.min_emails, 5);
    }

    #[test]
    fn a_zero_flag_overrides_rather_than_being_treated_as_unset() {
        // `--min-emails 0` asks for every sender; it is not the same as
        // omitting the flag.
        let result = with_min_emails(configured(), Some(0));
        assert_eq!(result.min_emails, 0);
    }

    #[test]
    fn the_flag_leaves_the_other_preferences_alone() {
        let result = with_min_emails(configured(), Some(25));
        assert_eq!(result.stale_after_months, 6);
        assert_eq!(result.cache_max_age_days, 21);
    }

    #[test]
    fn the_flag_applies_on_top_of_the_defaults_when_nothing_is_configured() {
        let result = with_min_emails(Preferences::default(), Some(1));
        assert_eq!(result.min_emails, 1);
        assert_eq!(result.stale_after_months, 12);
        assert_eq!(result.cache_max_age_days, 7);
    }
}

/// The flags and subcommands a headless caller depends on.
#[cfg(test)]
mod headless_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("argv should parse")
    }

    // -----------------------------------------------------------------------
    // Global flags
    // -----------------------------------------------------------------------

    #[test]
    fn the_script_facing_flags_are_accepted_before_the_subcommand() {
        let cli = parse(&["unsubscribe", "--json", "--quiet", "--no-color", "history"]);
        assert!(cli.json && cli.quiet && cli.no_color);
    }

    #[test]
    fn the_script_facing_flags_are_accepted_after_the_subcommand_too() {
        // They are global, so neither position should be a surprise.
        let cli = parse(&["unsubscribe", "history", "--json", "--quiet", "--no-color"]);
        assert!(cli.json && cli.quiet && cli.no_color);
    }

    #[test]
    fn none_of_the_script_facing_flags_is_on_by_default() {
        let cli = parse(&["unsubscribe", "scan"]);
        assert!(!cli.json && !cli.quiet && !cli.no_color);
    }

    #[test]
    fn the_exit_code_table_is_printed_in_the_help() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("Exit codes:"), "{help}");
        assert!(help.contains("5  another run holds the lock"), "{help}");
    }

    // -----------------------------------------------------------------------
    // The default front-end
    // -----------------------------------------------------------------------

    #[test]
    fn no_subcommand_names_no_command_at_all() {
        // The app is the default; `dispatch` decides whether there is a
        // terminal to open it on.
        assert!(parse(&["unsubscribe"]).command.is_none());
    }

    #[test]
    fn the_app_can_also_be_asked_for_by_name() {
        assert!(matches!(
            parse(&["unsubscribe", "tui"]).command,
            Some(Commands::Tui)
        ));
    }

    // -----------------------------------------------------------------------
    // run
    // -----------------------------------------------------------------------

    #[test]
    fn every_selection_flag_is_accepted_together() {
        // They union rather than exclude, so clap must not reject the pair.
        let cli = parse(&[
            "unsubscribe",
            "run",
            "--resumed",
            "--all-active",
            "--stale",
            "--sender",
            "one@example.com",
            "--sender",
            "two@example.com",
            "--yes",
        ]);
        match cli.command {
            Some(Commands::Run {
                resumed,
                all_active,
                stale,
                senders,
                yes,
                ..
            }) => {
                assert!(resumed && all_active && stale && yes);
                assert_eq!(senders, ["one@example.com", "two@example.com"]);
            }
            other => panic!("expected `run`, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn the_sender_cap_defaults_to_fifty() {
        // A default that refuses a runaway selection; 0 lifts it.
        match parse(&["unsubscribe", "run"]).command {
            Some(Commands::Run { max_senders, .. }) => assert_eq!(max_senders, 50),
            _ => panic!("expected `run`"),
        }
        match parse(&["unsubscribe", "run", "--max-senders", "0"]).command {
            Some(Commands::Run { max_senders, .. }) => assert_eq!(max_senders, 0),
            _ => panic!("expected `run`"),
        }
    }

    #[test]
    fn no_selection_flag_is_on_by_default() {
        match parse(&["unsubscribe", "run"]).command {
            Some(Commands::Run {
                resumed,
                all_active,
                stale,
                senders,
                senders_file,
                yes,
                ..
            }) => {
                assert!(!resumed && !all_active && !stale && !yes);
                assert!(senders.is_empty());
                assert_eq!(senders_file, None);
            }
            _ => panic!("expected `run`"),
        }
    }

    #[test]
    fn the_short_form_of_yes_is_accepted() {
        match parse(&["unsubscribe", "run", "-y", "--resumed"]).command {
            Some(Commands::Run { yes, .. }) => assert!(yes),
            _ => panic!("expected `run`"),
        }
    }

    // -----------------------------------------------------------------------
    // history
    // -----------------------------------------------------------------------

    #[test]
    fn history_accepts_each_of_its_filters() {
        match parse(&[
            "unsubscribe",
            "history",
            "--sender",
            "acme",
            "--resumed",
            "--since",
            "2026-03-18",
            "--timeline",
        ])
        .command
        {
            Some(Commands::History {
                sender,
                resumed,
                since,
                timeline,
            }) => {
                assert_eq!(sender.as_deref(), Some("acme"));
                assert!(resumed && timeline);
                assert_eq!(since.as_deref(), Some("2026-03-18"));
            }
            _ => panic!("expected `history`"),
        }
    }

    #[test]
    fn history_with_no_filters_asks_for_everything() {
        match parse(&["unsubscribe", "history"]).command {
            Some(Commands::History {
                sender,
                resumed,
                since,
                timeline,
            }) => {
                assert_eq!(sender, None);
                assert_eq!(since, None);
                assert!(!resumed && !timeline);
            }
            _ => panic!("expected `history`"),
        }
    }

    // -----------------------------------------------------------------------
    // config
    // -----------------------------------------------------------------------

    #[test]
    fn config_accepts_each_of_its_subcommands() {
        use commands::config::ConfigAction;
        let cases: [(&[&str], fn(&ConfigAction) -> bool); 5] = [
            (&["unsubscribe", "config", "list"], |a| {
                matches!(a, ConfigAction::List)
            }),
            (&["unsubscribe", "config", "path"], |a| {
                matches!(a, ConfigAction::Path)
            }),
            (&["unsubscribe", "config", "get", "scan.folders"], |a| {
                matches!(a, ConfigAction::Get { key } if key == "scan.folders")
            }),
            (
                &["unsubscribe", "config", "set", "scan.folders", "INBOX"],
                |a| matches!(a, ConfigAction::Set { key, value } if key == "scan.folders" && *value == ["INBOX"]),
            ),
            (&["unsubscribe", "config", "unset", "account.host"], |a| {
                matches!(a, ConfigAction::Unset { key } if key == "account.host")
            }),
        ];
        for (argv, check) in cases {
            match parse(argv).command {
                Some(Commands::Config { action: Some(action) }) => {
                    assert!(check(&action), "{argv:?} parsed as {action:?}");
                }
                _ => panic!("expected `config` with a subcommand for {argv:?}"),
            }
        }
    }

    #[test]
    fn bare_config_names_no_action() {
        match parse(&["unsubscribe", "config"]).command {
            Some(Commands::Config { action }) => assert!(action.is_none()),
            _ => panic!("expected `config`"),
        }
    }

    #[test]
    fn config_set_takes_several_values_for_a_list() {
        use commands::config::ConfigAction;
        match parse(&["unsubscribe", "config", "set", "scan.folders", "INBOX", "Sent"]).command {
            Some(Commands::Config {
                action: Some(ConfigAction::Set { value, .. }),
            }) => assert_eq!(value, ["INBOX", "Sent"]),
            _ => panic!("expected `config set`"),
        }
    }

    #[test]
    fn config_set_without_a_value_is_rejected() {
        assert!(Cli::try_parse_from(["unsubscribe", "config", "set", "scan.folders"]).is_err());
    }

    #[test]
    fn config_get_without_a_key_is_rejected() {
        assert!(Cli::try_parse_from(["unsubscribe", "config", "get"]).is_err());
    }

    // -----------------------------------------------------------------------
    // selection_policy
    // -----------------------------------------------------------------------

    fn senders_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("senders.txt");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn the_flags_and_the_file_become_one_list_of_senders() {
        // A caller keeping a long list on disk should still be able to add one
        // address on the command line.
        let (_dir, path) = senders_file("from-file@example.com\n");
        let policy = selection_policy(
            false,
            false,
            false,
            vec!["from-flag@example.com".to_string()],
            Some(&path),
            50,
        )
        .unwrap();
        assert_eq!(
            policy.senders,
            ["from-flag@example.com", "from-file@example.com"]
        );
    }

    #[test]
    fn a_senders_files_comments_and_blanks_never_reach_the_policy() {
        let (_dir, path) = senders_file("# list\n\none@example.com  # noisy\n\ntwo@example.com\n");
        let policy = selection_policy(false, false, false, Vec::new(), Some(&path), 50).unwrap();
        assert_eq!(policy.senders, ["one@example.com", "two@example.com"]);
    }

    #[test]
    fn a_senders_file_that_is_not_there_is_a_usage_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("nope.txt");
        let error = selection_policy(false, false, false, Vec::new(), Some(&missing), 50)
            .unwrap_err();
        let message = format!("{error:#}");
        assert_eq!(exit_code(&Err(error)), Exit::Usage.code());
        assert!(message.contains("nope.txt"), "{message}");
    }

    #[test]
    fn the_flags_carry_straight_through_to_the_policy() {
        let policy = selection_policy(true, true, true, Vec::new(), None, 7).unwrap();
        assert!(policy.resumed && policy.all_active && policy.stale);
        assert_eq!(policy.max_senders, 7);
    }

    #[test]
    fn a_run_with_no_selection_flag_and_no_terminal_demands_one() {
        let policy = selection_policy(false, false, false, Vec::new(), None, 50).unwrap();
        assert_eq!(decide_run_mode(&policy, false), RunMode::SelectionRequired);
    }

    #[test]
    fn an_empty_senders_file_leaves_the_policy_with_nothing_to_act_on() {
        // A file that lists nobody is not a selection, so the caller is told
        // rather than silently running against everything.
        let (_dir, path) = senders_file("# nobody today\n\n");
        let policy = selection_policy(false, false, false, Vec::new(), Some(&path), 50).unwrap();
        assert!(policy.is_empty());
        assert_eq!(decide_run_mode(&policy, false), RunMode::SelectionRequired);
    }
}
