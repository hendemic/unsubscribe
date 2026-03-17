mod config;
mod http;
mod progress;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::{Path, PathBuf};
use unsubscribe_core::{EmailProvider, Folder, SenderInfo, UnsubscribeResult};

// ANSI color helpers
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

#[derive(Parser)]
#[command(name = "unsubscribe", about = "Bulk unsubscribe from email lists")]
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
    },
    /// Show recent scan warnings (unparseable headers)
    Warnings,
    /// Update to the latest release from GitHub
    Update,
    /// Create config file with interactive setup
    Init,
    /// Update IMAP credentials (server, username, password)
    Reauth,
    /// Remove config, data, keychain entry, and binary
    Uninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(config::Config::default_path);

    match &cli.command {
        Commands::Warnings => return cmd_warnings(),
        Commands::Update => return cmd_update(),
        Commands::Init => return cmd_init(&config_path),
        Commands::Reauth => return cmd_reauth(&config_path),
        Commands::Uninstall => return cmd_uninstall(&config_path),
        _ => {}
    }

    if !config_path.exists() {
        eprintln!("{YELLOW}No config file found at {}{RESET}", config_path.display());
        eprintln!("Run {BOLD}unsubscribe init{RESET} to set up your config.\n");
        std::process::exit(1);
    }

    let config = config::Config::load(&config_path)?;

    match cli.command {
        Commands::Run { dry_run, min_emails } => cmd_run(&config, dry_run, min_emails),
        Commands::Scan { min_emails } => cmd_scan(&config, min_emails),
        Commands::Export { output, min_emails } => cmd_export(&config, &output, min_emails),
        Commands::Warnings
        | Commands::Update
        | Commands::Init
        | Commands::Reauth
        | Commands::Uninstall => unreachable!(),
    }
}

fn make_provider(config: &config::Config) -> unsubscribe_email::ImapProvider {
    unsubscribe_email::ImapProvider::new(
        config.imap.host.clone(),
        config.imap.port,
        config.imap.username.clone(),
        config.imap.password.clone(),
    )
}

fn do_scan(config: &config::Config, min_emails: u32) -> Result<(Vec<SenderInfo>, Vec<String>)> {
    eprintln!("{BOLD}Scanning mailbox...{RESET}\n");
    let provider = make_provider(config);
    let folders: Vec<Folder> = config.scan.folders.iter().map(|f| Folder::new(f)).collect();
    let progress = progress::CliScanProgress::new();
    let scan_result = provider.scan(&folders, &progress)?;

    // Save warnings to log
    if !scan_result.warnings.is_empty() {
        let warnings_path = data_dir().join("warnings.log");
        std::fs::create_dir_all(warnings_path.parent().unwrap())?;
        std::fs::write(&warnings_path, scan_result.warnings.join("\n") + "\n")?;
    }

    let senders: Vec<_> = scan_result
        .senders
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    Ok((senders, scan_result.warnings))
}

fn print_warnings_summary(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n{YELLOW}{} sender(s) had unparseable List-Unsubscribe headers.{RESET}",
        warnings.len()
    );
    eprintln!("{DIM}Run `unsubscribe warnings` to see details.{RESET}\n");
}

fn cmd_warnings() -> Result<()> {
    let warnings_path = data_dir().join("warnings.log");
    match std::fs::read_to_string(&warnings_path) {
        Ok(contents) if !contents.trim().is_empty() => {
            println!("{BOLD}Unparseable List-Unsubscribe headers from last scan:{RESET}\n");
            for line in contents.lines() {
                println!("  {YELLOW}{line}{RESET}");
            }
        }
        _ => {
            println!("{GREEN}No warnings from last scan.{RESET}");
        }
    }
    Ok(())
}

fn cmd_update() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    eprintln!("{BOLD}Checking for updates...{RESET}");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("https://api.github.com/repos/hendemic/unsubscribe/releases/latest")
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to check for updates")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("No releases found. Check https://github.com/hendemic/unsubscribe/releases");
    }

    let release: serde_json::Value = resp.json().context("Failed to parse release info")?;
    let latest_tag = release["tag_name"]
        .as_str()
        .context("No tag_name in release")?;
    let latest_version = latest_tag.trim_start_matches('v');

    if latest_version == current {
        eprintln!("{GREEN}Already up to date (v{current}).{RESET}");
        return Ok(());
    }

    eprintln!(
        "Update available: {DIM}v{current}{RESET} → {BOLD}{latest_tag}{RESET}"
    );

    // Determine the right binary for this platform
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        (os, arch) => anyhow::bail!("Unsupported platform: {os}-{arch}"),
    };

    let asset_name = format!("unsubscribe-{target}");
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

    eprintln!("Downloading {CYAN}{asset_name}{RESET}...");
    let bytes = client
        .get(download_url)
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to download update")?
        .bytes()
        .context("Failed to read update binary")?;

    // Replace current binary
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

fn cmd_init(config_path: &Path) -> Result<()> {
    if config_path.exists() {
        eprintln!("{YELLOW}Config already exists at {}{RESET}", config_path.display());
        eprint!("Overwrite? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    eprintln!("{BOLD}Setting up unsubscribe config{RESET}\n");

    let host = prompt("IMAP host", "imap.zoho.com")?;
    let port = prompt("IMAP port", "993")?;
    let username = prompt("Email address", "")?;
    let password = prompt_password("App password")?;
    if password.is_empty() {
        anyhow::bail!("App password is required");
    }
    let folders = prompt("Folders to scan (comma-separated)", "INBOX")?;
    let archive = prompt("Archive folder", "Unsubscribed")?;

    let port: u16 = port.parse().context("Invalid port number")?;

    let folders_vec: Vec<String> = folders
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Store password in OS keychain
    config::Config::store_password(&username, &password)?;
    eprintln!("\n  {GREEN}Password stored in OS keychain{RESET}");

    // Write config file (without password)
    config::Config::write_init(config_path, &host, port, &username, folders_vec, &archive)?;

    eprintln!("{GREEN}Config written to {}{RESET}", config_path.display());
    eprintln!("\nRun {BOLD}unsubscribe scan{RESET} to test your connection.");
    Ok(())
}

fn cmd_reauth(config_path: &Path) -> Result<()> {
    if !config_path.exists() {
        eprintln!("{YELLOW}No config file found.{RESET}");
        eprintln!("Run {BOLD}unsubscribe init{RESET} first.\n");
        std::process::exit(1);
    }

    let config = config::Config::load(config_path)?;

    eprintln!("{BOLD}Update IMAP credentials{RESET}");
    eprintln!("{DIM}Press Enter to keep current value{RESET}\n");

    let host = prompt("IMAP host", &config.imap.host)?;
    let port = prompt("IMAP port", &config.imap.port.to_string())?;
    let username = prompt("Email address", &config.imap.username)?;
    let password = prompt_password("App password (enter new or press Enter to keep current)")?;

    let port: u16 = port.parse().context("Invalid port number")?;

    // Read current scan config to preserve it
    let folders = config.scan.folders.clone();
    let archive = config.scan.archive_folder.clone();

    // If password was entered, update keychain; otherwise keep existing
    let password = if password.is_empty() {
        config.imap.password.clone()
    } else {
        password
    };

    // Delete old keychain entry if username changed
    if username != config.imap.username {
        let _ = config::Config::delete_password(&config.imap.username);
    }

    config::Config::store_password(&username, &password)?;
    config::Config::write_init(config_path, &host, port, &username, folders, &archive)?;

    eprintln!("\n{GREEN}Credentials updated.{RESET}");
    Ok(())
}

fn cmd_uninstall(config_path: &Path) -> Result<()> {
    eprintln!("{BOLD}This will remove:{RESET}");
    eprintln!("  - Config:  {}", config_path.parent().unwrap_or(config_path).display());
    eprintln!("  - Data:    {}", data_dir().display());
    eprintln!("  - Keychain entry");
    eprintln!("  - Binary:  {}", std::env::current_exe().unwrap_or_default().display());

    eprint!("\n{BOLD}Are you sure?{RESET} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        eprintln!("Aborted.");
        return Ok(());
    }

    // Remove keychain entry (best-effort, config may not exist)
    if let Ok(config) = config::Config::load(config_path) {
        let _ = config::Config::delete_password(&config.imap.username);
        eprintln!("  {GREEN}Removed keychain entry{RESET}");
    }

    // Remove config directory
    if let Some(config_dir) = config_path.parent() {
        if config_dir.exists() {
            std::fs::remove_dir_all(config_dir)?;
            eprintln!("  {GREEN}Removed {}{RESET}", config_dir.display());
        }
    }

    // Remove data directory
    let data = data_dir();
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
        anyhow::bail!("{label} is required");
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

fn cmd_scan(config: &config::Config, min_emails: u32) -> Result<()> {
    let (senders, warnings) = do_scan(config, min_emails)?;

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
        let (method, method_color) = if s.one_click {
            ("1-click", GREEN)
        } else if !s.unsubscribe_urls.is_empty() {
            ("http", CYAN)
        } else {
            ("mailto", YELLOW)
        };
        println!(
            " {:<44} {DIM}{:<34}{RESET} {method_color}{:>7}{RESET} {:>8}",
            truncate(name, 44),
            truncate(&s.email, 34),
            method,
            s.email_count
        );
    }

    let total_emails: u32 = senders.iter().map(|s| s.email_count).sum();
    println!(
        "\n{BOLD}Total:{RESET} {} senders, {} emails",
        senders.len(),
        total_emails
    );

    print_warnings_summary(&warnings);

    Ok(())
}

fn cmd_run(config: &config::Config, dry_run: bool, min_emails: u32) -> Result<()> {
    if dry_run {
        eprintln!("{BOLD}{YELLOW}=== DRY RUN MODE — no changes will be made ==={RESET}\n");
    }

    // Phase 1: Scan
    let (senders, warnings) = do_scan(config, min_emails)?;

    if senders.is_empty() {
        println!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        print_warnings_summary(&warnings);
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

    let to_unsub: Vec<&SenderInfo> = selections
        .iter()
        .filter(|(_, selected)| *selected)
        .map(|(sender, _)| sender)
        .collect();

    if to_unsub.is_empty() {
        eprintln!("{YELLOW}No senders selected for unsubscribe.{RESET}");
        return Ok(());
    }

    let total_emails: u32 = to_unsub.iter().map(|s| s.email_count).sum();
    eprintln!(
        "Will unsubscribe from {BOLD}{}{RESET} senders ({} emails).\n",
        to_unsub.len(),
        total_emails
    );

    // Phase 3: Unsubscribe
    eprintln!("{BOLD}Unsubscribing...{RESET}\n");

    let results: Vec<UnsubscribeResult> = if dry_run {
        to_unsub
            .iter()
            .map(|s| {
                let url = s
                    .unsubscribe_urls
                    .first()
                    .or(s.unsubscribe_mailto.first())
                    .cloned()
                    .unwrap_or_default();
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
                let result = unsubscribe_core::unsubscribe(&[sender], &http_client);
                pb.inc(1);
                result.into_iter().next().expect("one sender produces one result")
            })
            .collect();

        pb.finish();
        results
    };

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

    // Phase 4: Archive
    eprintln!("\n{BOLD}Archiving emails...{RESET}\n");

    let archived: u32 = if dry_run {
        let total: u32 = to_unsub.iter().map(|s| s.email_count).sum();
        eprintln!(
            "Dry run: would archive {total} emails to '{}'",
            config.scan.archive_folder
        );
        total
    } else {
        let provider = make_provider(config);
        let messages: Vec<_> = to_unsub.iter().flat_map(|s| s.messages.clone()).collect();
        let destination = Folder::new(&config.scan.archive_folder);
        provider.archive(&messages, &destination)?
    };

    eprintln!(
        "{GREEN}Archived {archived} emails{RESET} to '{}'.",
        config.scan.archive_folder
    );

    // Write action log to XDG data dir
    let log_path = data_dir().join("unsubscribe_log.csv");
    std::fs::create_dir_all(log_path.parent().unwrap())?;
    write_log(&results, &log_path)?;
    eprintln!("{DIM}Action log written to {}{RESET}", log_path.display());

    print_warnings_summary(&warnings);

    Ok(())
}

fn cmd_export(config: &config::Config, output: &Path, min_emails: u32) -> Result<()> {
    let (senders, _) = do_scan(config, min_emails)?;

    let mut wtr =
        csv::Writer::from_path(output).context("Failed to create CSV")?;

    wtr.write_record(["name", "email", "domain", "method", "emails", "url"])?;

    for s in &senders {
        let method = if s.one_click {
            "one-click"
        } else if !s.unsubscribe_urls.is_empty() {
            "http"
        } else {
            "mailto"
        };
        let url = s
            .unsubscribe_urls
            .first()
            .or(s.unsubscribe_mailto.first())
            .cloned()
            .unwrap_or_default();

        wtr.write_record([
            &s.display_name,
            &s.email,
            &s.domain,
            method,
            &s.email_count.to_string(),
            &url,
        ])?;
    }

    wtr.flush()?;
    println!("{GREEN}Exported {} senders{RESET} to {output:?}", senders.len());
    Ok(())
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

fn write_log(results: &[UnsubscribeResult], path: &Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["email", "method", "success", "detail", "url"])?;
    for r in results {
        wtr.write_record([&r.email, &r.method, &r.success.to_string(), &r.detail, &r.url])?;
    }
    wtr.flush()?;
    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}
