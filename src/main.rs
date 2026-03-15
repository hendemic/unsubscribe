mod config;
mod scanner;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "email-unsubscribe", about = "Bulk unsubscribe from email lists")]
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
        #[arg(short, long, default_value = "1")]
        min_emails: u32,
    },
    /// Only scan and list senders with unsubscribe links
    Scan {
        /// Only include senders with at least this many emails
        #[arg(short, long, default_value = "1")]
        min_emails: u32,
    },
    /// Export scan results to CSV
    Export {
        /// Output CSV file path
        #[arg(short, long, default_value = "unsubscribe_senders.csv")]
        output: PathBuf,
        /// Only include senders with at least this many emails
        #[arg(long, default_value = "1")]
        min_emails: u32,
    },
    /// Show recent scan warnings (unparseable headers)
    Warnings,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(config::Config::default_path);

    if let Commands::Warnings = &cli.command {
        return cmd_warnings();
    }

    let config = config::Config::load(&config_path)?;

    match cli.command {
        Commands::Run { dry_run, min_emails } => cmd_run(&config, dry_run, min_emails),
        Commands::Scan { min_emails } => cmd_scan(&config, min_emails),
        Commands::Export { output, min_emails } => cmd_export(&config, &output, min_emails),
        Commands::Warnings => unreachable!(),
    }
}

fn do_scan(config: &config::Config, min_emails: u32) -> Result<(Vec<scanner::SenderInfo>, Vec<String>)> {
    let scan_result = scanner::scan(config)?;

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
        "\n{} sender(s) had unparseable List-Unsubscribe headers.",
        warnings.len()
    );
    eprintln!("Run `email-unsubscribe warnings` to see details.\n");
}

fn cmd_warnings() -> Result<()> {
    let warnings_path = data_dir().join("warnings.log");
    match std::fs::read_to_string(&warnings_path) {
        Ok(contents) if !contents.trim().is_empty() => {
            println!("Unparseable List-Unsubscribe headers from last scan:\n");
            for line in contents.lines() {
                println!("  {line}");
            }
        }
        _ => {
            println!("No warnings from last scan.");
        }
    }
    Ok(())
}

fn cmd_scan(config: &config::Config, min_emails: u32) -> Result<()> {
    let (senders, warnings) = do_scan(config, min_emails)?;

    if senders.is_empty() {
        println!("No senders with unsubscribe links found.");
        print_warnings_summary(&warnings);
        return Ok(());
    }

    println!(
        "\nFound {} senders with unsubscribe links:\n",
        senders.len()
    );
    println!(
        "{:<45} {:<35} {:>7} {:>8}",
        "Name", "Email", "Method", "Emails"
    );
    println!("{}", "-".repeat(100));

    for s in &senders {
        let name = if s.display_name.is_empty() {
            "-"
        } else {
            &s.display_name
        };
        let method = if s.one_click {
            "1-click"
        } else if !s.unsubscribe_urls.is_empty() {
            "http"
        } else {
            "mailto"
        };
        println!(
            "{:<45} {:<35} {:>7} {:>8}",
            truncate(name, 44),
            truncate(&s.email, 34),
            method,
            s.email_count
        );
    }

    let total_emails: u32 = senders.iter().map(|s| s.email_count).sum();
    println!("\nTotal: {} senders, {} emails", senders.len(), total_emails);

    print_warnings_summary(&warnings);

    Ok(())
}

fn cmd_run(config: &config::Config, dry_run: bool, min_emails: u32) -> Result<()> {
    if dry_run {
        eprintln!("=== DRY RUN MODE — no changes will be made ===\n");
    }

    // Phase 1: Scan
    eprintln!("Phase 1: Scanning mailbox for unsubscribe links...\n");
    let (senders, warnings) = do_scan(config, min_emails)?;

    if senders.is_empty() {
        println!("No senders with unsubscribe links found.");
        print_warnings_summary(&warnings);
        return Ok(());
    }

    eprintln!(
        "\nFound {} senders with unsubscribe links.\n",
        senders.len()
    );

    // Phase 2: TUI selection
    eprintln!("Phase 2: Opening selection screen...\n");
    let selections = match tui::select_senders(senders)? {
        Some(s) => s,
        None => {
            eprintln!("Cancelled.");
            return Ok(());
        }
    };

    let to_unsub: Vec<&scanner::SenderInfo> = selections
        .iter()
        .filter(|(_, selected)| *selected)
        .map(|(sender, _)| sender)
        .collect();

    if to_unsub.is_empty() {
        eprintln!("No senders selected for unsubscribe.");
        return Ok(());
    }

    let total_emails: u32 = to_unsub.iter().map(|s| s.email_count).sum();
    eprintln!(
        "Will unsubscribe from {} senders ({} emails).\n",
        to_unsub.len(),
        total_emails
    );

    // Phase 3: Unsubscribe
    eprintln!("Phase 3: Unsubscribing...\n");
    let results = scanner::unsubscribe(&to_unsub, dry_run);

    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.iter().filter(|r| !r.success).count();

    eprintln!("\nUnsubscribe results: {success_count} succeeded, {fail_count} failed\n");

    for r in &results {
        let icon = if r.success { "OK" } else { "FAIL" };
        eprintln!("  [{icon}] {:<35} {:<15} {}", r.email, r.method, r.detail);
        if !r.url.is_empty() {
            eprintln!("        URL: {}", r.url);
        }
    }

    // Phase 4: Archive
    eprintln!("\nPhase 4: Archiving emails...\n");
    let archived = scanner::archive(config, &to_unsub, dry_run)?;
    eprintln!("Archived {archived} emails to '{}'.", config.scan.archive_folder);

    // Write action log to XDG data dir
    let log_path = data_dir().join("unsubscribe_log.csv");
    std::fs::create_dir_all(log_path.parent().unwrap())?;
    write_log(&results, &log_path)?;
    eprintln!("\nAction log written to {}", log_path.display());

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
    println!("Exported {} senders to {output:?}", senders.len());
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

fn write_log(results: &[scanner::UnsubscribeResult], path: &Path) -> Result<()> {
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
