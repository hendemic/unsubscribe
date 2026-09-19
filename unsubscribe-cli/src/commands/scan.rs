//! Scan command and the scan pipeline shared with `run` and `export`:
//! scanning the mailbox (or loading a cached scan) and printing results.

use anyhow::{Context, Result};
use std::path::Path;
use unsubscribe_core::{
    AccountConfig, CacheMeta, CachedScan, Credential, DataStore, Folder, Preferences,
    ScanWatermark, SenderInfo,
};

use crate::terminal::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW};
use crate::time::{is_stale, now_iso8601};
use crate::{make_provider, progress};

pub fn do_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    preferences: &Preferences,
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
        .filter(|s| s.email_count >= preferences.min_emails)
        .collect();

    Ok((senders, scan_result.warnings))
}

/// Load cached scan results, applying the `min_emails` preference.
pub fn load_cached_scan(
    store: &dyn DataStore,
    account: &str,
    preferences: &Preferences,
) -> Result<(Vec<SenderInfo>, String)> {
    let cache = store
        .read_scan_cache(account)?
        .ok_or_else(|| {
            anyhow::anyhow!("No cached scan results found. Run `unsubscribe scan` first.")
        })?;

    let senders: Vec<_> = cache
        .senders
        .into_iter()
        .filter(|s| s.email_count >= preferences.min_emails)
        .collect();

    Ok((senders, cache.meta.scanned_at))
}

pub fn print_warnings_summary(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "\n{YELLOW}{} email(s) had unparseable or missing List-Unsubscribe headers.{RESET}",
        warnings.len()
    );
    eprintln!("{DIM}Run `unsubscribe warnings` to see details.{RESET}\n");
}

pub fn cmd_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    preferences: &Preferences,
) -> Result<()> {
    let (senders, warnings) = do_scan(account, credential, store, preferences)?;

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
        let stale_marker = if is_stale(s, preferences.stale_after_months) {
            " [stale]"
        } else {
            ""
        };
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
    let stale_count = senders
        .iter()
        .filter(|s| is_stale(s, preferences.stale_after_months))
        .count();
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

pub fn cmd_export(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    preferences: &Preferences,
    output: &Path,
    cached: bool,
) -> Result<()> {
    let senders = if cached {
        let (senders, timestamp) = load_cached_scan(store, &account.account_id, preferences)?;
        eprintln!("{DIM}Using cached scan from {timestamp}{RESET}");
        senders
    } else {
        let (senders, _) = do_scan(account, credential, store, preferences)?;
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
        let stale = is_stale(s, preferences.stale_after_months).to_string();

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

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}
