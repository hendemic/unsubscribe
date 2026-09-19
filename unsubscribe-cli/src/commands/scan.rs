//! Scan command and the scan pipeline shared with `run` and `export`:
//! scanning the mailbox (or loading a cached scan) and printing results.

use anyhow::{Context, Result};
use std::path::Path;
use unsubscribe_core::{
    latest_successful_attempts, AccountConfig, CacheMeta, CachedScan, Credential, DataStore, Folder,
    HistoryStore, ScanCacheStore, ScanWatermark, SenderInfo,
};

use crate::commands::load_history;
use crate::terminal::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{is_stale, now_iso8601};
use crate::{make_provider, progress};

pub fn do_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
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
    // The cache is disposable: failing to write it costs a rescan, not a run.
    if let Err(e) = cache_store.write_scan_cache(&cache) {
        eprintln!("{YELLOW}Warning: could not write scan cache: {e}{RESET}");
    }

    let senders: Vec<_> = scan_result
        .senders
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    Ok((senders, scan_result.warnings))
}

/// Load cached scan results, applying min_emails filter.
pub fn load_cached_scan(
    cache_store: &dyn ScanCacheStore,
    account: &str,
    min_emails: u32,
) -> Result<(Vec<SenderInfo>, String)> {
    let cache = cache_store
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
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    min_emails: u32,
) -> Result<()> {
    let (senders, warnings) = do_scan(account, credential, store, cache_store, min_emails)?;
    let previously_unsubscribed =
        latest_successful_attempts(&load_history(history, &account.account_id));

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
        // A sender we already unsubscribed from is mailing again, so say so
        // even when it is also stale.
        let (marker, marker_color) =
            if previously_unsubscribed.contains_key(&s.email.to_lowercase()) {
                (" [unsubscribed]", RED)
            } else if is_stale(s) {
                (" [stale]", DIM)
            } else {
                ("", DIM)
            };
        let (method, method_color) = if s.one_click {
            ("1-click", GREEN)
        } else if !s.unsubscribe_urls.is_empty() {
            ("http", CYAN)
        } else {
            ("mailto", YELLOW)
        };
        println!(
            " {:<44} {DIM}{:<34}{RESET} {method_color}{:>7}{RESET} {:>8}{marker_color}{marker}{RESET}",
            truncate(name, 44),
            truncate(&s.email, 34),
            method,
            s.email_count
        );
    }

    let total_emails: u32 = senders.iter().map(|s| s.email_count).sum();
    let stale_count = senders.iter().filter(|s| is_stale(s)).count();
    let previous_count = senders
        .iter()
        .filter(|s| previously_unsubscribed.contains_key(&s.email.to_lowercase()))
        .count();
    let notes: Vec<String> = [
        (previous_count, "previously unsubscribed"),
        (stale_count, "stale"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect();
    let stale_note = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join(", "))
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
    cache_store: &dyn ScanCacheStore,
    output: &Path,
    min_emails: u32,
    cached: bool,
) -> Result<()> {
    let senders = if cached {
        let (senders, timestamp) = load_cached_scan(cache_store, &account.account_id, min_emails)?;
        eprintln!("{DIM}Using cached scan from {timestamp}{RESET}");
        senders
    } else {
        let (senders, _) = do_scan(account, credential, store, cache_store, min_emails)?;
        senders
    };

    let mut wtr =
        csv::Writer::from_path(output).context("Failed to create CSV")?;

    wtr.write_record([
        "name", "email", "domain", "list_id", "method", "emails", "url", "stale",
    ])?;

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
            s.display_name.as_str(),
            s.email.as_str(),
            s.domain.as_str(),
            s.list_id.as_deref().unwrap_or(""),
            method,
            &s.email_count.to_string(),
            url.as_str(),
            stale.as_str(),
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
