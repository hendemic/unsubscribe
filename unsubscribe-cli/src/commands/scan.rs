//! Scan command and the scan pipeline shared with `run` and `export`:
//! scanning the mailbox (or loading a cached scan) and printing results.

use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Write};
use std::path::Path;
use unsubscribe_core::{
    decide_scan_action, latest_successful_attempts, AccountConfig, CacheMeta, CachedScan,
    CachedScanSummary, Credential, DataStore, Folder, HistoryStore, ScanAction, ScanCacheStore,
    ScanWatermark, SenderInfo,
};

use crate::commands::load_history;
use crate::terminal::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{
    age_secs_since, format_relative_age, is_stale, now_iso8601, utc_to_local_date,
    SCAN_MAX_AGE_SECS,
};
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

/// The senders a `run` or `export` works from, and where they came from.
pub struct ResolvedScan {
    pub senders: Vec<SenderInfo>,
    /// Scan warnings. Empty when the senders came from the cache, which does
    /// not store them.
    pub warnings: Vec<String>,
    /// When the scan behind these senders was taken (ISO 8601, UTC).
    pub scanned_at: String,
    pub from_cache: bool,
}

/// Decide between the cached scan and a fresh one, then produce the senders.
///
/// The decision itself is [`decide_scan_action`] in core; this only gathers the
/// inputs, asks the question when core says to, and carries out the answer.
pub fn resolve_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    cached: bool,
    rescan: bool,
    min_emails: u32,
) -> Result<ResolvedScan> {
    let usable = usable_cache(cache_store, &account.account_id, min_emails);
    let summary = usable.as_ref().map(|(scanned_at, senders)| CachedScanSummary {
        sender_count: senders.len(),
        age_secs: age_secs_since(scanned_at),
    });

    let action = decide_scan_action(
        summary,
        cached,
        rescan,
        std::io::stdin().is_terminal(),
        SCAN_MAX_AGE_SECS,
    );

    let use_cache = match action {
        ScanAction::UseCache => true,
        ScanAction::Rescan => false,
        ScanAction::CacheUnavailable => {
            bail!("No cached scan results found. Run `unsubscribe scan` first.")
        }
        ScanAction::Ask { default_cached } => {
            let (scanned_at, senders) = usable.as_ref().expect("Ask implies a usable cache");
            prompt_use_cached(scanned_at, senders.len(), default_cached)?
        }
    };

    if use_cache {
        let (scanned_at, senders) = usable.expect("cache was checked before use");
        return Ok(ResolvedScan {
            senders,
            warnings: Vec::new(),
            scanned_at,
            from_cache: true,
        });
    }

    let (senders, warnings) = do_scan(account, credential, store, cache_store, min_emails)?;
    Ok(ResolvedScan {
        senders,
        warnings,
        scanned_at: now_iso8601(),
        from_cache: false,
    })
}

/// The cached scan for an account, if there is one worth offering.
///
/// An unreadable cache is warned about and then treated as absent -- it costs
/// a rescan, not a run. So is an empty one: after enough runs prune their
/// senders the cache holds nothing to choose, and asking would be noise.
fn usable_cache(
    cache_store: &dyn ScanCacheStore,
    account: &str,
    min_emails: u32,
) -> Option<(String, Vec<SenderInfo>)> {
    let cache = match cache_store.read_scan_cache(account) {
        Ok(cache) => cache?,
        Err(e) => {
            eprintln!("{YELLOW}Warning: could not read the scan cache: {e}{RESET}");
            return None;
        }
    };

    let senders: Vec<_> = cache
        .senders
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    (!senders.is_empty()).then_some((cache.meta.scanned_at, senders))
}

/// Ask whether to reuse the cached scan. Returns true for "use cached".
///
/// Anything unrecognised -- including a bare Enter or a closed stdin -- takes
/// the default, which is reuse for a fresh scan and a rescan for a stale one.
fn prompt_use_cached(scanned_at: &str, sender_count: usize, default_cached: bool) -> Result<bool> {
    let when = utc_to_local_date(scanned_at).unwrap_or_else(|| scanned_at.to_string());
    let age = age_secs_since(scanned_at)
        .map(format_relative_age)
        .map(|age| {
            // A stale cache says so in red: it is the reason the default flipped.
            if default_cached {
                format!(" ({DIM}{age}{RESET})")
            } else {
                format!(" ({RED}{age}{RESET})")
            }
        })
        .unwrap_or_default();
    let choices = if default_cached {
        "[U]se cached / [r]escan"
    } else {
        "[u]se cached / [R]escan"
    };

    eprint!(
        "{BOLD}Last scan:{RESET} {when}{age} \u{2014} {sender_count} senders. {choices}: "
    );
    std::io::stderr().flush()?;

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return Ok(default_cached);
    }

    Ok(match answer.trim().chars().next() {
        Some('u') | Some('U') => true,
        Some('r') | Some('R') => false,
        _ => default_cached,
    })
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
    rescan: bool,
) -> Result<()> {
    let resolved = resolve_scan(
        account,
        credential,
        store,
        cache_store,
        cached,
        rescan,
        min_emails,
    )?;
    if resolved.from_cache {
        eprintln!("{DIM}Using cached scan from {}{RESET}", resolved.scanned_at);
    }
    let senders = resolved.senders;

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
