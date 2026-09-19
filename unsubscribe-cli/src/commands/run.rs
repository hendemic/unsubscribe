//! `run` command: scan, select, unsubscribe, and archive in one pass.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use unsubscribe_core::{
    AccountConfig, Credential, DataStore, Folder, HistoryStore, ScanCacheStore, SenderInfo,
    UnsubscribeAttempt, UnsubscribeMethod, UnsubscribeResult,
};

use crate::action_log::append_log_entry;
use crate::commands::load_history;
use crate::commands::scan::{do_scan, load_cached_scan, print_warnings_summary};
use crate::terminal::{BOLD, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{is_stale, now_iso8601, now_unix_secs};
use crate::{http, make_email_sender, make_provider, tui};

pub fn cmd_run(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    dry_run: bool,
    min_emails: u32,
    cached: bool,
    mailto: bool,
) -> Result<()> {
    if dry_run {
        eprintln!("{BOLD}{YELLOW}=== DRY RUN MODE — no changes will be made ==={RESET}\n");
    }

    // Phase 1: Scan (or load from cache)
    let (senders, warnings, scan_timestamp) = if cached {
        let (senders, timestamp) = load_cached_scan(cache_store, &account.account_id, min_emails)?;
        eprintln!("{BOLD}Using cached scan from {timestamp}{RESET}\n");
        (senders, Vec::new(), Some(timestamp))
    } else {
        let (senders, warnings) = do_scan(account, credential, store, cache_store, min_emails)?;
        let timestamp = now_iso8601();
        (senders, warnings, Some(timestamp))
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

    // Phase 2: TUI selection. Senders we already unsubscribed from get their own
    // section, so a sender that ignored an unsubscribe is the first thing seen.
    let attempts = load_history(history, &account.account_id);

    eprintln!("{BOLD}Opening selection screen...{RESET}\n");
    let selections = match tui::select_senders(senders, &attempts, scan_timestamp.as_deref())? {
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
    let log_path = unsubscribe_persistence::data_dir().join("unsubscribe_log.csv");
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
                    method: UnsubscribeMethod::DryRun,
                    success: true,
                    detail: "Would unsubscribe".to_string(),
                    url,
                    http_status: None,
                    final_url: None,
                }
            })
            .collect()
    } else {
        eprintln!("{BOLD}Unsubscribing...{RESET}\n");
        let http_client = http::ReqwestHttpClient::new()?;

        let email_sender: Option<Box<dyn unsubscribe_core::EmailSender>> = if mailto {
            Some(make_email_sender(account, credential)?)
        } else {
            None
        };

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
                let result = unsubscribe_core::unsubscribe(
                    &[sender],
                    &http_client,
                    email_sender.as_deref(),
                )
                .into_iter()
                .next()
                .expect("one sender produces one result");
                pb.inc(1);
                // Best-effort incremental write — a write failure is warned but
                // does not abort the unsubscribe run.
                if let Err(e) = append_log_entry(&result, &log_path) {
                    eprintln!("{YELLOW}Warning: could not write to action log: {e}{RESET}");
                }
                // Attempt records cannot be backfilled -- their timestamp is
                // now -- so each one is written as soon as it is known.
                // The history is evidence, not a prerequisite: an unavailable
                // one costs the record, not the unsubscribe.
                if let Some(history) = history {
                    let attempt = attempt_from_result(&account.account_id, sender, &result);
                    if let Err(e) = history.record_attempt(&attempt) {
                        eprintln!(
                            "{YELLOW}Warning: could not record unsubscribe history: {e}{RESET}"
                        );
                    }
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

    // The archived messages have moved, so the cached rows now point at message
    // ids that are no longer where the cache says they are. Pruning also keeps a
    // sender that was just handled from reappearing on the next cached run.
    // Only a real archive prunes: a dry run changed nothing.
    if !dry_run {
        let archived_senders: Vec<String> = all_to_archive
            .iter()
            .map(|s| s.email.clone())
            .collect();
        if let Err(e) = cache_store.remove_cached_senders(&account.account_id, &archived_senders) {
            eprintln!("{YELLOW}Warning: could not prune the scan cache: {e}{RESET}");
            eprintln!("{DIM}Run `unsubscribe scan` to rebuild it.{RESET}");
        }
    }

    if !cached {
        print_warnings_summary(&warnings);
    }

    Ok(())
}

/// Build the history record for a completed attempt.
///
/// The sender supplies the identity evidence (domain, list id, the raw
/// `List-Unsubscribe` header) and the result supplies what the attempt did.
fn attempt_from_result(
    account: &str,
    sender: &SenderInfo,
    result: &UnsubscribeResult,
) -> UnsubscribeAttempt {
    UnsubscribeAttempt::new(
        account.to_string(),
        sender.email.clone(),
        sender.domain.clone(),
        sender.list_id.clone(),
        now_unix_secs(),
        result.method,
        result.success,
        result.http_status,
        result.url.clone(),
        result.final_url.clone(),
        sender.list_unsubscribe_raw.clone(),
        result.detail.clone(),
    )
}
