//! `run` command: scan, select, unsubscribe, and archive in one pass.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use unsubscribe_core::{
    AccountConfig, Credential, DataStore, Folder, HistoryStore, Preferences, ScanCacheStore,
    SenderInfo, UnsubscribeAttempt, UnsubscribeMethod, UnsubscribeResult,
};

use crate::action_log::append_log_entry;
use crate::commands::load_history;
use crate::commands::scan::{print_warnings_summary, resolve_scan};
use crate::terminal::{BOLD, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{is_stale, now_unix_secs};
use crate::{http, make_email_sender, make_provider, tui};

pub fn cmd_run(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    preferences: &Preferences,
    dry_run: bool,
    cached: bool,
    rescan: bool,
) -> Result<()> {
    if dry_run {
        eprintln!("{BOLD}{YELLOW}=== DRY RUN MODE — no changes will be made ==={RESET}\n");
    }

    // Phase 1: Scan, or reuse a cached scan the user chose to keep
    let resolved = resolve_scan(
        account,
        credential,
        store,
        cache_store,
        cached,
        rescan,
        preferences,
    )?;
    let from_cache = resolved.from_cache;
    let warnings = resolved.warnings;
    let senders = resolved.senders;
    // The TUI header shows when the senders on screen were found, cached or not.
    let scan_timestamp = Some(resolved.scanned_at);

    if from_cache {
        eprintln!(
            "{BOLD}Using cached scan from {}{RESET}\n",
            scan_timestamp.as_deref().unwrap_or_default()
        );
    }

    if senders.is_empty() {
        println!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        if !from_cache {
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
    let selections = match tui::select_senders(senders, &attempts, scan_timestamp.as_deref(), preferences)? {
        Some(s) => s,
        None => {
            eprintln!("{YELLOW}Cancelled.{RESET}");
            return Ok(());
        }
    };

    // Partition selected senders: active ones get HTTP unsubscribe + archive,
    // stale ones (no message within `stale_after_months`) get archive-only.
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
        selected
            .iter()
            .partition(|s| !is_stale(s, preferences.stale_after_months));

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

        // Mailto unsubscribe is attempted automatically alongside HTTP. If a
        // sender can't be constructed (e.g. SMTP not configured for this
        // account), mailto-only senders are skipped in `unsubscribe_core::unsubscribe`
        // rather than aborting the whole run.
        let email_sender: Option<Box<dyn unsubscribe_core::EmailSender>> =
            match make_email_sender(account, credential) {
                Ok(sender) => Some(sender),
                Err(e) => {
                    eprintln!(
                        "{YELLOW}Note: mailto unsubscribe unavailable ({e}). Mailto-only senders will be skipped.{RESET}"
                    );
                    None
                }
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

    if !from_cache {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A sender carrying every piece of identity evidence an attempt records.
    fn evidence_sender() -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: "news@acme.com".to_string(),
            domain: "acme.com".to_string(),
            unsubscribe_urls: vec!["https://acme.com/unsub?t=abc".to_string()],
            unsubscribe_mailto: vec!["mailto:unsub@acme.com".to_string()],
            one_click: true,
            list_id: Some("weekly.acme.com".to_string()),
            list_unsubscribe_raw: Some(
                "<https://acme.com/unsub?t=abc>, <mailto:unsub@acme.com>".to_string(),
            ),
            email_count: 7,
            messages: vec![],
            last_seen: Some(1_700_000_000),
        }
    }

    fn successful_result() -> UnsubscribeResult {
        UnsubscribeResult {
            email: "news@acme.com".to_string(),
            method: UnsubscribeMethod::OneClickPost,
            success: true,
            detail: "HTTP 200".to_string(),
            url: "https://acme.com/unsub?t=abc".to_string(),
            http_status: Some(200),
            final_url: Some("https://acme.com/unsub/done".to_string()),
        }
    }

    /// Check a string against the RFC 4122 textual form: 8-4-4-4-12 lowercase
    /// hex digits, with the version nibble set to 4 for a random UUID.
    fn is_wellformed_uuid_v4(s: &str) -> bool {
        let groups: Vec<&str> = s.split('-').collect();
        if groups.len() != 5 {
            return false;
        }
        if [8, 4, 4, 4, 12] != [
            groups[0].len(),
            groups[1].len(),
            groups[2].len(),
            groups[3].len(),
            groups[4].len(),
        ] {
            return false;
        }
        if !groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        {
            return false;
        }
        // Version 4 lives in the first nibble of the third group; the variant
        // bits put the fourth group's first character in 8..=b.
        groups[2].starts_with('4')
            && matches!(groups[3].chars().next(), Some('8' | '9' | 'a' | 'b'))
    }

    #[test]
    fn attempt_copies_every_evidence_field_from_the_sender_and_the_result() {
        let attempt = attempt_from_result("me@example.com", &evidence_sender(), &successful_result());

        assert_eq!(attempt.account, "me@example.com");
        assert_eq!(attempt.sender_email, "news@acme.com");
        assert_eq!(attempt.sender_domain, "acme.com");
        assert_eq!(attempt.list_id.as_deref(), Some("weekly.acme.com"));
        assert_eq!(attempt.method, "one_click_post");
        assert!(attempt.success);
        assert_eq!(attempt.http_status, Some(200));
        assert_eq!(attempt.url, "https://acme.com/unsub?t=abc");
        assert_eq!(
            attempt.final_url.as_deref(),
            Some("https://acme.com/unsub/done")
        );
        assert_eq!(
            attempt.list_unsubscribe_raw.as_deref(),
            Some("<https://acme.com/unsub?t=abc>, <mailto:unsub@acme.com>")
        );
        assert_eq!(attempt.detail, "HTTP 200");
    }

    #[test]
    fn attempt_records_the_senders_domain_not_the_accounts() {
        // Both are email addresses; swapping them would silently file every
        // attempt under the user's own domain.
        let attempt =
            attempt_from_result("me@gmail.com", &evidence_sender(), &successful_result());
        assert_eq!(attempt.sender_domain, "acme.com");
        assert_eq!(attempt.account, "me@gmail.com");
    }

    #[test]
    fn attempt_stores_the_stable_method_id_not_the_display_label() {
        // MailtoSent is the case where the two differ: id "mailto_sent",
        // label "mailto". Storing the label would break history on a rename.
        let mut result = successful_result();
        result.method = UnsubscribeMethod::MailtoSent;

        let attempt = attempt_from_result("me@example.com", &evidence_sender(), &result);

        assert_eq!(attempt.method, "mailto_sent");
        assert_ne!(
            attempt.method,
            UnsubscribeMethod::MailtoSent.label(),
            "the display label must not be what gets stored"
        );
    }

    #[test]
    fn a_failed_attempt_maps_the_same_fields_as_a_successful_one() {
        let result = UnsubscribeResult {
            email: "news@acme.com".to_string(),
            method: UnsubscribeMethod::Get,
            success: false,
            detail: "HTTP 410".to_string(),
            url: "https://acme.com/unsub?t=abc".to_string(),
            http_status: Some(410),
            final_url: None,
        };

        let attempt = attempt_from_result("me@example.com", &evidence_sender(), &result);

        assert!(!attempt.success);
        assert_eq!(attempt.method, "get");
        assert_eq!(attempt.http_status, Some(410));
        assert_eq!(attempt.detail, "HTTP 410");
        assert_eq!(attempt.final_url, None);
        // The identity evidence is recorded whether or not the attempt worked.
        assert_eq!(attempt.sender_email, "news@acme.com");
        assert_eq!(attempt.sender_domain, "acme.com");
        assert_eq!(attempt.list_id.as_deref(), Some("weekly.acme.com"));
        assert_eq!(
            attempt.list_unsubscribe_raw.as_deref(),
            Some("<https://acme.com/unsub?t=abc>, <mailto:unsub@acme.com>")
        );
        assert_eq!(attempt.url, "https://acme.com/unsub?t=abc");
    }

    #[test]
    fn a_sender_without_identity_headers_records_none_rather_than_empty_strings() {
        let mut sender = evidence_sender();
        sender.list_id = None;
        sender.list_unsubscribe_raw = None;
        let mut result = successful_result();
        result.method = UnsubscribeMethod::MailtoSkipped;
        result.http_status = None;
        result.final_url = None;
        result.url = String::new();

        let attempt = attempt_from_result("me@example.com", &sender, &result);

        assert_eq!(attempt.list_id, None);
        assert_eq!(attempt.list_unsubscribe_raw, None);
        assert_eq!(attempt.http_status, None);
        assert_eq!(attempt.final_url, None);
        assert_eq!(attempt.url, "");
        assert_eq!(attempt.method, "mailto_skipped");
    }

    #[test]
    fn each_attempt_gets_a_distinct_well_formed_uuid() {
        // Histories from two devices merge as a union keyed by id, so a
        // repeated id would silently drop an attempt.
        let sender = evidence_sender();
        let result = successful_result();
        let ids: HashSet<String> = (0..64)
            .map(|_| attempt_from_result("me@example.com", &sender, &result).id)
            .collect();

        assert_eq!(ids.len(), 64, "attempt ids must be unique");
        for id in &ids {
            assert!(
                is_wellformed_uuid_v4(id),
                "id is not an RFC 4122 v4 UUID: {id}"
            );
        }
    }

    #[test]
    fn attempted_at_is_the_current_utc_time_in_seconds() {
        // Derived independently of `now_unix_secs` so a unit mix-up (millis) or
        // a local-time offset would show up as a large difference.
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_secs() as i64;

        let attempt =
            attempt_from_result("me@example.com", &evidence_sender(), &successful_result());

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_secs() as i64;

        assert!(
            (before..=after).contains(&attempt.attempted_at),
            "attempted_at {} is outside [{before}, {after}]",
            attempt.attempted_at
        );
    }
}
