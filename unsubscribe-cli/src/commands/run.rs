//! `run` command: scan, select, unsubscribe, and archive in one pass.
//!
//! The decisions all live in `unsubscribe_core::pipeline`; what is left here is
//! the terminal: which phase headers to print, when to open the selection
//! screen, and how to explain a failure.

use anyhow::{Context, Result};
use unsubscribe_core::{
    annotate_senders, execute_run, plan_run, record_resumptions, AccountConfig, Credential,
    DataStore, EmailSender, Folder, HistoryStore, Preferences, RunContext, RunPlan, RunPolicy,
    ScanCacheStore, SenderInfo,
};

use crate::commands::load_history;
use crate::commands::scan::{print_warnings_summary, resolve_scan};
use crate::progress::{CliRunObserver, CliWarningsOnly};
use crate::terminal::{BOLD, DIM, RED, RESET, YELLOW};
use crate::time::now_unix_secs;
use crate::{http, make_email_sender, make_provider, tui};

#[allow(clippy::too_many_arguments)]
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
        eprintln!("{BOLD}{YELLOW}=== DRY RUN MODE \u{2014} no changes will be made ==={RESET}\n");
    }

    let policy = RunPolicy {
        min_emails: preferences.min_emails,
        stale_after_months: preferences.stale_after_months,
        grace_period_days: preferences.grace_period_days,
        dry_run,
    };

    // Phase 1: scan, or reuse a cached scan the user chose to keep.
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

    if from_cache {
        eprintln!("{BOLD}Using cached scan from {}{RESET}\n", resolved.scanned_at);
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

    // Phase 2: annotate against history, then let the user choose. Senders we
    // already unsubscribed from get their own section, so a sender that ignored
    // an unsubscribe is the first thing seen.
    let history_view = load_history(history, &account.account_id);
    let mut resumptions = history_view.resumptions;
    let annotated = annotate_senders(
        &account.account_id,
        senders,
        &history_view.attempts,
        &resumptions,
        &policy,
        now_unix_secs(),
    );
    // Seeing a sender ignore an unsubscribe is evidence in its own right, so it
    // is written before the user gets a chance to cancel out of the screen.
    record_resumptions(&annotated, history, &policy, &CliWarningsOnly);
    // Planning happens after the selection screen, by which point these are
    // part of the record -- and they are what makes the ignored rung spent.
    resumptions.extend(annotated.new_resumptions.iter().cloned());

    eprintln!("{BOLD}Opening selection screen...{RESET}\n");
    let Some(selections) = tui::select_senders(annotated, Some(&resolved.scanned_at), preferences)?
    else {
        eprintln!("{YELLOW}Cancelled.{RESET}");
        return Ok(());
    };

    let selected: Vec<SenderInfo> = selections
        .into_iter()
        .filter(|(_, selected)| *selected)
        .map(|(sender, _)| sender)
        .collect();

    if selected.is_empty() {
        eprintln!("{YELLOW}No senders selected.{RESET}");
        return Ok(());
    }

    // Phase 3: plan. Active senders get an unsubscribe attempt and an archive;
    // stale ones (no message within `stale_after_months`) are archived only.
    let plan = plan_run(
        selected,
        &history_view.attempts,
        &resumptions,
        &policy,
        now_unix_secs(),
    );
    announce_plan(&plan);

    // Phase 4: execute. The action log starts fresh each run: it is a
    // disposable view of this run, not the history.
    let log_path = unsubscribe_persistence::data_dir().join("unsubscribe_log.csv");
    std::fs::create_dir_all(log_path.parent().expect("path has parent"))?;
    if log_path.exists() {
        std::fs::remove_file(&log_path).with_context(|| {
            format!("Failed to clear previous action log: {}", log_path.display())
        })?;
    }

    let provider = make_provider(account, credential)?;
    let http_client = http::ReqwestHttpClient::new()?;
    // Mailto unsubscribe is attempted automatically alongside HTTP. If a sender
    // cannot be constructed (e.g. SMTP not configured for this account),
    // mailto-only senders are skipped inside the unsubscribe flow rather than
    // aborting the whole run.
    let email_sender: Option<Box<dyn EmailSender>> = if dry_run {
        None
    } else {
        match make_email_sender(account, credential) {
            Ok(sender) => Some(sender),
            Err(e) => {
                eprintln!(
                    "{YELLOW}Note: mailto unsubscribe unavailable ({e}). Mailto-only senders will be skipped.{RESET}"
                );
                None
            }
        }
    };

    let archive_folder = Folder::new(&account.archive_folder);
    let observer = CliRunObserver::new(dry_run, &account.archive_folder, log_path);
    let ctx = RunContext {
        account: &account.account_id,
        archive_folder: &archive_folder,
        provider: provider.as_ref(),
        http: &http_client,
        email_sender: email_sender.as_deref(),
        history,
        cache: cache_store,
        observer: &observer,
    };

    if let Err(e) = execute_run(&plan, &ctx, &policy) {
        eprintln!("{RED}Archive failed:{RESET} {e}");
        if !plan.to_unsubscribe.is_empty() {
            eprintln!(
                "{YELLOW}Unsubscribe results are preserved in:{RESET} {}",
                observer.log_path().display()
            );
        }
        eprintln!("{DIM}You may archive manually or re-run after resolving the issue.{RESET}");
        return Err(e);
    }

    report_exhausted(&plan);

    if !from_cache {
        print_warnings_summary(&warnings);
    }

    Ok(())
}

/// Say what the run is about to do, before anything happens.
fn announce_plan(plan: &RunPlan) {
    if !plan.to_unsubscribe.is_empty() {
        eprintln!(
            "Will unsubscribe from {BOLD}{}{RESET} active senders ({} emails).",
            plan.to_unsubscribe.len(),
            plan.unsubscribe_emails()
        );
    }
    if !plan.archive_only.is_empty() {
        eprintln!(
            "Will archive {BOLD}{}{RESET} stale senders without unsubscribing ({} emails).",
            plan.archive_only.len(),
            plan.archive_only_emails()
        );
    }
    if !plan.exhausted.is_empty() {
        eprintln!(
            "Will archive {BOLD}{}{RESET} senders with no unsubscribe method left ({} emails).",
            plan.exhausted.len(),
            plan.exhausted_emails()
        );
    }
    eprintln!("Total: {} emails.\n", plan.total_emails());
}

/// Name the senders that have run out of ways to be asked.
///
/// They are the input to the rungs that do not exist yet -- a server-side
/// filter, and a report to the company or its ESP -- so the run ends by
/// listing them rather than letting them disappear into the archive.
fn report_exhausted(plan: &RunPlan) {
    if plan.exhausted.is_empty() {
        return;
    }
    eprintln!(
        "\n{YELLOW}{} sender(s) have no unsubscribe method left:{RESET}",
        plan.exhausted.len()
    );
    for sender in &plan.exhausted {
        eprintln!("  {:<40} {DIM}archived only{RESET}", sender.email);
    }
    eprintln!("{DIM}Every method these senders offer has been tried and ignored.{RESET}");
}
