//! `run` command: scan, select, unsubscribe, and archive in one pass.
//!
//! The decisions all live in `unsubscribe_core::pipeline` and
//! `unsubscribe_core::selection`; what is left here is the terminal: which
//! phase headers to print, whether to open the selection screen or apply a
//! policy, and how to explain a failure.
//!
//! Two ways in, one pipeline. With a selection flag the run is headless --
//! no screen, no prompts, and an exit code a script can branch on. Without
//! one, and with a terminal to ask at, it behaves exactly as it always has.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use unsubscribe_core::{
    annotate_senders, decide_run_mode, execute_run, plan_run, record_resumptions, select_by_policy,
    AccountConfig, AnnotatedSenders, Credential, DataStore, EmailSender, Folder, HistoryStore,
    Preferences, RunContext, RunMode, RunOutcome, RunPlan, RunPolicy, ScanCacheStore, Selection,
    SelectedSender, SelectionPolicy, SelectionReason, SenderInfo,
};
use unsubscribe_persistence::{LockOutcome, RunLock};

use crate::commands::load_history;
use crate::commands::scan::{print_warnings_summary, resolve_scan};
use crate::exit::{classify_provider_error, Exit, ExitError};
use crate::json as json_out;
use crate::note;
use crate::output;
use crate::progress::{CliRunObserver, CliWarningsOnly};
use crate::terminal::{confirm, Tty, BOLD, DIM, RED, RESET, YELLOW};
use crate::time::now_unix_secs;
use crate::{http, make_email_sender, make_provider, tui};

/// Everything `run` was asked to do, beyond the account and the stores.
///
/// One struct rather than nine positional flags, and the shape a future
/// scheduler would fill in directly.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub dry_run: bool,
    pub cached: bool,
    pub rescan: bool,
    /// Answer every confirmation with yes. Required for an unattended run that
    /// would otherwise have something to ask about.
    pub yes: bool,
    pub json: bool,
    pub policy: SelectionPolicy,
    pub tty: Tty,
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_run(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    preferences: &Preferences,
    request: &RunRequest,
) -> Result<Exit> {
    let mode = decide_run_mode(&request.policy, request.tty.stdin);
    if mode == RunMode::SelectionRequired {
        return Err(ExitError::usage(SELECTION_REQUIRED).into());
    }

    if request.dry_run {
        note!("{BOLD}{YELLOW}=== DRY RUN MODE \u{2014} no changes will be made ==={RESET}\n");
    }

    // A dry run reads and writes nothing the archive cares about, so it is not
    // worth blocking a real run for. Everything else takes the lock before it
    // scans: two runs that both plan from the same cache will both try to move
    // the same messages.
    let _lock = if request.dry_run {
        None
    } else {
        match RunLock::acquire(&account.account_id)? {
            LockOutcome::Acquired(lock) => Some(lock),
            LockOutcome::Held(held) => {
                let who = held
                    .pid
                    .map(|pid| format!(" (process {pid})"))
                    .unwrap_or_default();
                return Err(ExitError::new(
                    Exit::Locked,
                    format!(
                        "Another `unsubscribe run` is already working on {}{who}.\n\
                         Lock file: {}",
                        account.account_id,
                        held.path.display()
                    ),
                )
                .into());
            }
        }
    };

    let policy = RunPolicy {
        min_emails: preferences.min_emails,
        stale_after_months: preferences.stale_after_months,
        grace_period_days: preferences.grace_period_days,
        dry_run: request.dry_run,
    };

    // Phase 1: scan, or reuse a cached scan. A headless run is never asked
    // about the cache; it takes a fresh one and rescans a stale one.
    let prompts_allowed = request.tty.stdin && !request.yes && mode == RunMode::Interactive;
    let resolved = resolve_scan(
        account,
        credential,
        store,
        cache_store,
        request.cached,
        request.rescan,
        preferences,
        prompts_allowed,
        request.tty,
    )
    .map_err(classify_provider_error)?;
    let from_cache = resolved.from_cache;
    let warnings = resolved.warnings;
    let senders = resolved.senders;

    if from_cache {
        note!("{BOLD}Using cached scan from {}{RESET}\n", resolved.scanned_at);
    }

    if senders.is_empty() {
        note!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        if !from_cache {
            print_warnings_summary(&warnings);
        }
        if request.json {
            output::emit_json(&empty_document(account, &resolved.scanned_at, &warnings))?;
        }
        return Ok(Exit::NothingToDo);
    }

    note!(
        "\n{BOLD}Found {} senders{RESET} with unsubscribe links.\n",
        senders.len()
    );

    // Phase 2: annotate against history, then choose. Senders we already
    // unsubscribed from get their own section, so a sender that ignored an
    // unsubscribe is the first thing seen.
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
    // Planning happens after selection, by which point these are part of the
    // record -- and they are what makes the ignored rung spent.
    resumptions.extend(annotated.new_resumptions.iter().cloned());

    let Some(chosen) = choose_senders(annotated, request, &resolved.scanned_at, preferences)?
    else {
        note!("{YELLOW}Cancelled.{RESET}");
        return Ok(Exit::NothingToDo);
    };

    if chosen.is_empty() {
        note!("{YELLOW}No senders selected.{RESET}");
        if request.json {
            output::emit_json(&empty_document(account, &resolved.scanned_at, &warnings))?;
        }
        return Ok(Exit::NothingToDo);
    }

    // Phase 3: plan. Active senders get an unsubscribe attempt and an archive;
    // stale ones (no message within `stale_after_months`) are archived only.
    let reasons: HashMap<String, SelectionReason> = chosen
        .selected
        .iter()
        .map(|s| (s.sender.email.to_lowercase(), s.reason))
        .collect();
    let plan = plan_run(
        chosen.senders(),
        &history_view.attempts,
        &resumptions,
        &policy,
        now_unix_secs(),
    );
    announce_plan(&plan);
    if request.dry_run {
        report_dry_run(&plan, &reasons);
    }

    if !confirm_plan(&plan, request)? {
        note!("{YELLOW}Cancelled.{RESET}");
        return Ok(Exit::NothingToDo);
    }

    // Phase 4: execute. The action log starts fresh each run: it is a
    // disposable view of this run, not the history.
    let log_path = unsubscribe_persistence::data_dir().join("unsubscribe_log.csv");
    std::fs::create_dir_all(log_path.parent().expect("path has parent"))?;
    if log_path.exists() {
        std::fs::remove_file(&log_path).with_context(|| {
            format!("Failed to clear previous action log: {}", log_path.display())
        })?;
    }

    let provider = make_provider(account, credential).map_err(classify_provider_error)?;
    let http_client = http::ReqwestHttpClient::new()?;
    // Mailto unsubscribe is attempted automatically alongside HTTP. If a sender
    // cannot be constructed (e.g. SMTP not configured for this account),
    // mailto-only senders are skipped inside the unsubscribe flow rather than
    // aborting the whole run.
    let email_sender: Option<Box<dyn EmailSender>> = if request.dry_run {
        None
    } else {
        match make_email_sender(account, credential) {
            Ok(sender) => Some(sender),
            Err(e) => {
                note!(
                    "{YELLOW}Note: mailto unsubscribe unavailable ({e}). Mailto-only senders will be skipped.{RESET}"
                );
                None
            }
        }
    };

    let archive_folder = Folder::new(&account.archive_folder);
    let observer = CliRunObserver::new(
        request.dry_run,
        &account.archive_folder,
        log_path,
        request.tty.stderr,
    );
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

    let outcome = match execute_run(&plan, &ctx, &policy) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("{RED}Archive failed:{RESET} {e}");
            if !plan.to_unsubscribe.is_empty() {
                eprintln!(
                    "{YELLOW}Unsubscribe results are preserved in:{RESET} {}",
                    observer.log_path().display()
                );
            }
            eprintln!("{DIM}You may archive manually or re-run after resolving the issue.{RESET}");
            return Err(classify_provider_error(e));
        }
    };

    report_exhausted(&plan);
    report_unknown_senders(&chosen);

    if !from_cache {
        print_warnings_summary(&warnings);
    }

    let exit = if outcome.failed() > 0 {
        Exit::SomeFailed
    } else {
        Exit::Success
    };

    if request.json {
        output::emit_json(&run_document(
            account,
            request,
            &resolved.scanned_at,
            from_cache,
            &plan,
            &outcome,
            &chosen,
            &reasons,
            &warnings,
            exit,
        ))?;
    }

    Ok(exit)
}

/// The message a headless caller gets when it has not said what to act on.
///
/// Public because `main` checks the mode before it unlocks anything, so the
/// user hears about the missing flag rather than about their keyring.
pub const SELECTION_REQUIRED: &str = "\
`run` needs to know which senders to act on when there is no terminal to ask at.

Pass one or more selection flags:
  --resumed             senders that ignored a previous unsubscribe
  --all-active          every non-stale sender not previously unsubscribed
  --stale               stale senders (archived without an attempt)
  --sender <EMAIL>      one named sender, repeatable
  --senders-file <PATH> one address per line

Add --yes to act without a confirmation, e.g. `unsubscribe run --resumed --yes`.";

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Get the senders to act on, from the policy or from the person.
///
/// `None` means the interactive screen was cancelled; an empty selection means
/// nothing matched, which is a different thing and gets a different exit code.
fn choose_senders(
    annotated: AnnotatedSenders,
    request: &RunRequest,
    scanned_at: &str,
    preferences: &Preferences,
) -> Result<Option<Selection>> {
    if request.policy.is_empty() {
        note!("{BOLD}Opening selection screen...{RESET}\n");
        let Some(selections) = tui::select_senders(annotated, Some(scanned_at), preferences)?
        else {
            return Ok(None);
        };
        // The screen is the selection: what it hands back is already the
        // answer, so there is no policy to attribute a reason to.
        let selected = selections
            .into_iter()
            .filter(|(_, selected)| *selected)
            .map(|(sender, _)| SelectedSender {
                sender,
                reason: SelectionReason::Chosen,
            })
            .collect();
        return Ok(Some(Selection {
            selected,
            unknown: Vec::new(),
            over_cap: None,
        }));
    }

    let selection = select_by_policy(&annotated, &request.policy);
    if let Some(cap) = selection.over_cap {
        return Err(ExitError::usage(format!(
            "Refusing to act on {} senders in one non-interactive run (limit {}).\n\
             Raise it with `--max-senders {}`, or narrow the selection.",
            cap.selected, cap.max_senders, cap.selected
        ))
        .into());
    }
    describe_selection(&selection);
    Ok(Some(selection))
}

/// Say what the policy matched, grouped by the flag that matched it.
fn describe_selection(selection: &Selection) {
    if selection.selected.is_empty() {
        return;
    }
    let mut counts: Vec<(SelectionReason, usize)> = Vec::new();
    for chosen in &selection.selected {
        match counts.iter_mut().find(|(r, _)| *r == chosen.reason) {
            Some((_, count)) => *count += 1,
            None => counts.push((chosen.reason, 1)),
        }
    }
    let summary: Vec<String> = counts
        .iter()
        .map(|(reason, count)| format!("{count} {}", reason.label()))
        .collect();
    note!(
        "{BOLD}Selected {} senders{RESET} ({}).\n",
        selection.selected.len(),
        summary.join(", ")
    );
}

/// Name the addresses that were asked for but are not in this scan.
///
/// Not an error: a sender that has stopped mailing has nothing to unsubscribe
/// from, and a list of addresses is meant to outlive any one scan.
fn report_unknown_senders(selection: &Selection) {
    if selection.unknown.is_empty() {
        return;
    }
    note!(
        "\n{YELLOW}{} named sender(s) were not in this scan and were skipped:{RESET}",
        selection.unknown.len()
    );
    for email in &selection.unknown {
        note!("  {email}");
    }
}

/// Confirm before acting, where there is anyone to confirm with.
///
/// `--yes` is the unattended answer. Without it a terminal is asked, and a
/// caller with no terminal is told to pass the flag rather than left hanging
/// on a stdin nobody is typing into.
fn confirm_plan(plan: &RunPlan, request: &RunRequest) -> Result<bool> {
    // The selection screen was the confirmation; so is a dry run, which is
    // about to change nothing.
    if request.policy.is_empty() || request.dry_run || request.yes {
        return Ok(true);
    }
    if !request.tty.stdin {
        return Err(ExitError::usage(format!(
            "Refusing to act on {} senders without a confirmation.\n\
             Pass `--yes` to run unattended, or `--dry-run` to see what would happen.",
            plan.to_unsubscribe.len() + plan.archive_only.len() + plan.exhausted.len()
        ))
        .into());
    }
    confirm("Proceed?")
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Say what the run is about to do, before anything happens.
fn announce_plan(plan: &RunPlan) {
    if !plan.to_unsubscribe.is_empty() {
        note!(
            "Will unsubscribe from {BOLD}{}{RESET} active senders ({} emails).",
            plan.to_unsubscribe.len(),
            plan.unsubscribe_emails()
        );
    }
    if !plan.archive_only.is_empty() {
        note!(
            "Will archive {BOLD}{}{RESET} stale senders without unsubscribing ({} emails).",
            plan.archive_only.len(),
            plan.archive_only_emails()
        );
    }
    if !plan.exhausted.is_empty() {
        note!(
            "Will archive {BOLD}{}{RESET} senders with no unsubscribe method left ({} emails).",
            plan.exhausted.len(),
            plan.exhausted_emails()
        );
    }
    note!("Total: {} emails.\n", plan.total_emails());
}

/// Spell out a dry run sender by sender: why it was picked, and what rung it
/// would climb. Without this a `--dry-run` says how many, never which.
fn report_dry_run(plan: &RunPlan, reasons: &HashMap<String, SelectionReason>) {
    let reason_of = |email: &str| {
        reasons
            .get(&email.to_lowercase())
            .map(|r| r.label())
            .unwrap_or("selected")
    };
    for planned in &plan.to_unsubscribe {
        note!(
            "  {:<40} {DIM}{} \u{2014} {}{RESET}",
            planned.sender.email,
            reason_of(&planned.sender.email),
            planned.step.label()
        );
    }
    for sender in &plan.archive_only {
        note!(
            "  {:<40} {DIM}{} \u{2014} archive only, no attempt{RESET}",
            sender.email,
            reason_of(&sender.email)
        );
    }
    for sender in &plan.exhausted {
        note!(
            "  {:<40} {DIM}{} \u{2014} exhausted, archive only{RESET}",
            sender.email,
            reason_of(&sender.email)
        );
    }
    note!();
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
    note!(
        "\n{YELLOW}{} sender(s) have no unsubscribe method left:{RESET}",
        plan.exhausted.len()
    );
    for sender in &plan.exhausted {
        note!("  {:<40} {DIM}archived only{RESET}", sender.email);
    }
    note!("{DIM}Every method these senders offer has been tried and ignored.{RESET}");
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// The document for a run that found or selected nothing.
fn empty_document(account: &AccountConfig, scanned_at: &str, warnings: &[String]) -> Value {
    let mut doc = json_out::document("run", &account.account_id);
    doc.insert("scanned_at".to_string(), json!(scanned_at));
    doc.insert("senders".to_string(), json!([]));
    doc.insert(
        "totals".to_string(),
        json!({
            "selected": 0,
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "archived_messages": 0,
        }),
    );
    doc.insert("warnings".to_string(), json!(warnings));
    doc.insert("exit_code".to_string(), json!(Exit::NothingToDo.code()));
    Value::Object(doc)
}

/// Everything the run did, per sender and in total.
#[allow(clippy::too_many_arguments)]
fn run_document(
    account: &AccountConfig,
    request: &RunRequest,
    scanned_at: &str,
    from_cache: bool,
    plan: &RunPlan,
    outcome: &RunOutcome,
    selection: &Selection,
    reasons: &HashMap<String, SelectionReason>,
    warnings: &[String],
    exit: Exit,
) -> Value {
    let reason_of = |sender: &SenderInfo| reasons.get(&sender.email.to_lowercase()).copied();

    let attempted = plan
        .to_unsubscribe
        .iter()
        .zip(&outcome.results)
        .map(|(planned, result)| {
            let mut value = json_out::planned(planned, reason_of(&planned.sender));
            json_out::merge(&mut value, json!({ "result": json_out::result(result) }));
            value
        });

    let archived = |senders: &[SenderInfo], action: &'static str| {
        senders
            .iter()
            .map(|sender| {
                let mut value = json_out::identity(sender);
                json_out::merge(
                    &mut value,
                    json!({
                        "email_count": sender.email_count,
                        "messages": sender.messages.len(),
                        "selection_reason": reason_of(sender).map(SelectionReason::as_id),
                        "action": action,
                        "result": Value::Null,
                    }),
                );
                value
            })
            .collect::<Vec<_>>()
    };

    let senders: Vec<Value> = attempted
        .chain(archived(&plan.archive_only, "archive_only"))
        .chain(archived(&plan.exhausted, "exhausted"))
        .collect();

    let mut doc = json_out::document("run", &account.account_id);
    doc.insert("dry_run".to_string(), json!(request.dry_run));
    doc.insert("scanned_at".to_string(), json!(scanned_at));
    doc.insert("from_cache".to_string(), json!(from_cache));
    doc.insert("senders".to_string(), json!(senders));
    doc.insert(
        "totals".to_string(),
        json!({
            "selected": selection.selected.len(),
            "attempted": plan.to_unsubscribe.len(),
            "succeeded": outcome.succeeded(),
            "failed": outcome.failed(),
            "archive_only": plan.archive_only.len(),
            "exhausted": plan.exhausted.len(),
            "archived_messages": outcome.archived,
            "emails": plan.total_emails(),
        }),
    );
    doc.insert("unknown_senders".to_string(), json!(selection.unknown));
    doc.insert("warnings".to_string(), json!(warnings));
    doc.insert("exit_code".to_string(), json!(exit.code()));
    Value::Object(doc)
}
