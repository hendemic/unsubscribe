//! Running the core pipeline on the app's behalf.
//!
//! Core is sync and blocking by design -- consumers own their concurrency --
//! so everything that talks to a mailbox or a server goes through here, where
//! the adapters are built and the pipeline stages are called in order. Nothing
//! in this file decides anything: the plan comes from
//! [`unsubscribe_core::plan_run`] and the outcome from
//! [`unsubscribe_core::execute_run`].

use anyhow::{bail, Result};
use unsubscribe_core::{
    execute_run, plan_run, AccountConfig, Credential, EmailSender, Folder, HistoryStore,
    Preferences, Resumption, RunContext, RunObserver, RunOutcome, RunPlan, RunPolicy,
    ScanCacheStore, SenderInfo, UnsubscribeAttempt,
};

use unsubscribe_persistence::{LockOutcome, RunLock};

use crate::{http, make_email_sender, make_provider};

/// The history a selection was annotated against, carried forward to the plan.
///
/// Observe, then judge: the resumptions this scan turned up are already part
/// of the record by the time the selection screen opens, and the plan has to
/// see them or it will re-try the rung that was just shown not to work.
#[derive(Debug, Clone, Default)]
pub struct SelectionContext {
    pub attempts: Vec<UnsubscribeAttempt>,
    pub resumptions: Vec<Resumption>,
}

/// Work out what a run would do to the selected senders.
#[must_use]
pub fn plan(
    selected: Vec<SenderInfo>,
    history: &SelectionContext,
    policy: &RunPolicy,
    now: i64,
) -> RunPlan {
    plan_run(
        selected,
        &history.attempts,
        &history.resumptions,
        policy,
        now,
    )
}

/// Carry out a plan, building the adapters it needs.
///
/// A mailto sender that cannot be built is not fatal: the flow skips
/// mailto-only senders rather than aborting, exactly as the command does.
///
/// Takes the same per-account lock as `unsubscribe run`, so a run started here
/// and one started by a timer never both move the same messages. A dry run
/// moves nothing and takes no lock, again as the command does.
pub fn execute(
    account: &AccountConfig,
    credential: &Credential,
    cache: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    plan: &RunPlan,
    policy: &RunPolicy,
    observer: &dyn RunObserver,
) -> Result<RunOutcome> {
    let _lock = if policy.dry_run {
        None
    } else {
        match RunLock::acquire(&account.account_id)? {
            LockOutcome::Acquired(lock) => Some(lock),
            LockOutcome::Held(held) => {
                let who = held
                    .pid
                    .map(|pid| format!(" (process {pid})"))
                    .unwrap_or_default();
                bail!(
                    "Another run is already working on {}{who}. Try again when it finishes.",
                    account.account_id
                );
            }
        }
    };

    let provider = make_provider(account, credential)?;
    let http_client = http::ReqwestHttpClient::new()?;
    let email_sender: Option<Box<dyn EmailSender>> = if policy.dry_run {
        None
    } else {
        make_email_sender(account, credential).ok()
    };
    let archive_folder = Folder::new(&account.archive_folder);

    let ctx = RunContext {
        account: &account.account_id,
        archive_folder: &archive_folder,
        provider: provider.as_ref(),
        http: &http_client,
        email_sender: email_sender.as_deref(),
        history,
        cache,
        observer,
    };
    execute_run(plan, &ctx, policy)
}

/// The policy a run uses, given the user's preferences and a dry-run choice.
#[must_use]
pub fn policy(preferences: &Preferences, dry_run: bool) -> RunPolicy {
    RunPolicy {
        min_emails: preferences.min_emails,
        stale_after_months: preferences.stale_after_months,
        grace_period_days: preferences.grace_period_days,
        dry_run,
    }
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------
//
// Core is blocking, so the app runs a stage on its own thread and keeps
// drawing. Two channels between the two: a shared snapshot the UI reads every
// frame for the high-frequency progress, and a one-shot result at the end.
// The cancel flag goes the other way, and the ports poll it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use unsubscribe_core::{
    is_cancelled, scan_senders, Folder as CoreFolder, ObtainedSenders, PlannedSender, RunWarning,
    ScanProgress, UnsubscribeResult,
};
use unsubscribe_persistence::{FileDataStore, SqliteCacheStore, SqliteHistoryStore};

use crate::time::now_iso8601;

/// A panic in a worker is a bug, not a user-visible failure mode -- but a dead
/// UI with no explanation is worse than a message, so it is reported as one.
const PANICKED: &str = "The background task stopped unexpectedly.";

// -- scan --------------------------------------------------------------------

/// One folder's progress, as the screen draws it.
#[derive(Debug, Clone, Default)]
pub struct FolderProgress {
    pub name: String,
    pub total: u32,
    pub scanned: u32,
    pub done: bool,
}

/// What the scan screen reads, and the flag it writes.
#[derive(Debug, Default)]
pub struct ScanShared {
    folders: Mutex<Vec<FolderProgress>>,
    /// Distinct senders found so far, as only the adapter can count them.
    totals: Mutex<(u32, u32)>,
    cancel: AtomicBool,
}

impl ScanShared {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Ask the scan to stop at its next batch boundary.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn cancel_requested(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Per-folder progress, in the order the folders started.
    #[must_use]
    pub fn folders(&self) -> Vec<FolderProgress> {
        self.folders.lock().expect("scan progress lock").clone()
    }

    /// Distinct senders and warnings found so far.
    #[must_use]
    pub fn totals(&self) -> (u32, u32) {
        *self.totals.lock().expect("scan totals lock")
    }

    fn with_folder(&self, name: &str, f: impl FnOnce(&mut FolderProgress)) {
        let mut folders = self.folders.lock().expect("scan progress lock");
        match folders.iter_mut().find(|folder| folder.name == name) {
            Some(folder) => f(folder),
            None => {
                let mut folder = FolderProgress {
                    name: name.to_string(),
                    ..FolderProgress::default()
                };
                f(&mut folder);
                folders.push(folder);
            }
        }
    }
}

/// The [`ScanProgress`] port, writing into the shared snapshot.
struct ScanReporter(Arc<ScanShared>);

impl ScanProgress for ScanReporter {
    fn on_folder_start(&self, folder: &CoreFolder, total_messages: u32) {
        self.0
            .with_folder(folder.as_str(), |progress| progress.total = total_messages);
    }

    fn on_messages_scanned(&self, folder: &CoreFolder, count: u32) {
        self.0
            .with_folder(folder.as_str(), |progress| progress.scanned += count);
    }

    fn on_folder_done(&self, folder: &CoreFolder) {
        self.0
            .with_folder(folder.as_str(), |progress| progress.done = true);
    }

    fn on_totals(&self, senders: u32, warnings: u32) {
        *self.0.totals.lock().expect("scan totals lock") = (senders, warnings);
    }

    fn should_cancel(&self) -> bool {
        self.0.cancel_requested()
    }
}

/// How a scan ended.
pub enum ScanOutcome {
    Done(Box<ObtainedSenders>),
    /// The user cancelled. Nothing was written: the previous cache stands.
    Cancelled,
    Failed(String),
}

/// Scan the mailbox on a worker thread.
///
/// The thread opens its own store handles rather than borrowing the app's:
/// SQLite is happy with a second connection and it keeps every lifetime out
/// of the thread boundary.
pub fn spawn_scan(
    account: AccountConfig,
    credential: Credential,
    preferences: Preferences,
    shared: Arc<ScanShared>,
) -> Receiver<ScanOutcome> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            scan_once(&account, &credential, &preferences, &shared)
        }));
        let message = match outcome {
            Ok(Ok(obtained)) => ScanOutcome::Done(Box::new(obtained)),
            Ok(Err(e)) if is_cancelled(&e) => ScanOutcome::Cancelled,
            Ok(Err(e)) => ScanOutcome::Failed(format!("{e:#}")),
            Err(_) => ScanOutcome::Failed(PANICKED.to_string()),
        };
        // A closed receiver means the screen is gone; nothing to report to.
        let _ = tx.send(message);
    });
    rx
}

fn scan_once(
    account: &AccountConfig,
    credential: &Credential,
    preferences: &Preferences,
    shared: &Arc<ScanShared>,
) -> Result<ObtainedSenders> {
    let provider = make_provider(account, credential)?;
    let folders: Vec<CoreFolder> = account
        .scan_folders
        .iter()
        .map(|f| CoreFolder::new(f))
        .collect();
    let cache = SqliteCacheStore::open_default()?;
    let warnings = FileDataStore::new();
    let reporter = ScanReporter(Arc::clone(shared));

    scan_senders(
        &account.account_id,
        &folders,
        provider.as_ref(),
        &cache,
        &warnings,
        preferences.min_emails,
        &now_iso8601(),
        &reporter,
        &NoWarnings,
    )
}

/// Scan warnings reach the screen through the scan's own result, so the
/// observer a scan needs only has to exist.
struct NoWarnings;

impl RunObserver for NoWarnings {
    fn on_unsubscribe_start(&self, _sender_count: u32) {}
    fn on_sender_result(&self, _planned: &PlannedSender, _result: &UnsubscribeResult) {}
    fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}
    fn on_archive_start(&self, _message_count: u32, _email_count: u32) {}
    fn on_archive_done(&self, _archived: u32) {}
    fn on_warning(&self, _warning: &RunWarning) {}
}

// -- run ---------------------------------------------------------------------

/// One line of a run, as the screen draws it.
#[derive(Debug, Clone)]
pub enum RunEvent {
    /// One sender's attempt finished.
    Sender {
        email: String,
        success: bool,
        method: String,
        detail: String,
        /// What was ignored and what was tried instead, when this was a climb
        /// up the ladder.
        escalation: Option<String>,
    },
    /// The archive phase started.
    Archiving { messages: u32, emails: u32 },
    /// The archive finished.
    Archived { archived: u32 },
    /// Something non-fatal went wrong.
    Warning(String),
}

/// What the run screen reads, and the flag it writes.
#[derive(Debug, Default)]
pub struct RunShared {
    events: Mutex<Vec<RunEvent>>,
    /// How many senders the run set out to attempt.
    planned: Mutex<u32>,
    cancel: AtomicBool,
}

impl RunShared {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Ask the run to stop before the next sender.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn cancel_requested(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn events(&self) -> Vec<RunEvent> {
        self.events.lock().expect("run events lock").clone()
    }

    #[must_use]
    pub fn planned(&self) -> u32 {
        *self.planned.lock().expect("run planned lock")
    }

    /// Append one line to the log. `pub(super)` so the run screen's tests can
    /// stage a log without a worker thread.
    pub(super) fn push(&self, event: RunEvent) {
        self.events.lock().expect("run events lock").push(event);
    }
}

/// The [`RunObserver`] port, writing into the shared log.
struct RunReporter(Arc<RunShared>);

impl RunObserver for RunReporter {
    fn on_unsubscribe_start(&self, sender_count: u32) {
        *self.0.planned.lock().expect("run planned lock") = sender_count;
    }

    fn on_sender_result(&self, planned: &PlannedSender, result: &UnsubscribeResult) {
        self.0.push(RunEvent::Sender {
            email: result.email.clone(),
            success: result.success,
            method: result.method.label().to_string(),
            detail: result.detail.clone(),
            escalation: escalation_text(planned),
        });
    }

    fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}

    fn on_archive_start(&self, message_count: u32, email_count: u32) {
        self.0.push(RunEvent::Archiving {
            messages: message_count,
            emails: email_count,
        });
    }

    fn on_archive_done(&self, archived: u32) {
        self.0.push(RunEvent::Archived { archived });
    }

    fn on_warning(&self, warning: &RunWarning) {
        self.0.push(RunEvent::Warning(warning_text(warning)));
    }

    fn should_cancel(&self) -> bool {
        self.0.cancel_requested()
    }
}

/// How a run ended.
pub enum RunResult {
    Done(Box<RunOutcome>),
    /// The archive failed; every attempt is still in the history.
    Failed(String),
}

/// Carry out a plan on a worker thread.
pub fn spawn_run(
    account: AccountConfig,
    credential: Credential,
    plan: RunPlan,
    policy: RunPolicy,
    shared: Arc<RunShared>,
) -> Receiver<RunResult> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let cache = SqliteCacheStore::open_default()?;
            let history = SqliteHistoryStore::open_default().ok();
            let reporter = RunReporter(Arc::clone(&shared));
            execute(
                &account,
                &credential,
                &cache,
                history.as_ref().map(|store| store as &dyn HistoryStore),
                &plan,
                &policy,
                &reporter,
            )
        }));
        let message = match outcome {
            Ok(Ok(outcome)) => RunResult::Done(Box::new(outcome)),
            Ok(Err(e)) => RunResult::Failed(format!("{e:#}")),
            Err(_) => RunResult::Failed(PANICKED.to_string()),
        };
        let _ = tx.send(message);
    });
    rx
}

/// What a row says about climbing the ladder, when it climbed one.
fn escalation_text(planned: &PlannedSender) -> Option<String> {
    let escalation = planned.escalation()?;
    Some(match escalation.from {
        Some(from) => format!(
            "escalated: {} \u{2192} {}",
            from.label(),
            escalation.rung.label()
        ),
        None => format!("escalated to {}", escalation.rung.label()),
    })
}

/// One line of wording per warning, for a list rather than a terminal.
///
/// The CLI says the same things with colour and a follow-up hint; here the
/// medium is a row in a scrolling log, so the text is its own.
fn warning_text(warning: &RunWarning) -> String {
    match warning {
        RunWarning::CacheUnreadable(e) => format!("Could not read the scan cache: {e}"),
        RunWarning::CacheNotWritten(e) => format!("Could not write the scan cache: {e}"),
        RunWarning::CacheNotPruned(e) => {
            format!("Could not prune the scan cache ({e}) \u{2014} rescan to rebuild it")
        }
        RunWarning::AttemptNotRecorded(e) => {
            format!("Unsubscribed, but the history could not record it: {e}")
        }
        RunWarning::ResumptionNotRecorded(e) => {
            format!("Could not record a resumed sender: {e}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::{
        Escalation, Folder as CoreFolder, MessageId, NextStep, Rung, RungMethod, UnsubscribeMethod,
        UnsubscribeResult,
    };

    fn folder(name: &str) -> CoreFolder {
        CoreFolder::new(name)
    }

    fn progress(shared: &Arc<ScanShared>) -> ScanReporter {
        ScanReporter(Arc::clone(shared))
    }

    fn named(shared: &ScanShared, name: &str) -> FolderProgress {
        shared
            .folders()
            .into_iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no progress for {name}"))
    }

    // -----------------------------------------------------------------------
    // Scan progress
    // -----------------------------------------------------------------------

    #[test]
    fn a_scan_starts_with_nothing_to_show() {
        let shared = ScanShared::new();

        assert!(shared.folders().is_empty());
        assert_eq!(shared.totals(), (0, 0));
        assert!(!shared.cancel_requested());
    }

    #[test]
    fn message_counts_accumulate_across_batches() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_folder_start(&folder("INBOX"), 500);
        reporter.on_messages_scanned(&folder("INBOX"), 100);
        reporter.on_messages_scanned(&folder("INBOX"), 100);
        reporter.on_messages_scanned(&folder("INBOX"), 50);

        let inbox = named(&shared, "INBOX");
        assert_eq!(inbox.scanned, 250);
        assert_eq!(inbox.total, 500);
        assert!(!inbox.done);
    }

    #[test]
    fn a_second_folder_start_updates_the_total_without_adding_a_row() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_folder_start(&folder("INBOX"), 500);
        reporter.on_messages_scanned(&folder("INBOX"), 100);
        reporter.on_folder_start(&folder("INBOX"), 600);

        assert_eq!(shared.folders().len(), 1);
        assert_eq!(named(&shared, "INBOX").total, 600);
        assert_eq!(
            named(&shared, "INBOX").scanned,
            100,
            "what was already read is not lost"
        );
    }

    #[test]
    fn a_batch_reported_before_its_folder_started_is_kept_not_dropped() {
        // Adapters scan folders on their own threads; nothing guarantees the
        // start arrives at the UI before the first batch does.
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_messages_scanned(&folder("Archive"), 40);
        reporter.on_folder_start(&folder("Archive"), 200);

        assert_eq!(named(&shared, "Archive").scanned, 40);
        assert_eq!(named(&shared, "Archive").total, 200);
    }

    #[test]
    fn a_folder_done_after_more_batches_keeps_the_final_count() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_folder_start(&folder("INBOX"), 100);
        reporter.on_messages_scanned(&folder("INBOX"), 100);
        reporter.on_folder_done(&folder("INBOX"));
        // A duplicate ending must not undo anything.
        reporter.on_folder_done(&folder("INBOX"));

        let inbox = named(&shared, "INBOX");
        assert!(inbox.done);
        assert_eq!(inbox.scanned, 100);
        assert_eq!(shared.folders().len(), 1);
    }

    #[test]
    fn folders_keep_the_order_they_started_in() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_folder_start(&folder("INBOX"), 10);
        reporter.on_folder_start(&folder("Archive"), 10);
        reporter.on_folder_start(&folder("Spam"), 10);
        reporter.on_messages_scanned(&folder("Spam"), 1);

        let names: Vec<String> = shared.folders().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["INBOX", "Archive", "Spam"]);
    }

    #[test]
    fn each_folder_counts_only_its_own_messages() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_folder_start(&folder("INBOX"), 100);
        reporter.on_folder_start(&folder("Archive"), 100);
        reporter.on_messages_scanned(&folder("INBOX"), 30);
        reporter.on_messages_scanned(&folder("Archive"), 5);

        assert_eq!(named(&shared, "INBOX").scanned, 30);
        assert_eq!(named(&shared, "Archive").scanned, 5);
    }

    #[test]
    fn the_latest_totals_the_adapter_reports_are_the_ones_shown() {
        // Only the adapter can count senders deduplicated across folders, so
        // each report replaces the last rather than adding to it.
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        reporter.on_totals(12, 1);
        reporter.on_totals(30, 4);

        assert_eq!(shared.totals(), (30, 4));
    }

    #[test]
    fn a_scan_polls_the_flag_the_screen_sets() {
        let shared = ScanShared::new();
        let reporter = progress(&shared);

        assert!(!reporter.should_cancel());
        shared.cancel();
        assert!(reporter.should_cancel());
        // Asking twice changes nothing.
        shared.cancel();
        assert!(reporter.should_cancel());
    }

    // -----------------------------------------------------------------------
    // Run progress
    // -----------------------------------------------------------------------

    fn sender_info(email: &str) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
            unsubscribe_mailto: vec!["mailto:unsub@acme.example.com".to_string()],
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 3,
            messages: vec![unsubscribe_core::FolderMessage {
                folder: folder("INBOX"),
                message_id: MessageId::new("INBOX:1"),
            }],
            last_seen: None,
        }
    }

    fn planned(email: &str, step: NextStep) -> PlannedSender {
        PlannedSender {
            sender: sender_info(email),
            step,
        }
    }

    fn result(email: &str, success: bool) -> UnsubscribeResult {
        UnsubscribeResult {
            email: email.to_string(),
            method: UnsubscribeMethod::OneClickPost,
            success,
            detail: "HTTP 200".to_string(),
            url: "https://acme.example.com/unsub".to_string(),
            http_status: Some(200),
            final_url: None,
        }
    }

    fn escalation(from: Option<RungMethod>, to: RungMethod) -> NextStep {
        NextStep::Escalate(Escalation {
            rung: Rung::new(to, "https://acme.example.com/unsub"),
            from,
            follows_attempt_id: Some("a1".to_string()),
        })
    }

    #[test]
    fn a_run_starts_with_an_empty_log() {
        let shared = RunShared::new();

        assert!(shared.events().is_empty());
        assert_eq!(shared.planned(), 0);
        assert!(!shared.cancel_requested());
    }

    #[test]
    fn the_run_log_keeps_every_phase_in_the_order_it_happened() {
        let shared = RunShared::new();
        let reporter = RunReporter(Arc::clone(&shared));

        reporter.on_unsubscribe_start(2);
        reporter.on_sender_result(&planned("one@acme.example.com", NextStep::FirstAttempt), &result("one@acme.example.com", true));
        reporter.on_sender_result(&planned("two@acme.example.com", NextStep::FirstAttempt), &result("two@acme.example.com", false));
        reporter.on_archive_start(6, 2);
        reporter.on_archive_done(6);

        assert_eq!(shared.planned(), 2);
        let kinds: Vec<&str> = shared
            .events()
            .iter()
            .map(|event| match event {
                RunEvent::Sender { .. } => "sender",
                RunEvent::Archiving { .. } => "archiving",
                RunEvent::Archived { .. } => "archived",
                RunEvent::Warning(_) => "warning",
            })
            .collect();
        assert_eq!(kinds, ["sender", "sender", "archiving", "archived"]);
    }

    #[test]
    fn a_sender_row_carries_the_result_the_pipeline_produced() {
        let shared = RunShared::new();
        let reporter = RunReporter(Arc::clone(&shared));

        reporter.on_sender_result(
            &planned("one@acme.example.com", NextStep::FirstAttempt),
            &result("one@acme.example.com", false),
        );

        match &shared.events()[0] {
            RunEvent::Sender {
                email,
                success,
                method,
                escalation,
                ..
            } => {
                assert_eq!(email, "one@acme.example.com");
                assert!(!success);
                assert_eq!(method, UnsubscribeMethod::OneClickPost.label());
                assert_eq!(escalation.as_deref(), None, "a first attempt climbs nothing");
            }
            other => panic!("expected a sender row, got {other:?}"),
        }
    }

    #[test]
    fn the_archive_counts_reach_the_log_unchanged() {
        let shared = RunShared::new();
        let reporter = RunReporter(Arc::clone(&shared));

        reporter.on_archive_start(41, 7);
        reporter.on_archive_done(41);

        assert!(matches!(
            shared.events().as_slice(),
            [
                RunEvent::Archiving {
                    messages: 41,
                    emails: 7
                },
                RunEvent::Archived { archived: 41 }
            ]
        ));
    }

    #[test]
    fn a_run_polls_the_flag_the_screen_sets() {
        let shared = RunShared::new();
        let reporter = RunReporter(Arc::clone(&shared));

        assert!(!reporter.should_cancel());
        shared.cancel();
        assert!(reporter.should_cancel());
    }

    // -----------------------------------------------------------------------
    // Wording
    // -----------------------------------------------------------------------

    #[test]
    fn a_first_attempt_and_an_exhausted_sender_name_no_escalation() {
        assert_eq!(
            escalation_text(&planned("one@acme.example.com", NextStep::FirstAttempt)),
            None
        );
        assert_eq!(
            escalation_text(&planned("one@acme.example.com", NextStep::Exhausted)),
            None
        );
    }

    #[test]
    fn a_climb_names_what_was_ignored_and_what_is_being_tried_instead() {
        let text = escalation_text(&planned(
            "one@acme.example.com",
            escalation(Some(RungMethod::OneClickPost), RungMethod::HttpFlow),
        ))
        .expect("an escalation has something to say");

        assert!(text.contains(RungMethod::OneClickPost.label()), "{text}");
        assert!(text.contains(RungMethod::HttpFlow.label()), "{text}");
    }

    #[test]
    fn a_climb_from_an_unknown_rung_still_names_the_one_being_tried() {
        let text = escalation_text(&planned(
            "one@acme.example.com",
            escalation(None, RungMethod::Mailto),
        ))
        .expect("an escalation has something to say");

        assert_eq!(text, format!("escalated to {}", RungMethod::Mailto.label()));
    }

    #[test]
    fn every_warning_becomes_one_line_that_keeps_the_underlying_reason() {
        let warnings = [
            RunWarning::CacheUnreadable("file is corrupt".to_string()),
            RunWarning::CacheNotWritten("read-only".to_string()),
            RunWarning::CacheNotPruned("locked".to_string()),
            RunWarning::AttemptNotRecorded("db is locked".to_string()),
            RunWarning::ResumptionNotRecorded("db is locked".to_string()),
        ];

        for warning in &warnings {
            let text = warning_text(warning);
            assert_eq!(text.lines().count(), 1, "{text:?} must be one row in a log");
            assert!(!text.is_empty());
        }
        assert!(warning_text(&warnings[0]).contains("file is corrupt"));
        assert!(warning_text(&warnings[3]).contains("db is locked"));
    }

    // -----------------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------------

    fn preferences() -> Preferences {
        Preferences {
            min_emails: 5,
            stale_after_months: 9,
            cache_max_age_days: 3,
            grace_period_days: 21,
        }
    }

    #[test]
    fn a_dry_run_choice_is_carried_into_the_policy_the_run_uses() {
        assert!(policy(&preferences(), true).dry_run);
        assert!(!policy(&preferences(), false).dry_run);
    }

    #[test]
    fn the_run_policy_is_the_users_preferences_and_nothing_invented() {
        let policy = policy(&preferences(), false);

        assert_eq!(policy.min_emails, 5);
        assert_eq!(policy.stale_after_months, 9);
        assert_eq!(policy.grace_period_days, 21);
    }
}
