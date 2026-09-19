//! The run pipeline: obtain senders, annotate them against history, plan what
//! will happen, and execute it.
//!
//! Four stages the consumer calls in order, with its own selection step between
//! annotating and planning. Nothing here prints, prompts, or knows what a
//! terminal is: progress and per-sender outcomes go out through
//! [`RunObserver`], and everything a user could tune arrives in [`RunPolicy`].
//! That is what lets the interactive TUI, the scriptable CLI and the future
//! unattended scheduler run the same loop.
//!
//! Ordering inside [`execute_run`] is the part that matters and is deliberate:
//! each attempt is written to the history the moment it completes, so a later
//! archive failure loses the mail move and never the evidence; the scan cache
//! is pruned only once the archive has actually succeeded; and a dry run
//! touches nothing at all.

use anyhow::Result;

use crate::escalation::{next_step, Escalation, NextStep};
use crate::history::{
    forget_shared_list_ids, observed_resumptions, split_previously_unsubscribed,
    PreviouslyUnsubscribed, Resumption,
    UnsubscribeAttempt,
};
use crate::ports::{
    CacheMeta, CachedScan, DataStore, EmailProvider, EmailSender, HistoryStore, HttpClient,
    ScanCacheStore, ScanProgress,
};
use crate::types::{Folder, FolderMessage, SenderInfo, UnsubscribeMethod, UnsubscribeResult};
use crate::unsubscribe::{unsubscribe_sender, unsubscribe_via};

/// Seconds in a month, taken as a twelfth of a 365-day year so that a threshold
/// of 12 months is exactly one year.
const SECS_PER_MONTH: i64 = 365 * 24 * 60 * 60 / 12;

/// Current time in Unix seconds (UTC), or 0 if the clock is before the epoch.
///
/// The pure stages take the time as an argument; this exists for the ones that
/// are already doing I/O and need to stamp a record as it happens.
#[must_use]
pub fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A sender is stale when their most recent message predates the threshold.
///
/// Senders whose adapter gave no date are never stale: unknown is not old.
#[must_use]
pub fn is_stale(sender: &SenderInfo, stale_after_months: u32, now: i64) -> bool {
    match sender.last_seen {
        Some(ts) => now - ts > i64::from(stale_after_months) * SECS_PER_MONTH,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Policy and reporting
// ---------------------------------------------------------------------------

/// The tunable values a run needs, supplied by the consumer.
///
/// Core hard-codes no thresholds; every number here is something a user (or a
/// scheduler's config) chose, handed over as plain data so the same pipeline
/// serves a TUI, a headless CLI and a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunPolicy {
    /// Minimum number of emails a sender must have to be offered at all.
    pub min_emails: u32,
    /// Months without a message before a sender is archived rather than
    /// unsubscribed from.
    pub stale_after_months: u32,
    /// Days a sender is given to honour an unsubscribe before new mail counts
    /// as a resumption.
    pub grace_period_days: u32,
    /// Report what would happen and change nothing.
    pub dry_run: bool,
}

/// A stage stopped because the consumer asked it to, through
/// [`ScanProgress::should_cancel`] or [`RunObserver::should_cancel`].
///
/// Carried as an error so it travels the same path a failure does, but it is
/// not one: consumers test for it with [`is_cancelled`] and say "cancelled"
/// rather than showing a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Whether an error is really a cancellation.
#[must_use]
pub fn is_cancelled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Cancelled>().is_some()
}

/// Something non-fatal that went wrong mid-run.
///
/// An enum rather than a message so the consumer writes the wording: core
/// never produces user-facing text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunWarning {
    /// The scan cache could not be read; the run continues without it.
    CacheUnreadable(String),
    /// The scan cache could not be replaced after a scan. Costs a rescan.
    CacheNotWritten(String),
    /// Archived senders could not be dropped from the cache, so the cache now
    /// points at messages that have moved.
    CacheNotPruned(String),
    /// An attempt completed but could not be written to the history. The
    /// unsubscribe happened; the evidence for it did not survive.
    AttemptNotRecorded(String),
    /// A sender was seen ignoring its unsubscribe but the observation could
    /// not be written to the history.
    ResumptionNotRecorded(String),
}

/// Port for reporting run progress and per-sender outcomes.
///
/// The same pattern as [`ScanProgress`]: consumers render, core reports. A
/// headless consumer implements it with logging, or uses [`NoopRunObserver`].
pub trait RunObserver {
    /// About to attempt `sender_count` unsubscribes. Zero is reported too, so
    /// a consumer can decide for itself whether to announce the phase.
    fn on_unsubscribe_start(&self, sender_count: u32);

    /// One sender's attempt finished. Fires in dry runs as well, where the
    /// result describes what would have been tried.
    fn on_sender_result(&self, planned: &PlannedSender, result: &UnsubscribeResult);

    /// Every attempt is done. `planned` and `results` are in the same order,
    /// so a consumer can show what each sender escalated from and to.
    fn on_unsubscribe_done(&self, planned: &[PlannedSender], results: &[UnsubscribeResult]);

    /// About to archive `message_count` messages carrying `email_count` emails
    /// between them.
    fn on_archive_start(&self, message_count: u32, email_count: u32);

    /// The archive finished, having moved `archived` messages.
    fn on_archive_done(&self, archived: u32);

    /// Something went wrong that did not stop the run.
    fn on_warning(&self, warning: &RunWarning);

    /// Whether the consumer has asked the run to stop.
    ///
    /// Polled between senders and never inside one: an attempt that has been
    /// made is evidence, and abandoning it half-way would lose the record of
    /// a request the sender has already received. Senders already handled are
    /// still archived and pruned. The default is never, so a consumer that
    /// has no way to cancel needs no code at all.
    fn should_cancel(&self) -> bool {
        false
    }
}

/// Observer for consumers that do not report progress (tests, batch jobs).
pub struct NoopRunObserver;

impl RunObserver for NoopRunObserver {
    fn on_unsubscribe_start(&self, _sender_count: u32) {}
    fn on_sender_result(&self, _planned: &PlannedSender, _result: &UnsubscribeResult) {}
    fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}
    fn on_archive_start(&self, _message_count: u32, _email_count: u32) {}
    fn on_archive_done(&self, _archived: u32) {}
    fn on_warning(&self, _warning: &RunWarning) {}
}

// ---------------------------------------------------------------------------
// Stage 1: obtain senders
// ---------------------------------------------------------------------------

/// Senders a run works from, and where they came from.
#[derive(Debug, Clone)]
pub struct ObtainedSenders {
    pub senders: Vec<SenderInfo>,
    /// Scan warnings. Always empty for cached senders -- the cache does not
    /// store them.
    pub warnings: Vec<String>,
    /// When the scan behind these senders was taken (ISO 8601, UTC).
    pub scanned_at: String,
    pub from_cache: bool,
}

/// The cached scan for an account, if there is one worth offering.
///
/// An unreadable cache is reported through the observer and then treated as
/// absent: it costs a rescan, not a run. So is an empty one -- after enough
/// runs prune their senders there is nothing left to choose between.
#[must_use]
pub fn load_cached_senders(
    cache: &dyn ScanCacheStore,
    account: &str,
    min_emails: u32,
    observer: &dyn RunObserver,
) -> Option<ObtainedSenders> {
    let cached = match cache.read_scan_cache(account) {
        Ok(cached) => cached?,
        Err(e) => {
            observer.on_warning(&RunWarning::CacheUnreadable(e.to_string()));
            return None;
        }
    };

    // Identity is decided over the whole scan, so the shared-list rule is
    // applied before the minimum-count filter thins it out.
    let senders: Vec<_> = forget_shared_list_ids(cached.senders)
        .into_iter()
        .filter(|s| s.email_count >= min_emails)
        .collect();

    (!senders.is_empty()).then(|| ObtainedSenders {
        senders,
        warnings: Vec::new(),
        scanned_at: cached.meta.scanned_at,
        from_cache: true,
    })
}

/// Scan the mailbox, persist the warnings and the cache, and filter the result.
///
/// `scanned_at` is the consumer's ISO 8601 UTC stamp for this scan; core does
/// no date formatting. Writing the cache is best-effort -- losing it costs a
/// rescan -- while failing to persist warnings is reported to the caller, as it
/// signals a data directory that is not writable at all.
#[allow(clippy::too_many_arguments)]
pub fn scan_senders(
    account: &str,
    folders: &[Folder],
    provider: &dyn EmailProvider,
    cache: &dyn ScanCacheStore,
    warnings_store: &dyn DataStore,
    min_emails: u32,
    scanned_at: &str,
    progress: &dyn ScanProgress,
    observer: &dyn RunObserver,
) -> Result<ObtainedSenders> {
    let scan = provider.scan(folders, progress);

    // Checked before the result is even unwrapped: an adapter that aborted
    // mid-scan may report the abort as an error, and that is a cancellation,
    // not a failure. Nothing has been written at this point, so the cache and
    // the warnings from the last complete scan are untouched.
    if progress.should_cancel() {
        return Err(Cancelled.into());
    }
    let scan = scan?;

    warnings_store.write_warnings(&scan.warnings)?;

    let cached = CachedScan {
        meta: CacheMeta {
            scanned_at: scanned_at.to_string(),
            format_version: 1,
            account: account.to_string(),
        },
        senders: scan.senders.clone(),
        watermark: scan.watermark,
    };
    if let Err(e) = cache.write_scan_cache(&cached) {
        observer.on_warning(&RunWarning::CacheNotWritten(e.to_string()));
    }

    Ok(ObtainedSenders {
        // The cache above keeps every header verbatim; what leaves this stage
        // is identity, and a list identifier several addresses share is none.
        senders: forget_shared_list_ids(scan.senders)
            .into_iter()
            .filter(|s| s.email_count >= min_emails)
            .collect(),
        warnings: scan.warnings,
        scanned_at: scanned_at.to_string(),
        from_cache: false,
    })
}

// ---------------------------------------------------------------------------
// Stage 2: annotate against history
// ---------------------------------------------------------------------------

/// Scanned senders sorted into the three groups a consumer presents.
///
/// A previously unsubscribed sender stays in its own group even when it is also
/// stale: that it came back at all is the interesting part.
#[derive(Debug, Clone, Default)]
pub struct AnnotatedSenders {
    /// Senders with a prior successful unsubscribe, in scanned order, each
    /// carrying the verdict on whether that unsubscribe was honoured.
    pub previously_unsubscribed: Vec<PreviouslyUnsubscribed>,
    /// Senders seen within the staleness threshold (or of unknown date).
    pub active: Vec<SenderInfo>,
    /// Senders whose most recent message predates the staleness threshold.
    pub stale: Vec<SenderInfo>,
    /// Senders caught ignoring an unsubscribe that the history does not
    /// already record. Hand these to [`record_resumptions`], and to
    /// [`plan_run`] alongside the history's own -- the run that catches a
    /// sender is the run that should escalate past the rung it ignored.
    pub new_resumptions: Vec<Resumption>,
}

impl AnnotatedSenders {
    /// Total number of senders across all three groups.
    #[must_use]
    pub fn total(&self) -> usize {
        self.previously_unsubscribed.len() + self.active.len() + self.stale.len()
    }

    /// Senders that ignored an unsubscribe, however long ago it was observed.
    pub fn resumed(&self) -> impl Iterator<Item = &PreviouslyUnsubscribed> {
        self.previously_unsubscribed
            .iter()
            .filter(|p| p.verdict.outcome.is_resumed())
    }
}

/// Match scanned senders against an account's unsubscribe history, judging
/// what each previously unsubscribed sender has done since.
///
/// The judgement itself is pure ([`crate::history::classify_outcome`]); what
/// this adds is the grouping and the list of observations worth recording.
/// Nothing is written here -- a consumer that decides not to record (a dry run)
/// simply does not call [`record_resumptions`].
#[must_use]
pub fn annotate_senders(
    account: &str,
    senders: Vec<SenderInfo>,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    policy: &RunPolicy,
    now: i64,
) -> AnnotatedSenders {
    // What this scan reveals has to be known before anything is judged: a
    // sender caught ignoring an unsubscribe right now has a spent rung right
    // now, and the verdict on screen must already say so.
    let new_resumptions =
        observed_resumptions(account, &senders, attempts, resumptions, now, policy.grace_period_days);
    let effective: Vec<Resumption> = resumptions
        .iter()
        .chain(new_resumptions.iter())
        .cloned()
        .collect();

    let sections = split_previously_unsubscribed(
        senders,
        attempts,
        &effective,
        now,
        policy.grace_period_days,
    );
    let (stale, active): (Vec<_>, Vec<_>) = sections
        .remaining
        .into_iter()
        .partition(|s| is_stale(s, policy.stale_after_months, now));

    AnnotatedSenders {
        previously_unsubscribed: sections.previously_unsubscribed,
        active,
        stale,
        new_resumptions,
    }
}

/// Write the resumptions an annotation turned up.
///
/// The violation log is evidence, not a prerequisite: a history that cannot be
/// written costs the record and nothing else. A dry run records nothing,
/// having promised to change nothing.
pub fn record_resumptions(
    annotated: &AnnotatedSenders,
    history: Option<&dyn HistoryStore>,
    policy: &RunPolicy,
    observer: &dyn RunObserver,
) {
    if policy.dry_run {
        return;
    }
    let Some(history) = history else {
        return;
    };
    for resumption in &annotated.new_resumptions {
        if let Err(e) = history.record_resumption(resumption) {
            observer
                .on_warning(&RunWarning::ResumptionNotRecorded(e.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 3: plan
// ---------------------------------------------------------------------------

/// One sender the run will attempt an unsubscribe for, and how.
#[derive(Debug, Clone)]
pub struct PlannedSender {
    pub sender: SenderInfo,
    /// The full flow, or the one rung the history says to climb to next.
    pub step: NextStep,
}

impl PlannedSender {
    /// The escalation this attempt is, when it is one.
    #[must_use]
    pub fn escalation(&self) -> Option<&Escalation> {
        match &self.step {
            NextStep::Escalate(escalation) => Some(escalation),
            NextStep::FirstAttempt | NextStep::Exhausted => None,
        }
    }
}

/// What a run will do to the senders the user selected.
///
/// Stale senders are archived without an unsubscribe attempt: mail that stopped
/// arriving a year ago is not worth poking a tracking URL for. So are exhausted
/// ones, for the opposite reason -- everything has been asked already.
#[derive(Debug, Clone, Default)]
pub struct RunPlan {
    /// Senders that get an unsubscribe attempt and then an archive.
    pub to_unsubscribe: Vec<PlannedSender>,
    /// Stale senders, archived only.
    pub archive_only: Vec<SenderInfo>,
    /// Senders whose every rung is spent or broken: archived, and the
    /// candidates for a server-side filter or a report once those exist.
    pub exhausted: Vec<SenderInfo>,
}

impl RunPlan {
    /// Emails belonging to senders that will be unsubscribed from.
    #[must_use]
    pub fn unsubscribe_emails(&self) -> u32 {
        self.to_unsubscribe
            .iter()
            .map(|planned| planned.sender.email_count)
            .sum()
    }

    /// Emails belonging to stale senders that will only be archived.
    #[must_use]
    pub fn archive_only_emails(&self) -> u32 {
        self.archive_only.iter().map(|s| s.email_count).sum()
    }

    /// Emails belonging to senders with nothing left to try.
    #[must_use]
    pub fn exhausted_emails(&self) -> u32 {
        self.exhausted.iter().map(|s| s.email_count).sum()
    }

    /// Emails the run touches in total.
    #[must_use]
    pub fn total_emails(&self) -> u32 {
        self.unsubscribe_emails() + self.archive_only_emails() + self.exhausted_emails()
    }

    /// Whether the plan would do nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_unsubscribe.is_empty() && self.archive_only.is_empty() && self.exhausted.is_empty()
    }

    /// Every sender the run archives, whether or not it was asked to stop.
    pub fn archived_senders(&self) -> impl Iterator<Item = &SenderInfo> {
        self.to_unsubscribe
            .iter()
            .map(|planned| &planned.sender)
            .chain(self.archive_only.iter())
            .chain(self.exhausted.iter())
    }

    /// Every message the run moves, across all archived senders.
    #[must_use]
    pub fn archive_messages(&self) -> Vec<FolderMessage> {
        self.archived_senders()
            .flat_map(|s| s.messages.iter().cloned())
            .collect()
    }

    /// Addresses of the archived senders, for pruning the scan cache.
    #[must_use]
    pub fn archived_sender_emails(&self) -> Vec<String> {
        self.archived_senders().map(|s| s.email.clone()).collect()
    }
}

/// Work out what the run will do to each selected sender.
///
/// Three destinations: stale senders are archived, senders whose ladder is used
/// up are archived and noted, and everything else gets the one attempt its
/// history says is worth making. Order within each group is the order the
/// senders were selected in.
#[must_use]
pub fn plan_run(
    selected: Vec<SenderInfo>,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    policy: &RunPolicy,
    now: i64,
) -> RunPlan {
    selected
        .into_iter()
        .fold(RunPlan::default(), |mut plan, sender| {
            if is_stale(&sender, policy.stale_after_months, now) {
                plan.archive_only.push(sender);
                return plan;
            }
            let step = next_step(&sender, attempts, resumptions);
            if step.is_exhausted() {
                plan.exhausted.push(sender);
            } else {
                plan.to_unsubscribe.push(PlannedSender { sender, step });
            }
            plan
        })
}

// ---------------------------------------------------------------------------
// Stage 4: execute
// ---------------------------------------------------------------------------

/// The adapters and stores a run acts through.
///
/// Grouped into one struct because the alternative is a dozen positional
/// arguments; every field is a port, so a consumer assembles this from whatever
/// implementations it has.
pub struct RunContext<'a> {
    /// Account the run belongs to, as the history and cache key it.
    pub account: &'a str,
    /// Folder archived messages are moved into.
    pub archive_folder: &'a Folder,
    pub provider: &'a dyn EmailProvider,
    pub http: &'a dyn HttpClient,
    /// Used for `mailto:` unsubscribes. When absent, mailto-only senders are
    /// reported as skipped rather than failing the run.
    pub email_sender: Option<&'a dyn EmailSender>,
    /// When absent, the run still unsubscribes -- it just records no evidence.
    pub history: Option<&'a dyn HistoryStore>,
    pub cache: &'a dyn ScanCacheStore,
    pub observer: &'a dyn RunObserver,
}

/// What a run actually did.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct RunOutcome {
    /// One result per sender attempted, in plan order. Shorter than
    /// [`RunPlan::to_unsubscribe`] when the run was cancelled part-way.
    pub results: Vec<UnsubscribeResult>,
    /// Messages moved into the archive folder.
    pub archived: u32,
    /// Whether the run stopped early because the consumer asked it to.
    pub cancelled: bool,
}

impl RunOutcome {
    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    #[must_use]
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }
}

/// Carry out the plan: unsubscribe, record, archive, prune.
///
/// Returns an error only when the archive itself fails, and by then every
/// attempt is already in the history -- the caller can tell the user their
/// unsubscribes stand even though the mail did not move.
pub fn execute_run(
    plan: &RunPlan,
    ctx: &RunContext<'_>,
    policy: &RunPolicy,
) -> Result<RunOutcome> {
    let results = attempt_unsubscribes(plan, ctx, policy);
    let cancelled = results.len() < plan.to_unsubscribe.len();
    let attempted = &plan.to_unsubscribe[..results.len()];
    ctx.observer.on_unsubscribe_done(attempted, &results);

    // A cancelled run archives what it handled and nothing else. The senders
    // it never reached keep their mail where it is, so the next run finds
    // them exactly as this one did.
    let handled: Vec<&SenderInfo> = if cancelled {
        attempted.iter().map(|planned| &planned.sender).collect()
    } else {
        plan.archived_senders().collect()
    };
    let messages: Vec<FolderMessage> = handled
        .iter()
        .flat_map(|sender| sender.messages.iter().cloned())
        .collect();
    let emails: u32 = handled.iter().map(|sender| sender.email_count).sum();

    ctx.observer
        .on_archive_start(messages.len() as u32, emails);

    // A dry run reports what the archive would move and moves nothing. So
    // does an empty archive: a run cancelled before its first sender should
    // not open a mailbox connection to move nothing.
    let archived = if policy.dry_run {
        emails
    } else if messages.is_empty() {
        0
    } else {
        ctx.provider.archive(&messages, ctx.archive_folder)?
    };
    ctx.observer.on_archive_done(archived);

    // The archived messages have moved, so the cached rows now point at ids
    // that are no longer where the cache says they are. Pruning also keeps a
    // sender that was just handled from reappearing on the next cached run.
    // Only a real archive prunes: a dry run changed nothing.
    if !policy.dry_run {
        let emails: Vec<String> = handled.iter().map(|s| s.email.clone()).collect();
        let pruned = ctx.cache.remove_cached_senders(ctx.account, &emails);
        if let Err(e) = pruned {
            ctx.observer
                .on_warning(&RunWarning::CacheNotPruned(e.to_string()));
        }
    }

    Ok(RunOutcome {
        results,
        archived,
        cancelled,
    })
}

/// Attempt every planned unsubscribe, recording each one as it completes.
///
/// Stops between senders when the observer asks it to, returning the results
/// it has. A short list is how the caller learns the run was cancelled.
fn attempt_unsubscribes(
    plan: &RunPlan,
    ctx: &RunContext<'_>,
    policy: &RunPolicy,
) -> Vec<UnsubscribeResult> {
    ctx.observer
        .on_unsubscribe_start(plan.to_unsubscribe.len() as u32);

    plan.to_unsubscribe
        .iter()
        // Checked before each attempt, never during one: a request already
        // sent is evidence and has to be recorded.
        .take_while(|_| !ctx.observer.should_cancel())
        .map(|planned| {
            let sender = &planned.sender;
            let result = if policy.dry_run {
                dry_run_result(planned)
            } else {
                match &planned.step {
                    // Nothing has been ignored yet, so the sender gets the full
                    // flow with its within-attempt fallbacks.
                    NextStep::FirstAttempt => {
                        unsubscribe_sender(sender, ctx.http, ctx.email_sender)
                    }
                    // Escalating means trying the thing that has not been tried,
                    // so this rung and no other.
                    NextStep::Escalate(escalation) => {
                        unsubscribe_via(sender, &escalation.rung, ctx.http, ctx.email_sender)
                    }
                    // Never planned into this list; nothing sensible to attempt.
                    NextStep::Exhausted => no_rung_left(sender),
                }
            };

            // An attempt's timestamp is "now" and cannot be backfilled, so it
            // is written before anything else happens. The history is evidence,
            // not a prerequisite: an unavailable one costs the record, not the
            // unsubscribe. A dry run records nothing, having done nothing.
            if let Some(history) = ctx.history.filter(|_| !policy.dry_run) {
                let attempt = UnsubscribeAttempt::from_result(
                    ctx.account,
                    sender,
                    &result,
                    now_unix_secs(),
                    planned
                        .escalation()
                        .and_then(|e| e.follows_attempt_id.clone()),
                );
                if let Err(e) = history.record_attempt(&attempt) {
                    ctx.observer
                        .on_warning(&RunWarning::AttemptNotRecorded(e.to_string()));
                }
            }

            ctx.observer.on_sender_result(planned, &result);
            result
        })
        .collect()
}

/// What a dry run reports in place of an attempt.
fn dry_run_result(planned: &PlannedSender) -> UnsubscribeResult {
    let url = match planned.escalation() {
        Some(escalation) => escalation.rung.target.clone(),
        None => planned
            .sender
            .best_unsubscribe_url()
            .unwrap_or_default()
            .to_string(),
    };
    UnsubscribeResult {
        email: planned.sender.email.clone(),
        method: UnsubscribeMethod::DryRun,
        success: true,
        detail: "Would unsubscribe".to_string(),
        url,
        http_status: None,
        final_url: None,
    }
}

/// Defensive: an exhausted sender should have been planned as archive-only.
fn no_rung_left(sender: &SenderInfo) -> UnsubscribeResult {
    UnsubscribeResult {
        email: sender.email.clone(),
        method: UnsubscribeMethod::None,
        success: false,
        detail: "No unsubscribe method left to try".to_string(),
        url: String::new(),
        http_status: None,
        final_url: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escalation::{Rung, RungMethod};
    use crate::history::UnsubscribeOutcome;
    use crate::ports::NoopProgress;
    use crate::types::{HttpResponse, MessageId, ScanResult, ScanWatermark};
    use anyhow::bail;
    use std::sync::{Arc, Mutex};

    const ACCOUNT: &str = "user@example.com";
    const DAY: i64 = 24 * 60 * 60;
    /// When the successful unsubscribe on record happened.
    const UNSUB: i64 = 1_700_000_000;
    const URL: &str = "https://acme.example.com/unsub?id=1";
    const MAILTO: &str = "mailto:unsub@acme.example.com";

    // -----------------------------------------------------------------------
    // A log of every port call, in the order the pipeline made them
    // -----------------------------------------------------------------------

    /// Ordered record of what the ports were asked to do.
    ///
    /// Only the mutating ports write here; the observer keeps its own record,
    /// so an empty log is exactly "the run changed nothing".
    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<String>>,
    }

    impl Recorder {
        fn note(&self, event: impl Into<String>) {
            self.events.lock().expect("log").push(event.into());
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().expect("log").clone()
        }

        fn first_at(&self, prefix: &str) -> Option<usize> {
            self.events().iter().position(|e| e.starts_with(prefix))
        }

        fn last_at(&self, prefix: &str) -> Option<usize> {
            self.events().iter().rposition(|e| e.starts_with(prefix))
        }

        fn count(&self, prefix: &str) -> usize {
            self.events()
                .iter()
                .filter(|e| e.starts_with(prefix))
                .count()
        }
    }

    type Log = Arc<Recorder>;

    // -----------------------------------------------------------------------
    // Mock ports
    // -----------------------------------------------------------------------

    struct MockProvider {
        log: Log,
        /// Taken on the first `scan` call; a second scan has nothing to return.
        scan_result: Mutex<Option<ScanResult>>,
        archive_fails: bool,
    }

    impl EmailProvider for MockProvider {
        fn scan(&self, _folders: &[Folder], _progress: &dyn ScanProgress) -> Result<ScanResult> {
            self.log.note("scan");
            self.scan_result
                .lock()
                .expect("scan result")
                .take()
                .ok_or_else(|| anyhow::anyhow!("no scan result configured"))
        }

        fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32> {
            self.log
                .note(format!("archive:{}:{}", destination, messages.len()));
            if self.archive_fails {
                bail!("mailbox refused the move");
            }
            Ok(messages.len() as u32)
        }
    }

    struct MockHttp {
        log: Log,
        status: u16,
        /// POSTs never reach the server, GETs still do.
        post_unreachable: bool,
    }

    impl MockHttp {
        fn respond(&self, verb: &str, url: &str) -> Result<HttpResponse> {
            self.log.note(format!("http_{verb}:{url}"));
            if verb == "post" && self.post_unreachable {
                bail!("connection reset");
            }
            Ok(HttpResponse {
                status: self.status,
                // No form and no link, so the flow takes the response at face
                // value instead of chasing a confirmation page.
                body: "<html><body>You are unsubscribed.</body></html>".to_string(),
                final_url: Some(url.to_string()),
            })
        }
    }

    impl HttpClient for MockHttp {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.respond("get", url)
        }
        fn get_with_headers(&self, url: &str, _headers: &[(&str, &str)]) -> Result<HttpResponse> {
            self.respond("get", url)
        }
        fn post_form(&self, url: &str, _params: &[(&str, &str)]) -> Result<HttpResponse> {
            self.respond("post", url)
        }
        fn post_body(&self, url: &str, _ct: &str, _body: &str) -> Result<HttpResponse> {
            self.respond("post", url)
        }
        fn post_body_with_headers(
            &self,
            url: &str,
            _ct: &str,
            _body: &str,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse> {
            self.respond("post", url)
        }
    }

    struct MockEmailSender {
        log: Log,
    }

    impl EmailSender for MockEmailSender {
        fn send_email(&self, to: &str, _subject: &str, _body: &str) -> Result<()> {
            self.log.note(format!("send_email:{to}"));
            Ok(())
        }
    }

    struct MockHistory {
        log: Log,
        attempts: Mutex<Vec<UnsubscribeAttempt>>,
        resumptions: Mutex<Vec<Resumption>>,
        record_attempt_fails: bool,
        record_resumption_fails: bool,
    }

    impl MockHistory {
        fn recorded_attempts(&self) -> Vec<UnsubscribeAttempt> {
            self.attempts.lock().expect("attempts").clone()
        }

        fn recorded_resumptions(&self) -> Vec<Resumption> {
            self.resumptions.lock().expect("resumptions").clone()
        }
    }

    impl HistoryStore for MockHistory {
        fn record_attempt(&self, attempt: &UnsubscribeAttempt) -> Result<()> {
            self.log.note(format!("record_attempt:{}", attempt.sender_email));
            if self.record_attempt_fails {
                bail!("history database is locked");
            }
            self.attempts.lock().expect("attempts").push(attempt.clone());
            Ok(())
        }

        fn attempts_for_account(&self, _account: &str) -> Result<Vec<UnsubscribeAttempt>> {
            Ok(self.recorded_attempts())
        }

        fn record_resumption(&self, resumption: &Resumption) -> Result<()> {
            self.log
                .note(format!("record_resumption:{}", resumption.attempt_id));
            if self.record_resumption_fails {
                bail!("history database is locked");
            }
            self.resumptions
                .lock()
                .expect("resumptions")
                .push(resumption.clone());
            Ok(())
        }

        fn resumptions_for_account(&self, _account: &str) -> Result<Vec<Resumption>> {
            Ok(self.recorded_resumptions())
        }
    }

    struct MockCache {
        log: Log,
        cached: Mutex<Option<CachedScan>>,
        read_fails: bool,
        write_fails: bool,
        prune_fails: bool,
        pruned: Mutex<Vec<String>>,
    }

    impl MockCache {
        fn pruned(&self) -> Vec<String> {
            self.pruned.lock().expect("pruned").clone()
        }

        fn written(&self) -> Option<CachedScan> {
            self.cached.lock().expect("cached").clone()
        }
    }

    impl ScanCacheStore for MockCache {
        fn read_scan_cache(&self, _account: &str) -> Result<Option<CachedScan>> {
            if self.read_fails {
                bail!("cache file is corrupt");
            }
            Ok(self.cached.lock().expect("cached").clone())
        }

        fn write_scan_cache(&self, cache: &CachedScan) -> Result<()> {
            self.log.note("write_scan_cache");
            if self.write_fails {
                bail!("data directory is read-only");
            }
            *self.cached.lock().expect("cached") = Some(cache.clone());
            Ok(())
        }

        fn remove_cached_senders(&self, _account: &str, sender_emails: &[String]) -> Result<()> {
            self.log.note(format!("prune:{}", sender_emails.len()));
            if self.prune_fails {
                bail!("cache file is locked");
            }
            self.pruned
                .lock()
                .expect("pruned")
                .extend(sender_emails.iter().cloned());
            Ok(())
        }
    }

    struct MockWarnings {
        log: Log,
        written: Mutex<Vec<String>>,
        fails: bool,
    }

    impl DataStore for MockWarnings {
        fn write_warnings(&self, warnings: &[String]) -> Result<()> {
            self.log.note("write_warnings");
            if self.fails {
                bail!("data directory is read-only");
            }
            *self.written.lock().expect("warnings") = warnings.to_vec();
            Ok(())
        }

        fn read_warnings(&self) -> Result<Vec<String>> {
            Ok(self.written.lock().expect("warnings").clone())
        }
    }

    /// Observer that keeps what it was told, out of the port log.
    #[derive(Default)]
    struct RecordingObserver {
        warnings: Mutex<Vec<RunWarning>>,
        calls: Mutex<Vec<String>>,
    }

    impl RecordingObserver {
        fn warnings(&self) -> Vec<RunWarning> {
            self.warnings.lock().expect("warnings").clone()
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls").clone()
        }
    }

    impl RunObserver for RecordingObserver {
        fn on_unsubscribe_start(&self, sender_count: u32) {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("unsubscribe_start:{sender_count}"));
        }
        fn on_sender_result(&self, planned: &PlannedSender, result: &UnsubscribeResult) {
            self.calls.lock().expect("calls").push(format!(
                "sender_result:{}:{}",
                planned.sender.email,
                result.method.as_id()
            ));
        }
        fn on_unsubscribe_done(&self, planned: &[PlannedSender], results: &[UnsubscribeResult]) {
            self.calls.lock().expect("calls").push(format!(
                "unsubscribe_done:{}:{}",
                planned.len(),
                results.len()
            ));
        }
        fn on_archive_start(&self, message_count: u32, email_count: u32) {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("archive_start:{message_count}:{email_count}"));
        }
        fn on_archive_done(&self, archived: u32) {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("archive_done:{archived}"));
        }
        fn on_warning(&self, warning: &RunWarning) {
            self.warnings
                .lock()
                .expect("warnings")
                .push(warning.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    struct Harness {
        log: Log,
        provider: MockProvider,
        http: MockHttp,
        email_sender: MockEmailSender,
        history: MockHistory,
        cache: MockCache,
        warnings_store: MockWarnings,
        observer: RecordingObserver,
        archive_folder: Folder,
    }

    impl Harness {
        fn new() -> Self {
            let log: Log = Arc::new(Recorder::default());
            Self {
                provider: MockProvider {
                    log: Arc::clone(&log),
                    scan_result: Mutex::new(None),
                    archive_fails: false,
                },
                http: MockHttp {
                    log: Arc::clone(&log),
                    status: 200,
                    post_unreachable: false,
                },
                email_sender: MockEmailSender {
                    log: Arc::clone(&log),
                },
                history: MockHistory {
                    log: Arc::clone(&log),
                    attempts: Mutex::new(Vec::new()),
                    resumptions: Mutex::new(Vec::new()),
                    record_attempt_fails: false,
                    record_resumption_fails: false,
                },
                cache: MockCache {
                    log: Arc::clone(&log),
                    cached: Mutex::new(None),
                    read_fails: false,
                    write_fails: false,
                    prune_fails: false,
                    pruned: Mutex::new(Vec::new()),
                },
                warnings_store: MockWarnings {
                    log: Arc::clone(&log),
                    written: Mutex::new(Vec::new()),
                    fails: false,
                },
                observer: RecordingObserver::default(),
                archive_folder: Folder::new("Unsubscribed"),
                log,
            }
        }

        fn ctx(&self) -> RunContext<'_> {
            RunContext {
                account: ACCOUNT,
                archive_folder: &self.archive_folder,
                provider: &self.provider,
                http: &self.http,
                email_sender: Some(&self.email_sender),
                history: Some(&self.history),
                cache: &self.cache,
                observer: &self.observer,
            }
        }

        fn ctx_without_history(&self) -> RunContext<'_> {
            RunContext {
                history: None,
                ..self.ctx()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn policy(dry_run: bool) -> RunPolicy {
        RunPolicy {
            min_emails: 1,
            stale_after_months: 12,
            grace_period_days: 14,
            dry_run,
        }
    }

    /// A sender with one HTTP target, one mailto target, and `messages` messages.
    fn sender(email: &str, messages: u32, last_seen: Option<i64>) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec![URL.to_string()],
            unsubscribe_mailto: vec![MAILTO.to_string()],
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: messages,
            messages: (0..messages)
                .map(|i| FolderMessage {
                    folder: Folder::new("INBOX"),
                    message_id: MessageId::new(format!("INBOX:{email}:{i}")),
                })
                .collect(),
            last_seen,
        }
    }

    fn attempt(id: &str, sender_email: &str, at: i64, method: UnsubscribeMethod) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: ACCOUNT.to_string(),
            sender_email: sender_email.to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: None,
            attempted_at: at,
            method: method.as_id().to_string(),
            success: true,
            http_status: Some(200),
            url: URL.to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        }
    }

    /// The same attempt, aimed at a target other than the default HTTP one.
    ///
    /// A rung is identified by its target, so a mailto attempt has to record
    /// the `mailto:` URI it used or it spends a rung nothing climbed.
    fn attempt_to(
        id: &str,
        sender_email: &str,
        at: i64,
        method: UnsubscribeMethod,
        url: &str,
    ) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            url: url.to_string(),
            ..attempt(id, sender_email, at, method)
        }
    }

    fn resumption(attempt_id: &str, sender_email: &str) -> Resumption {
        Resumption {
            id: format!("res-{attempt_id}"),
            account: ACCOUNT.to_string(),
            sender_email: sender_email.to_string(),
            list_id: None,
            attempt_id: attempt_id.to_string(),
            observed_at: UNSUB + 40 * DAY,
            last_seen: UNSUB + 39 * DAY,
            email_count: 2,
        }
    }

    /// A plan that unsubscribes from one first-time sender with 2 messages.
    fn simple_plan() -> RunPlan {
        plan_run(
            vec![sender("news@acme.example.com", 2, Some(UNSUB))],
            &[],
            &[],
            &policy(false),
            UNSUB,
        )
    }

    // -----------------------------------------------------------------------
    // is_stale
    // -----------------------------------------------------------------------

    #[test]
    fn a_sender_seen_inside_the_threshold_is_not_stale() {
        let now = UNSUB + 400 * DAY;
        assert!(!is_stale(
            &sender("news@acme.example.com", 1, Some(now - 30 * DAY)),
            12,
            now
        ));
    }

    #[test]
    fn twelve_months_of_staleness_is_exactly_one_year() {
        // A sender last seen 365 days ago is on the line, not over it.
        let now = UNSUB + 1_000 * DAY;
        let on_the_line = sender("news@acme.example.com", 1, Some(now - 365 * DAY));
        let one_second_older = sender("news@acme.example.com", 1, Some(now - 365 * DAY - 1));

        assert!(!is_stale(&on_the_line, 12, now));
        assert!(is_stale(&one_second_older, 12, now));
    }

    #[test]
    fn a_sender_the_adapter_could_not_date_is_never_stale() {
        assert!(!is_stale(
            &sender("news@acme.example.com", 1, None),
            1,
            UNSUB + 10_000 * DAY
        ));
    }

    // -----------------------------------------------------------------------
    // Stage 1: load_cached_senders
    // -----------------------------------------------------------------------

    fn cached_scan(senders: Vec<SenderInfo>) -> CachedScan {
        CachedScan {
            meta: CacheMeta {
                scanned_at: "2026-03-18T19:30:00Z".to_string(),
                format_version: 1,
                account: ACCOUNT.to_string(),
            },
            senders,
            watermark: ScanWatermark::default(),
        }
    }

    #[test]
    fn cached_senders_come_back_with_the_timestamp_of_the_scan_behind_them() {
        let h = Harness::new();
        *h.cache.cached.lock().expect("cached") =
            Some(cached_scan(vec![sender("news@acme.example.com", 3, None)]));

        let obtained =
            load_cached_senders(&h.cache, ACCOUNT, 1, &h.observer).expect("cache offers senders");

        assert!(obtained.from_cache);
        assert_eq!(obtained.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(obtained.senders.len(), 1);
        assert!(obtained.warnings.is_empty());
    }

    #[test]
    fn a_cache_whose_senders_all_fall_below_the_minimum_offers_nothing() {
        let h = Harness::new();
        *h.cache.cached.lock().expect("cached") =
            Some(cached_scan(vec![sender("news@acme.example.com", 2, None)]));

        assert!(load_cached_senders(&h.cache, ACCOUNT, 3, &h.observer).is_none());
        assert!(h.observer.warnings().is_empty(), "nothing went wrong");
    }

    #[test]
    fn an_empty_cache_offers_nothing_and_is_not_a_problem() {
        let h = Harness::new();

        assert!(load_cached_senders(&h.cache, ACCOUNT, 1, &h.observer).is_none());
        assert!(h.observer.warnings().is_empty());
    }

    #[test]
    fn an_unreadable_cache_is_reported_and_then_treated_as_absent() {
        let mut h = Harness::new();
        h.cache.read_fails = true;

        assert!(load_cached_senders(&h.cache, ACCOUNT, 1, &h.observer).is_none());
        assert!(matches!(
            h.observer.warnings().as_slice(),
            [RunWarning::CacheUnreadable(_)]
        ));
    }

    // -----------------------------------------------------------------------
    // Stage 1: scan_senders
    // -----------------------------------------------------------------------

    fn scan_result(senders: Vec<SenderInfo>, warnings: Vec<String>) -> ScanResult {
        ScanResult {
            senders,
            warnings,
            watermark: ScanWatermark {
                adapter_state: Some("history-id-42".to_string()),
                ..ScanWatermark::default()
            },
        }
    }

    fn run_scan(h: &Harness) -> Result<ObtainedSenders> {
        scan_senders(
            ACCOUNT,
            &[Folder::new("INBOX")],
            &h.provider,
            &h.cache,
            &h.warnings_store,
            3,
            "2026-03-18T19:30:00Z",
            &NoopProgress,
            &h.observer,
        )
    }

    #[test]
    fn a_scan_caches_every_sender_it_found_but_returns_only_those_above_the_minimum() {
        // Filtering is a presentation choice; the cache keeps the whole scan so
        // lowering `min_emails` later does not force a rescan.
        let h = Harness::new();
        *h.provider.scan_result.lock().expect("scan") = Some(scan_result(
            vec![
                sender("big@acme.example.com", 9, None),
                sender("small@acme.example.com", 1, None),
            ],
            vec![],
        ));

        let obtained = run_scan(&h).expect("scan");

        assert_eq!(
            obtained
                .senders
                .iter()
                .map(|s| s.email.as_str())
                .collect::<Vec<_>>(),
            ["big@acme.example.com"]
        );
        let cached = h.cache.written().expect("cache written");
        assert_eq!(cached.senders.len(), 2);
        assert!(!obtained.from_cache);
        assert_eq!(obtained.scanned_at, "2026-03-18T19:30:00Z");
    }

    #[test]
    fn a_scan_persists_its_warnings_and_hands_them_back() {
        let h = Harness::new();
        *h.provider.scan_result.lock().expect("scan") = Some(scan_result(
            vec![sender("big@acme.example.com", 9, None)],
            vec!["unparseable List-Unsubscribe from x@y".to_string()],
        ));

        let obtained = run_scan(&h).expect("scan");

        assert_eq!(obtained.warnings, ["unparseable List-Unsubscribe from x@y"]);
        assert_eq!(
            h.warnings_store.read_warnings().expect("read"),
            ["unparseable List-Unsubscribe from x@y"]
        );
    }

    #[test]
    fn the_cache_carries_the_adapters_own_watermark() {
        let h = Harness::new();
        *h.provider.scan_result.lock().expect("scan") =
            Some(scan_result(vec![sender("big@acme.example.com", 9, None)], vec![]));

        run_scan(&h).expect("scan");

        assert_eq!(
            h.cache
                .written()
                .expect("cache written")
                .watermark
                .adapter_state
                .as_deref(),
            Some("history-id-42")
        );
    }

    #[test]
    fn a_cache_that_cannot_be_written_warns_and_the_senders_still_come_back() {
        let mut h = Harness::new();
        h.cache.write_fails = true;
        *h.provider.scan_result.lock().expect("scan") =
            Some(scan_result(vec![sender("big@acme.example.com", 9, None)], vec![]));

        let obtained = run_scan(&h).expect("the scan itself succeeded");

        assert_eq!(obtained.senders.len(), 1);
        assert!(matches!(
            h.observer.warnings().as_slice(),
            [RunWarning::CacheNotWritten(_)]
        ));
    }

    #[test]
    fn a_data_directory_that_cannot_hold_warnings_fails_the_scan() {
        // Unlike the cache, this is not a lost convenience: nothing the run
        // writes afterwards would land either.
        let mut h = Harness::new();
        h.warnings_store.fails = true;
        *h.provider.scan_result.lock().expect("scan") =
            Some(scan_result(vec![sender("big@acme.example.com", 9, None)], vec![]));

        assert!(run_scan(&h).is_err());
        assert_eq!(h.log.count("write_scan_cache"), 0, "no cache was written");
    }

    // -----------------------------------------------------------------------
    // Stage 2: annotate_senders
    // -----------------------------------------------------------------------

    #[test]
    fn annotating_splits_senders_into_previously_unsubscribed_active_and_stale() {
        let now = UNSUB + 500 * DAY;
        let senders = vec![
            sender("known@acme.example.com", 2, Some(now - DAY)),
            sender("fresh@acme.example.com", 2, Some(now - DAY)),
            sender("old@acme.example.com", 2, Some(now - 400 * DAY)),
        ];
        let attempts = vec![attempt(
            "a1",
            "known@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];

        let annotated =
            annotate_senders(ACCOUNT, senders, &attempts, &[], &policy(false), now);

        assert_eq!(
            annotated
                .previously_unsubscribed
                .iter()
                .map(|p| p.sender.email.as_str())
                .collect::<Vec<_>>(),
            ["known@acme.example.com"]
        );
        assert_eq!(
            annotated.active.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["fresh@acme.example.com"]
        );
        assert_eq!(
            annotated.stale.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["old@acme.example.com"]
        );
        assert_eq!(annotated.total(), 3);
    }

    #[test]
    fn a_previously_unsubscribed_sender_stays_in_its_own_group_even_when_stale() {
        // That it came back at all is the interesting part; burying it among
        // the stale senders would hide the violation.
        let now = UNSUB + 900 * DAY;
        let senders = vec![sender("known@acme.example.com", 2, Some(UNSUB + 60 * DAY))];
        let attempts = vec![attempt(
            "a1",
            "known@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];

        let annotated =
            annotate_senders(ACCOUNT, senders, &attempts, &[], &policy(false), now);

        assert_eq!(annotated.previously_unsubscribed.len(), 1);
        assert!(annotated.stale.is_empty());
    }

    #[test]
    fn a_sender_caught_resuming_right_now_is_judged_against_that_observation() {
        // "Observe, then judge": the run that catches a sender must already
        // treat the ignored rung as spent, or it repeats the request that was
        // just shown not to work.
        let now = UNSUB + 60 * DAY;
        let senders = vec![sender("news@acme.example.com", 2, Some(UNSUB + 50 * DAY))];
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];

        let annotated =
            annotate_senders(ACCOUNT, senders, &attempts, &[], &policy(false), now);

        let verdict = &annotated.previously_unsubscribed[0].verdict;
        assert!(matches!(
            verdict.outcome,
            UnsubscribeOutcome::Resumed { .. }
        ));
        assert_eq!(
            verdict.next_step,
            NextStep::Escalate(Escalation {
                rung: Rung::new(RungMethod::HttpFlow, URL),
                from: Some(RungMethod::OneClickPost),
                follows_attempt_id: Some("a1".to_string()),
            })
        );
    }

    #[test]
    fn annotating_offers_the_observation_it_turned_up_for_recording() {
        let now = UNSUB + 60 * DAY;
        let senders = vec![sender("news@acme.example.com", 2, Some(UNSUB + 50 * DAY))];
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];

        let annotated =
            annotate_senders(ACCOUNT, senders, &attempts, &[], &policy(false), now);

        assert_eq!(annotated.new_resumptions.len(), 1);
        assert_eq!(annotated.new_resumptions[0].attempt_id, "a1");
        assert_eq!(annotated.resumed().count(), 1);
    }

    #[test]
    fn an_observation_already_on_record_is_not_offered_again() {
        let now = UNSUB + 60 * DAY;
        let senders = vec![sender("news@acme.example.com", 2, Some(UNSUB + 50 * DAY))];
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let known = vec![resumption("a1", "news@acme.example.com")];

        let annotated =
            annotate_senders(ACCOUNT, senders, &attempts, &known, &policy(false), now);

        assert!(annotated.new_resumptions.is_empty());
        assert_eq!(annotated.resumed().count(), 1, "it is still a violation");
    }

    // -----------------------------------------------------------------------
    // Stage 2: record_resumptions
    // -----------------------------------------------------------------------

    fn annotated_with_one_resumption() -> AnnotatedSenders {
        let now = UNSUB + 60 * DAY;
        annotate_senders(
            ACCOUNT,
            vec![sender("news@acme.example.com", 2, Some(UNSUB + 50 * DAY))],
            &[attempt(
                "a1",
                "news@acme.example.com",
                UNSUB,
                UnsubscribeMethod::OneClickPost,
            )],
            &[],
            &policy(false),
            now,
        )
    }

    #[test]
    fn every_new_observation_is_written_to_the_history() {
        let h = Harness::new();
        let annotated = annotated_with_one_resumption();

        record_resumptions(&annotated, Some(&h.history), &policy(false), &h.observer);

        assert_eq!(
            h.history
                .recorded_resumptions()
                .iter()
                .map(|r| r.attempt_id.as_str())
                .collect::<Vec<_>>(),
            ["a1"]
        );
    }

    #[test]
    fn a_dry_run_records_no_observation() {
        let h = Harness::new();
        let annotated = annotated_with_one_resumption();

        record_resumptions(&annotated, Some(&h.history), &policy(true), &h.observer);

        assert!(h.log.events().is_empty(), "nothing was asked of any port");
    }

    #[test]
    fn a_run_without_a_history_store_records_no_observation_and_does_not_complain() {
        let h = Harness::new();
        let annotated = annotated_with_one_resumption();

        record_resumptions(&annotated, None, &policy(false), &h.observer);

        assert!(h.observer.warnings().is_empty());
    }

    #[test]
    fn an_observation_that_cannot_be_written_surfaces_as_a_warning() {
        let mut h = Harness::new();
        h.history.record_resumption_fails = true;
        let annotated = annotated_with_one_resumption();

        record_resumptions(&annotated, Some(&h.history), &policy(false), &h.observer);

        assert!(matches!(
            h.observer.warnings().as_slice(),
            [RunWarning::ResumptionNotRecorded(_)]
        ));
    }

    // -----------------------------------------------------------------------
    // Stage 3: plan_run
    // -----------------------------------------------------------------------

    #[test]
    fn a_stale_sender_is_archived_without_being_asked_to_stop() {
        let now = UNSUB + 900 * DAY;
        let plan = plan_run(
            vec![sender("old@acme.example.com", 4, Some(UNSUB))],
            &[],
            &[],
            &policy(false),
            now,
        );

        assert!(plan.to_unsubscribe.is_empty());
        assert_eq!(plan.archive_only.len(), 1);
        assert!(plan.exhausted.is_empty());
        assert_eq!(plan.archive_only_emails(), 4);
    }

    #[test]
    fn a_sender_with_nothing_left_to_try_is_archived_and_named_separately() {
        let now = UNSUB + 60 * DAY;
        let scanned = sender("news@acme.example.com", 4, Some(UNSUB + 50 * DAY));
        let attempts = vec![
            attempt("a1", "news@acme.example.com", UNSUB, UnsubscribeMethod::OneClickPost),
            attempt("a2", "news@acme.example.com", UNSUB + 10 * DAY, UnsubscribeMethod::Get),
            attempt_to(
                "a3",
                "news@acme.example.com",
                UNSUB + 20 * DAY,
                UnsubscribeMethod::MailtoSent,
                MAILTO,
            ),
        ];
        let resumptions = vec![
            resumption("a1", "news@acme.example.com"),
            resumption("a2", "news@acme.example.com"),
            resumption("a3", "news@acme.example.com"),
        ];

        let plan = plan_run(vec![scanned], &attempts, &resumptions, &policy(false), now);

        assert!(plan.to_unsubscribe.is_empty());
        assert!(plan.archive_only.is_empty());
        assert_eq!(plan.exhausted.len(), 1);
        assert_eq!(plan.exhausted_emails(), 4);
    }

    #[test]
    fn staleness_is_decided_before_the_ladder_is_consulted() {
        // A sender that stopped mailing a year ago is not worth poking a
        // tracking URL for, whatever its history says it could still try.
        let now = UNSUB + 900 * DAY;
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let resumptions = vec![resumption("a1", "news@acme.example.com")];

        let plan = plan_run(
            vec![sender("news@acme.example.com", 4, Some(UNSUB))],
            &attempts,
            &resumptions,
            &policy(false),
            now,
        );

        assert_eq!(plan.archive_only.len(), 1);
        assert!(plan.to_unsubscribe.is_empty());
    }

    #[test]
    fn a_plan_told_about_a_fresh_observation_escalates_past_the_ignored_rung() {
        // What `run` does: annotate, then hand `plan_run` the history's
        // resumptions *plus* the ones just observed.
        let now = UNSUB + 60 * DAY;
        let scanned = sender("news@acme.example.com", 2, Some(UNSUB + 50 * DAY));
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let annotated = annotate_senders(
            ACCOUNT,
            vec![scanned.clone()],
            &attempts,
            &[],
            &policy(false),
            now,
        );

        let plan = plan_run(
            vec![scanned],
            &attempts,
            &annotated.new_resumptions,
            &policy(false),
            now,
        );

        assert_eq!(plan.to_unsubscribe.len(), 1);
        assert_eq!(
            plan.to_unsubscribe[0].escalation().map(|e| &e.rung),
            Some(&Rung::new(RungMethod::HttpFlow, URL))
        );
    }

    #[test]
    fn each_group_keeps_the_order_the_senders_were_selected_in() {
        let now = UNSUB + 900 * DAY;
        let selected = vec![
            sender("active-1@acme.example.com", 1, Some(now)),
            sender("stale-1@acme.example.com", 1, Some(UNSUB)),
            sender("active-2@acme.example.com", 1, Some(now)),
            sender("stale-2@acme.example.com", 1, Some(UNSUB)),
        ];

        let plan = plan_run(selected, &[], &[], &policy(false), now);

        assert_eq!(
            plan.to_unsubscribe
                .iter()
                .map(|p| p.sender.email.as_str())
                .collect::<Vec<_>>(),
            ["active-1@acme.example.com", "active-2@acme.example.com"]
        );
        assert_eq!(
            plan.archive_only.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["stale-1@acme.example.com", "stale-2@acme.example.com"]
        );
    }

    #[test]
    fn the_archive_moves_the_messages_of_every_group() {
        let now = UNSUB + 900 * DAY;
        let selected = vec![
            sender("active@acme.example.com", 2, Some(now)),
            sender("stale@acme.example.com", 3, Some(UNSUB)),
        ];

        let plan = plan_run(selected, &[], &[], &policy(false), now);

        assert_eq!(plan.archive_messages().len(), 5);
        assert_eq!(plan.total_emails(), 5);
        assert_eq!(
            plan.archived_sender_emails(),
            ["active@acme.example.com", "stale@acme.example.com"]
        );
        assert!(!plan.is_empty());
    }

    #[test]
    fn a_plan_with_nothing_selected_does_nothing() {
        let plan = plan_run(vec![], &[], &[], &policy(false), UNSUB);

        assert!(plan.is_empty());
        assert_eq!(plan.total_emails(), 0);
        assert!(plan.archive_messages().is_empty());
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- ordering
    // -----------------------------------------------------------------------

    #[test]
    fn every_attempt_is_recorded_before_the_archive_moves_anything() {
        // An archive failure must cost the mail move and never the evidence.
        let h = Harness::new();
        let plan = plan_run(
            vec![
                sender("one@acme.example.com", 1, Some(UNSUB)),
                sender("two@acme.example.com", 1, Some(UNSUB)),
            ],
            &[],
            &[],
            &policy(false),
            UNSUB,
        );

        let _outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        let last_record = h.log.last_at("record_attempt:").expect("attempts recorded");
        let archive = h.log.first_at("archive:").expect("archive ran");
        assert_eq!(h.log.count("record_attempt:"), 2);
        assert!(
            last_record < archive,
            "attempts must be written before the archive: {:?}",
            h.log.events()
        );
    }

    #[test]
    fn the_cache_is_pruned_only_after_the_archive_has_succeeded() {
        let h = Harness::new();

        let _outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        let archive = h.log.first_at("archive:").expect("archive ran");
        let prune = h.log.first_at("prune:").expect("cache pruned");
        assert!(archive < prune, "{:?}", h.log.events());
        assert_eq!(h.cache.pruned(), ["news@acme.example.com"]);
    }

    #[test]
    fn the_archive_is_told_which_folder_to_move_the_messages_into() {
        let h = Harness::new();

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert!(h.log.events().contains(&"archive:Unsubscribed:2".to_string()));
        assert_eq!(outcome.archived, 2);
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- archive failure
    // -----------------------------------------------------------------------

    #[test]
    fn an_archive_failure_leaves_the_recorded_attempts_in_place() {
        let mut h = Harness::new();
        h.provider.archive_fails = true;

        let failed = execute_run(&simple_plan(), &h.ctx(), &policy(false));

        assert!(failed.is_err());
        assert_eq!(h.history.recorded_attempts().len(), 1);
    }

    #[test]
    fn an_archive_failure_leaves_the_cache_unpruned() {
        // The messages did not move, so the cached ids still point at them.
        let mut h = Harness::new();
        h.provider.archive_fails = true;

        let _ = execute_run(&simple_plan(), &h.ctx(), &policy(false));

        assert_eq!(h.log.count("prune:"), 0);
        assert!(h.cache.pruned().is_empty());
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- dry run
    // -----------------------------------------------------------------------

    #[test]
    fn a_dry_run_calls_no_mutating_port_method() {
        let h = Harness::new();

        let _outcome = execute_run(&simple_plan(), &h.ctx(), &policy(true)).expect("run");

        assert!(
            h.log.events().is_empty(),
            "a dry run must touch nothing: {:?}",
            h.log.events()
        );
    }

    #[test]
    fn a_dry_run_still_reports_what_it_would_have_moved() {
        let h = Harness::new();

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(true)).expect("run");

        assert_eq!(outcome.archived, 2);
        assert_eq!(outcome.succeeded(), 1);
        assert_eq!(outcome.failed(), 0);
        assert_eq!(outcome.results[0].method, UnsubscribeMethod::DryRun);
    }

    #[test]
    fn a_dry_run_names_the_rung_it_would_have_climbed() {
        let h = Harness::new();
        let now = UNSUB + 60 * DAY;
        let scanned = sender("news@acme.example.com", 1, Some(UNSUB + 50 * DAY));
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let resumptions = vec![resumption("a1", "news@acme.example.com")];
        let plan = plan_run(vec![scanned], &attempts, &resumptions, &policy(true), now);

        let outcome = execute_run(&plan, &h.ctx(), &policy(true)).expect("run");

        assert_eq!(outcome.results[0].url, URL);
        assert_eq!(outcome.results[0].detail, "Would unsubscribe");
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- non-fatal failures
    // -----------------------------------------------------------------------

    #[test]
    fn a_history_that_cannot_be_written_warns_and_the_run_carries_on() {
        // The unsubscribe happened; only the evidence for it was lost.
        let mut h = Harness::new();
        h.history.record_attempt_fails = true;

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert!(matches!(
            h.observer.warnings().as_slice(),
            [RunWarning::AttemptNotRecorded(_)]
        ));
        assert_eq!(outcome.archived, 2);
        assert_eq!(outcome.succeeded(), 1);
    }

    #[test]
    fn a_cache_that_cannot_be_pruned_warns_and_the_run_still_succeeds() {
        let mut h = Harness::new();
        h.cache.prune_fails = true;

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert!(matches!(
            h.observer.warnings().as_slice(),
            [RunWarning::CacheNotPruned(_)]
        ));
        assert_eq!(outcome.archived, 2);
    }

    #[test]
    fn a_run_without_a_history_store_still_unsubscribes_and_archives() {
        let h = Harness::new();

        let outcome =
            execute_run(&simple_plan(), &h.ctx_without_history(), &policy(false)).expect("run");

        assert_eq!(h.log.count("record_attempt:"), 0);
        assert!(h.observer.warnings().is_empty());
        assert_eq!(outcome.archived, 2);
        assert_eq!(outcome.succeeded(), 1);
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- what gets attempted
    // -----------------------------------------------------------------------

    #[test]
    fn a_first_attempt_runs_the_whole_flow() {
        let h = Harness::new();

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.results[0].method, UnsubscribeMethod::OneClickPost);
        assert_eq!(h.log.count(&format!("http_post:{URL}")), 1);
    }

    #[test]
    fn a_first_attempt_falls_back_within_itself_when_the_post_cannot_be_made() {
        // Nothing has been tried and ignored, so narrowing the attempt would
        // lose the fallback the full flow has always had.
        let mut h = Harness::new();
        h.http.post_unreachable = true;

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.results[0].method, UnsubscribeMethod::Get);
        assert!(outcome.results[0].success);
        assert_eq!(h.log.count(&format!("http_get:{URL}")), 1);
    }

    #[test]
    fn an_escalation_to_an_unreachable_post_fails_rather_than_becoming_a_get() {
        // Falling back here would land on the GET rung, which the escalation
        // may have skipped on purpose.
        let mut h = Harness::new();
        h.http.post_unreachable = true;
        // Two dead sends write the mailto rung off, leaving the one-click POST
        // as the first rung still worth trying.
        let attempts: Vec<UnsubscribeAttempt> = [UNSUB, UNSUB + DAY]
            .into_iter()
            .enumerate()
            .map(|(i, at)| UnsubscribeAttempt {
                success: false,
                ..attempt_to(
                    &format!("a{i}"),
                    "news@acme.example.com",
                    at,
                    UnsubscribeMethod::MailtoFailed,
                    MAILTO,
                )
            })
            .collect();
        let plan = plan_run(
            vec![sender("news@acme.example.com", 1, Some(UNSUB))],
            &attempts,
            &[],
            &policy(false),
            UNSUB + 2 * DAY,
        );
        assert_eq!(
            plan.to_unsubscribe[0].escalation().map(|e| e.rung.method),
            Some(RungMethod::OneClickPost),
            "guard: the broken mailto rung leaves the one-click POST next"
        );

        let outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.results[0].method, UnsubscribeMethod::OneClickPost);
        assert!(!outcome.results[0].success);
        assert_eq!(h.log.count("http_get:"), 0);
    }

    #[test]
    fn an_escalation_climbs_its_rung_and_no_other() {
        // Falling back would land on a rung the escalation may have skipped on
        // purpose, so the one-click POST must not be tried here.
        let h = Harness::new();
        let now = UNSUB + 60 * DAY;
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let resumptions = vec![resumption("a1", "news@acme.example.com")];
        let plan = plan_run(
            vec![sender("news@acme.example.com", 1, Some(UNSUB + 50 * DAY))],
            &attempts,
            &resumptions,
            &policy(false),
            now,
        );

        let outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.results[0].method, UnsubscribeMethod::Get);
        assert_eq!(h.log.count("http_post:"), 0);
        assert_eq!(h.log.count(&format!("http_get:{URL}")), 1);
    }

    #[test]
    fn an_escalated_attempt_is_recorded_against_the_attempt_it_answers() {
        let h = Harness::new();
        let now = UNSUB + 60 * DAY;
        let attempts = vec![attempt(
            "a1",
            "news@acme.example.com",
            UNSUB,
            UnsubscribeMethod::OneClickPost,
        )];
        let resumptions = vec![resumption("a1", "news@acme.example.com")];
        let plan = plan_run(
            vec![sender("news@acme.example.com", 1, Some(UNSUB + 50 * DAY))],
            &attempts,
            &resumptions,
            &policy(false),
            now,
        );

        let _outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        let recorded = h.history.recorded_attempts();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].follows_attempt_id.as_deref(), Some("a1"));
    }

    #[test]
    fn a_first_attempt_is_recorded_answering_nothing() {
        let h = Harness::new();

        let _outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert_eq!(h.history.recorded_attempts()[0].follows_attempt_id, None);
    }

    #[test]
    fn a_failed_unsubscribe_is_recorded_and_the_run_carries_on_to_the_archive() {
        let mut h = Harness::new();
        h.http.status = 500;

        let outcome = execute_run(&simple_plan(), &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.failed(), 1);
        assert!(!h.history.recorded_attempts()[0].success);
        assert_eq!(outcome.archived, 2);
    }

    #[test]
    fn an_exhausted_sender_that_reaches_the_attempt_list_is_not_asked_anything() {
        // `plan_run` never puts one here; if something else does, the run must
        // not invent a request to make.
        let h = Harness::new();
        let plan = RunPlan {
            to_unsubscribe: vec![PlannedSender {
                sender: sender("news@acme.example.com", 1, Some(UNSUB)),
                step: NextStep::Exhausted,
            }],
            ..RunPlan::default()
        };

        let outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        assert_eq!(outcome.results[0].method, UnsubscribeMethod::None);
        assert!(!outcome.results[0].success);
        assert_eq!(h.log.count("http_"), 0);
    }

    // -----------------------------------------------------------------------
    // Stage 4: execute_run -- what the observer is told
    // -----------------------------------------------------------------------

    #[test]
    fn the_observer_hears_each_phase_in_order_with_its_counts() {
        let h = Harness::new();
        let plan = plan_run(
            vec![
                sender("one@acme.example.com", 2, Some(UNSUB)),
                sender("two@acme.example.com", 3, Some(UNSUB)),
            ],
            &[],
            &[],
            &policy(false),
            UNSUB,
        );

        let _outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        assert_eq!(
            h.observer.calls(),
            [
                "unsubscribe_start:2",
                "sender_result:one@acme.example.com:one_click_post",
                "sender_result:two@acme.example.com:one_click_post",
                "unsubscribe_done:2:2",
                "archive_start:5:5",
                "archive_done:5",
            ]
        );
    }

    // -----------------------------------------------------------------------
    // Cancellation
    // -----------------------------------------------------------------------

    /// A progress reporter that has already been asked to stop.
    struct CancellingProgress;

    impl ScanProgress for CancellingProgress {
        fn on_folder_start(&self, _folder: &Folder, _total_messages: u32) {}
        fn on_messages_scanned(&self, _folder: &Folder, _count: u32) {}
        fn on_folder_done(&self, _folder: &Folder) {}
        fn should_cancel(&self) -> bool {
            true
        }
    }

    /// An observer that asks the run to stop once `after` senders have been
    /// attempted, the way a user pressing Esc part-way through does.
    struct CancelAfter {
        after: usize,
        attempted: Mutex<Vec<String>>,
    }

    impl CancelAfter {
        fn new(after: usize) -> Self {
            Self {
                after,
                attempted: Mutex::new(Vec::new()),
            }
        }

        fn attempted(&self) -> Vec<String> {
            self.attempted.lock().expect("attempted").clone()
        }
    }

    impl RunObserver for CancelAfter {
        fn on_unsubscribe_start(&self, _sender_count: u32) {}
        fn on_sender_result(&self, _planned: &PlannedSender, result: &UnsubscribeResult) {
            self.attempted
                .lock()
                .expect("attempted")
                .push(result.email.clone());
        }
        fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}
        fn on_archive_start(&self, _message_count: u32, _email_count: u32) {}
        fn on_archive_done(&self, _archived: u32) {}
        fn on_warning(&self, _warning: &RunWarning) {}
        fn should_cancel(&self) -> bool {
            self.attempted.lock().expect("attempted").len() >= self.after
        }
    }

    fn cancelling_scan(h: &Harness) -> Result<ObtainedSenders> {
        scan_senders(
            ACCOUNT,
            &[Folder::new("INBOX")],
            &h.provider,
            &h.cache,
            &h.warnings_store,
            3,
            "2026-06-01T00:00:00Z",
            &CancellingProgress,
            &h.observer,
        )
    }

    #[test]
    fn a_cancelled_scan_reports_cancellation_rather_than_a_failure() {
        let h = Harness::new();
        *h.provider.scan_result.lock().expect("scan result") = Some(scan_result(
            vec![sender("news@acme.example.com", 5, None)],
            vec!["bad header".to_string()],
        ));

        let error = cancelling_scan(&h).expect_err("a cancelled scan yields no senders");

        assert!(is_cancelled(&error), "got {error:#}");
    }

    #[test]
    fn a_cancelled_scan_leaves_the_last_complete_scan_in_the_cache() {
        let h = Harness::new();
        let previous = cached_scan(vec![sender("old@acme.example.com", 9, None)]);
        *h.cache.cached.lock().expect("cached") = Some(previous.clone());
        *h.warnings_store.written.lock().expect("warnings") = vec!["older warning".to_string()];
        *h.provider.scan_result.lock().expect("scan result") = Some(scan_result(
            vec![sender("news@acme.example.com", 5, None)],
            vec!["newer warning".to_string()],
        ));

        let _ = cancelling_scan(&h).expect_err("cancelled");

        let still_cached = h.cache.written().expect("the previous cache is still there");
        assert_eq!(still_cached.meta.scanned_at, previous.meta.scanned_at);
        assert_eq!(still_cached.senders.len(), 1);
        assert_eq!(still_cached.senders[0].email, "old@acme.example.com");
        assert_eq!(
            h.warnings_store.read_warnings().expect("warnings"),
            ["older warning"],
            "the warnings of the last complete scan stand too"
        );
        assert_eq!(h.log.count("write_scan_cache"), 0);
        assert_eq!(h.log.count("write_warnings"), 0);
    }

    #[test]
    fn an_adapter_that_reports_its_abort_as_an_error_is_still_a_cancellation() {
        // The adapter was configured with no result, so `scan` fails. Because
        // the cancel flag is checked before the result is unwrapped, the user
        // is told the scan stopped, not that it broke.
        let h = Harness::new();

        let error = cancelling_scan(&h).expect_err("no scan result configured");

        assert!(is_cancelled(&error), "got {error:#}");
    }

    #[test]
    fn a_scan_nobody_cancelled_reports_an_adapter_failure_as_a_failure() {
        let h = Harness::new();

        let error = run_scan(&h).expect_err("no scan result configured");

        assert!(!is_cancelled(&error), "got {error:#}");
    }

    #[test]
    fn an_ordinary_failure_is_not_mistaken_for_a_cancellation() {
        assert!(!is_cancelled(&anyhow::anyhow!("mailbox refused the move")));
        assert!(is_cancelled(&anyhow::Error::from(Cancelled)));
    }

    /// Three first-time senders, two messages each.
    fn three_sender_plan() -> RunPlan {
        plan_run(
            vec![
                sender("one@acme.example.com", 2, Some(UNSUB)),
                sender("two@acme.example.com", 2, Some(UNSUB)),
                sender("three@acme.example.com", 2, Some(UNSUB)),
            ],
            &[],
            &[],
            &policy(false),
            UNSUB,
        )
    }

    #[test]
    fn a_run_cancelled_after_two_senders_attempts_those_two_and_stops() {
        let h = Harness::new();
        let observer = CancelAfter::new(2);
        let plan = three_sender_plan();

        let outcome = execute_run(
            &plan,
            &RunContext {
                observer: &observer,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("the archive still succeeds");

        assert!(outcome.cancelled);
        assert_eq!(
            observer.attempted(),
            ["one@acme.example.com", "two@acme.example.com"],
            "the third sender is never asked anything"
        );
        assert_eq!(outcome.results.len(), 2);
    }

    #[test]
    fn a_cancelled_run_keeps_the_evidence_of_the_attempts_it_made() {
        let h = Harness::new();
        let observer = CancelAfter::new(2);

        let _ = execute_run(
            &three_sender_plan(),
            &RunContext {
                observer: &observer,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("archive succeeds");

        let recorded: Vec<String> = h
            .history
            .recorded_attempts()
            .into_iter()
            .map(|attempt| attempt.sender_email)
            .collect();
        assert_eq!(
            recorded,
            ["one@acme.example.com", "two@acme.example.com"],
            "an attempt that was made is evidence and is on record"
        );
    }

    #[test]
    fn a_cancelled_run_archives_only_the_senders_it_handled() {
        let h = Harness::new();
        let observer = CancelAfter::new(2);

        let outcome = execute_run(
            &three_sender_plan(),
            &RunContext {
                observer: &observer,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("archive succeeds");

        // Two senders, two messages each: the third sender's mail stays put,
        // so the next run finds it exactly as this one did.
        assert_eq!(outcome.archived, 4);
        assert_eq!(h.log.count("archive:Unsubscribed:4"), 1);
        let mut pruned = h.cache.pruned();
        pruned.sort();
        assert_eq!(pruned, ["one@acme.example.com", "two@acme.example.com"]);
    }

    #[test]
    fn a_cancelled_run_leaves_stale_and_exhausted_senders_where_they_are() {
        // They were never handled: archiving them would be doing work the user
        // just asked to stop.
        let h = Harness::new();
        let observer = CancelAfter::new(1);
        let mut plan = three_sender_plan();
        plan.archive_only = vec![sender("stale@acme.example.com", 4, Some(UNSUB - 800 * DAY))];
        plan.exhausted = vec![SenderInfo {
            unsubscribe_urls: Vec::new(),
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            ..sender("spent@acme.example.com", 4, Some(UNSUB))
        }];

        let outcome = execute_run(
            &plan,
            &RunContext {
                observer: &observer,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("archive succeeds");

        assert_eq!(outcome.archived, 2, "only the one attempted sender moves");
        assert_eq!(h.cache.pruned(), ["one@acme.example.com"]);
    }

    #[test]
    fn a_run_cancelled_before_its_first_sender_opens_no_mailbox_connection() {
        let h = Harness::new();
        let observer = CancelAfter::new(0);

        let outcome = execute_run(
            &three_sender_plan(),
            &RunContext {
                observer: &observer,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("nothing to do is not a failure");

        assert!(outcome.cancelled);
        assert!(outcome.results.is_empty());
        assert_eq!(outcome.archived, 0);
        assert_eq!(
            h.log.count("archive:"),
            0,
            "no connection is opened to move nothing"
        );
        assert!(h.history.recorded_attempts().is_empty());
    }

    #[test]
    fn a_run_nobody_cancelled_is_not_reported_as_cancelled() {
        let h = Harness::new();
        let plan = three_sender_plan();

        let outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("archive succeeds");

        assert!(!outcome.cancelled);
        assert_eq!(outcome.results.len(), 3);
        assert_eq!(outcome.archived, 6);
    }

    #[test]
    fn a_default_observer_never_stops_a_run() {
        let h = Harness::new();
        let plan = three_sender_plan();

        let outcome = execute_run(
            &plan,
            &RunContext {
                observer: &NoopRunObserver,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("archive succeeds");

        assert!(!outcome.cancelled);
        assert_eq!(outcome.results.len(), 3);
    }

    #[test]
    fn the_observer_hears_the_short_attempt_list_a_cancelled_run_produced() {
        let h = Harness::new();
        let observer = RecordingObserver::default();
        // A separate observer decides the cancelling; this one only listens.
        let canceller = CancelAfter::new(1);
        let both = PairObserver {
            listener: &observer,
            canceller: &canceller,
        };

        let _ = execute_run(
            &three_sender_plan(),
            &RunContext {
                observer: &both,
                ..h.ctx()
            },
            &policy(false),
        )
        .expect("archive succeeds");

        assert!(
            observer.calls().contains(&"unsubscribe_done:1:1".to_string()),
            "planned and results are the same length, got {:?}",
            observer.calls()
        );
        assert!(observer.calls().contains(&"unsubscribe_start:3".to_string()));
    }

    /// Reports to one observer while a second decides when to stop.
    struct PairObserver<'a> {
        listener: &'a RecordingObserver,
        canceller: &'a CancelAfter,
    }

    impl RunObserver for PairObserver<'_> {
        fn on_unsubscribe_start(&self, sender_count: u32) {
            self.listener.on_unsubscribe_start(sender_count);
        }
        fn on_sender_result(&self, planned: &PlannedSender, result: &UnsubscribeResult) {
            self.listener.on_sender_result(planned, result);
            self.canceller.on_sender_result(planned, result);
        }
        fn on_unsubscribe_done(&self, planned: &[PlannedSender], results: &[UnsubscribeResult]) {
            self.listener.on_unsubscribe_done(planned, results);
        }
        fn on_archive_start(&self, message_count: u32, email_count: u32) {
            self.listener.on_archive_start(message_count, email_count);
        }
        fn on_archive_done(&self, archived: u32) {
            self.listener.on_archive_done(archived);
        }
        fn on_warning(&self, warning: &RunWarning) {
            self.listener.on_warning(warning);
        }
        fn should_cancel(&self) -> bool {
            self.canceller.should_cancel()
        }
    }

    #[test]
    fn a_run_with_nothing_to_unsubscribe_still_announces_the_phase() {
        // Zero is reported so the consumer decides for itself whether to print
        // a heading.
        let h = Harness::new();
        let now = UNSUB + 900 * DAY;
        let plan = plan_run(
            vec![sender("old@acme.example.com", 2, Some(UNSUB))],
            &[],
            &[],
            &policy(false),
            now,
        );

        let _outcome = execute_run(&plan, &h.ctx(), &policy(false)).expect("run");

        assert_eq!(h.observer.calls()[0], "unsubscribe_start:0");
    }
}
