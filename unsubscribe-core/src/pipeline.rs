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
    observed_resumptions, split_previously_unsubscribed, PreviouslyUnsubscribed, Resumption,
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

    let senders: Vec<_> = cached
        .senders
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
    let scan = provider.scan(folders, progress)?;

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
        senders: scan
            .senders
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
    /// One result per sender in [`RunPlan::to_unsubscribe`], in plan order.
    pub results: Vec<UnsubscribeResult>,
    /// Messages moved into the archive folder.
    pub archived: u32,
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
    ctx.observer
        .on_unsubscribe_done(&plan.to_unsubscribe, &results);

    let messages = plan.archive_messages();
    ctx.observer
        .on_archive_start(messages.len() as u32, plan.total_emails());

    // A dry run reports what the archive would move and moves nothing.
    let archived = if policy.dry_run {
        plan.total_emails()
    } else {
        ctx.provider.archive(&messages, ctx.archive_folder)?
    };
    ctx.observer.on_archive_done(archived);

    // The archived messages have moved, so the cached rows now point at ids
    // that are no longer where the cache says they are. Pruning also keeps a
    // sender that was just handled from reappearing on the next cached run.
    // Only a real archive prunes: a dry run changed nothing.
    if !policy.dry_run {
        let pruned = ctx
            .cache
            .remove_cached_senders(ctx.account, &plan.archived_sender_emails());
        if let Err(e) = pruned {
            ctx.observer
                .on_warning(&RunWarning::CacheNotPruned(e.to_string()));
        }
    }

    Ok(RunOutcome { results, archived })
}

/// Attempt every planned unsubscribe, recording each one as it completes.
fn attempt_unsubscribes(
    plan: &RunPlan,
    ctx: &RunContext<'_>,
    policy: &RunPolicy,
) -> Vec<UnsubscribeResult> {
    ctx.observer
        .on_unsubscribe_start(plan.to_unsubscribe.len() as u32);

    plan.to_unsubscribe
        .iter()
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
