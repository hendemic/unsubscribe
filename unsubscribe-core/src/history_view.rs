//! Reading the history back: one timeline per sender.
//!
//! The stores keep two append-only tables -- attempts and resumptions -- keyed
//! by nothing a person recognises. What anyone actually wants to see is one
//! sender at a time: when it was asked to stop, whether it did, and what is
//! left to try. Assembling that is a decision about identity and ordering, so
//! it lives here, pure, and both the `history` command and the TUI's History
//! screen render what it produces rather than each inventing its own grouping.
//!
//! Senders with history that the current scan did not turn up still appear.
//! That a sender has gone quiet is the most interesting thing the history can
//! say about it, and dropping it would hide exactly the evidence the records
//! exist for.

use crate::escalation::{next_step, NextStep};
use crate::history::{
    attempts_about, classify_outcome, judge_sender, normalized_list_id, resumptions_about,
    LatestAttempts, Resumption, UnsubscribeAttempt, UnsubscribeOutcome,
};
use crate::types::SenderInfo;

/// One entry of a sender's timeline, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineEvent {
    /// An unsubscribe was attempted.
    Attempt(UnsubscribeAttempt),
    /// The sender was seen mailing again after one succeeded.
    Resumption(Resumption),
}

impl TimelineEvent {
    /// When the event happened, in Unix seconds (UTC).
    #[must_use]
    pub fn at(&self) -> i64 {
        match self {
            Self::Attempt(attempt) => attempt.attempted_at,
            Self::Resumption(resumption) => resumption.observed_at,
        }
    }

    /// Stable identifier for the kind of event, for machine-readable output.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Attempt(_) => "attempt",
            Self::Resumption(_) => "resumption",
        }
    }
}

/// Everything the history shows about one sender.
#[derive(Debug, Clone)]
pub struct SenderHistoryView {
    pub sender_email: String,
    pub sender_domain: String,
    pub list_id: Option<String>,
    /// When this sender was last attempted, in Unix seconds (UTC).
    pub last_attempt_at: i64,
    /// Stable `UnsubscribeMethod` identifier of that attempt, never a label.
    pub last_method: String,
    /// What has arrived since a successful unsubscribe. `None` when the sender
    /// is absent from the current scan (nothing to measure against) or has no
    /// successful attempt behind it (nothing was ever agreed to).
    pub outcome: Option<UnsubscribeOutcome>,
    /// Resumptions on record for this sender.
    pub violation_count: usize,
    /// What a retry would try. `None` when the sender is absent from the
    /// current scan: the ladder is built from headers we no longer have.
    pub next_step: Option<NextStep>,
    /// Every attempt and resumption for this sender, oldest first.
    pub timeline: Vec<TimelineEvent>,
}

impl SenderHistoryView {
    /// Whether this sender has ever ignored an unsubscribe.
    ///
    /// True for a sender caught doing it right now and for one whose violation
    /// is only on record, which is what `--resumed` is asking about.
    #[must_use]
    pub fn has_resumed(&self) -> bool {
        self.violation_count > 0 || self.outcome.is_some_and(|o| o.is_resumed())
    }

    /// The most recent thing that happened, attempt or resumption.
    #[must_use]
    pub fn last_activity_at(&self) -> i64 {
        self.timeline
            .last()
            .map_or(self.last_attempt_at, TimelineEvent::at)
    }

    /// Whether the sender appeared in the scan this view was built against.
    #[must_use]
    pub fn is_in_current_scan(&self) -> bool {
        self.next_step.is_some()
    }
}

/// Assemble one view per sender the history knows about.
///
/// Pure. `scanned` is the current cached scan and may be empty; senders with
/// history but absent from it still appear, without an outcome or a next step,
/// because both are judgements about mail we can no longer see.
///
/// Grouping follows [`UnsubscribeAttempt::is_about`]: a `List-Id` decides when
/// both sides carry one, otherwise the address does, case-insensitively.
/// Newest activity first, which is the order anyone reading a log wants.
#[must_use]
pub fn sender_histories(
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    scanned: &[SenderInfo],
    now: i64,
    grace_period_days: u32,
) -> Vec<SenderHistoryView> {
    let latest = LatestAttempts::from_history(attempts);

    let mut views: Vec<SenderHistoryView> = scanned
        .iter()
        .filter_map(|sender| scanned_view(sender, &latest, attempts, resumptions, now, grace_period_days))
        .collect();

    views.extend(unscanned_views(attempts, resumptions, scanned));
    views.sort_by_key(|view| std::cmp::Reverse(view.last_activity_at()));
    views
}

/// The view for a sender the current scan turned up.
///
/// `None` when the history holds nothing about it: a sender with no attempts
/// has no history to show, however recently it mailed.
fn scanned_view(
    sender: &SenderInfo,
    latest: &LatestAttempts,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    now: i64,
    grace_period_days: u32,
) -> Option<SenderHistoryView> {
    let mine: Vec<&UnsubscribeAttempt> = attempts_about(sender, attempts).collect();
    let last = mine.last()?;
    let ours: Vec<&Resumption> = resumptions_about(sender, resumptions).collect();
    let verdict = judge_sender(sender, latest, attempts, resumptions, now, grace_period_days);

    Some(SenderHistoryView {
        sender_email: sender.email.clone(),
        sender_domain: sender.domain.clone(),
        list_id: sender.list_id.clone(),
        last_attempt_at: last.attempted_at,
        last_method: last.method.clone(),
        outcome: verdict.map(|v| v.outcome),
        violation_count: ours.len(),
        next_step: Some(next_step(sender, attempts, resumptions)),
        timeline: timeline(&mine, &ours),
    })
}

/// Views for the senders the history remembers and the scan did not find.
fn unscanned_views(
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    scanned: &[SenderInfo],
) -> Vec<SenderHistoryView> {
    let claimed = |attempt: &UnsubscribeAttempt| scanned.iter().any(|s| attempt.is_about(s));

    // Group what is left the way the records themselves are identified: by
    // list where there is one, by address otherwise. Order of first appearance
    // keeps the result stable before the final sort.
    let mut keys: Vec<String> = Vec::new();
    for attempt in attempts.iter().filter(|a| !claimed(a)) {
        let key = record_key(attempt.list_id.as_deref(), &attempt.sender_email);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    keys.into_iter()
        .filter_map(|key| {
            let mine: Vec<&UnsubscribeAttempt> = attempts
                .iter()
                .filter(|a| !claimed(a))
                .filter(|a| record_key(a.list_id.as_deref(), &a.sender_email) == key)
                .collect();
            let last = mine.last()?;
            let ours: Vec<&Resumption> = resumptions
                .iter()
                .filter(|r| record_key(r.list_id.as_deref(), &r.sender_email) == key)
                .collect();

            Some(SenderHistoryView {
                sender_email: last.sender_email.clone(),
                sender_domain: last.sender_domain.clone(),
                list_id: last.list_id.clone(),
                last_attempt_at: last.attempted_at,
                last_method: last.method.clone(),
                // Nothing to judge against: the scan cannot say what this
                // sender has been doing, so neither can we.
                outcome: None,
                violation_count: ours.len(),
                next_step: None,
                timeline: timeline(&mine, &ours),
            })
        })
        .collect()
}

/// How a stored record identifies its sender: the list, or the address.
fn record_key(list_id: Option<&str>, sender_email: &str) -> String {
    normalized_list_id(list_id).unwrap_or_else(|| sender_email.to_lowercase())
}

/// Merge attempts and resumptions into one chronological sequence.
fn timeline(attempts: &[&UnsubscribeAttempt], resumptions: &[&Resumption]) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = attempts
        .iter()
        .map(|a| TimelineEvent::Attempt((*a).clone()))
        .chain(
            resumptions
                .iter()
                .map(|r| TimelineEvent::Resumption((*r).clone())),
        )
        .collect();
    events.sort_by_key(TimelineEvent::at);
    events
}

/// What a sender did between a successful attempt and the newest mail seen.
///
/// Exposed for consumers rendering one timeline entry at a time; the grouped
/// views already carry the same judgement in `outcome`.
#[must_use]
pub fn outcome_of(attempt: &UnsubscribeAttempt, last_seen: Option<i64>, now: i64, grace_period_days: u32) -> Option<UnsubscribeOutcome> {
    attempt
        .success
        .then(|| classify_outcome(attempt.attempted_at, last_seen, now, grace_period_days))
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Which senders a listing should keep.
///
/// Pure and additive: every field set must match. Filters select senders, not
/// events -- a matching sender keeps its whole timeline, because half a
/// timeline is a misleading record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    /// Case-insensitive substring of the address or the list id.
    pub sender: Option<String>,
    /// Only senders that ignored an unsubscribe.
    pub resumed_only: bool,
    /// Only senders with activity at or after this Unix timestamp.
    pub since: Option<i64>,
}

impl HistoryFilter {
    /// Whether one sender survives the filter.
    #[must_use]
    pub fn matches(&self, view: &SenderHistoryView) -> bool {
        if self.resumed_only && !view.has_resumed() {
            return false;
        }
        if let Some(since) = self.since {
            if !view.timeline.iter().any(|event| event.at() >= since) {
                return false;
            }
        }
        match &self.sender {
            Some(needle) => {
                let needle = needle.to_lowercase();
                view.sender_email.to_lowercase().contains(&needle)
                    || view
                        .list_id
                        .as_deref()
                        .is_some_and(|id| id.to_lowercase().contains(&needle))
            }
            None => true,
        }
    }

    /// Whether the filter asks for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sender.is_none() && !self.resumed_only && self.since.is_none()
    }
}

/// Apply a filter, preserving order.
#[must_use]
pub fn filter_histories(
    views: Vec<SenderHistoryView>,
    filter: &HistoryFilter,
) -> Vec<SenderHistoryView> {
    views
        .into_iter()
        .filter(|view| filter.matches(view))
        .collect()
}
