//! Reading the history back: one view struct per sender, with its timeline.
//!
//! The history is written as append-only events. Anything that *shows* it --
//! the app's History screen, the headless `history` command -- needs the same
//! reduction of those events into "what happened to this sender", so it lives
//! here rather than in either front-end. Everything in this file is pure: the
//! caller supplies the rows, the current scan, and what time it is.

use std::collections::HashMap;

use crate::escalation::{next_step, NextStep};
use crate::history::{
    classify_outcome, normalized_list_id, Resumption, UnsubscribeAttempt, UnsubscribeOutcome,
};
use crate::types::SenderInfo;

/// One entry of a sender's timeline, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineEvent {
    Attempt(UnsubscribeAttempt),
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

    /// The attempt, when this entry is one.
    #[must_use]
    pub fn attempt(&self) -> Option<&UnsubscribeAttempt> {
        match self {
            Self::Attempt(attempt) => Some(attempt),
            Self::Resumption(_) => None,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderHistoryView {
    pub sender_email: String,
    pub sender_domain: String,
    pub list_id: Option<String>,
    pub last_attempt_at: i64,
    /// Stable `UnsubscribeMethod` id (see [`crate::types::UnsubscribeMethod::as_id`]),
    /// not a display string -- consumers choose their own wording.
    pub last_method: String,
    /// `None` when the sender is absent from the current scan (nothing has
    /// arrived to judge) or has no successful attempt (nothing was ignored).
    pub outcome: Option<UnsubscribeOutcome>,
    /// Resumptions on record, counting one observed by this very reading.
    pub violation_count: usize,
    /// `None` when the sender is absent from the current scan: what to try
    /// next depends on the headers the sender is offering now.
    pub next_step: Option<NextStep>,
    /// Every attempt and resumption about this sender, oldest first.
    pub timeline: Vec<TimelineEvent>,
}

impl SenderHistoryView {
    /// Whether this sender is mailing right now despite a successful
    /// unsubscribe -- the condition under which it can be acted on again.
    #[must_use]
    pub fn is_resumed(&self) -> bool {
        self.outcome.is_some_and(|outcome| outcome.is_resumed())
    }

    /// Whether this sender has ever ignored an unsubscribe.
    ///
    /// True for a sender caught doing it right now and for one whose violation
    /// is only on record, which is what a "resumed only" listing is asking
    /// about in either front-end.
    #[must_use]
    pub fn has_resumed(&self) -> bool {
        self.violation_count > 0 || self.is_resumed()
    }

    /// The most recent thing that happened, attempt or resumption.
    #[must_use]
    pub fn last_activity_at(&self) -> i64 {
        self.timeline
            .last()
            .map_or(self.last_attempt_at, TimelineEvent::at)
    }

    /// Whether the sender appears in the scan the view was built against.
    ///
    /// History outlives the cache, so a sender can have a timeline and no
    /// current mail at all; only a scanned sender can be acted on.
    #[must_use]
    pub fn in_current_scan(&self) -> bool {
        self.next_step.is_some()
    }

    /// The attempts in the timeline, oldest first.
    pub fn attempts(&self) -> impl Iterator<Item = &UnsubscribeAttempt> {
        self.timeline.iter().filter_map(TimelineEvent::attempt)
    }
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

/// How one group of history rows is identified.
///
/// Rows carrying a `List-Id` group by it; the rest group by address. Which of
/// the two decides a *match* against a scanned sender is
/// [`UnsubscribeAttempt::is_about`]'s rule, applied in [`Group::is_about`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GroupKey {
    List(String),
    Email(String),
}

impl GroupKey {
    fn of_attempt(attempt: &UnsubscribeAttempt) -> Self {
        match normalized_list_id(attempt.list_id.as_deref()) {
            Some(list_id) => Self::List(list_id),
            None => Self::Email(attempt.sender_email.to_lowercase()),
        }
    }

    fn of_resumption(resumption: &Resumption) -> Self {
        match normalized_list_id(resumption.list_id.as_deref()) {
            Some(list_id) => Self::List(list_id),
            None => Self::Email(resumption.sender_email.to_lowercase()),
        }
    }
}

/// One sender's rows, before a scanned sender is matched to them.
#[derive(Debug, Default)]
struct Group {
    attempts: Vec<UnsubscribeAttempt>,
    resumptions: Vec<Resumption>,
    /// The list identifier every row in this group carries, if any.
    list_id: Option<String>,
    /// Every address the group's rows were recorded against, lowercased.
    emails: Vec<String>,
}

impl Group {
    /// Whether this group is about `sender`, by the rule the rows themselves
    /// use: `List-Id` when both sides carry one, the address otherwise.
    fn is_about(&self, sender: &SenderInfo) -> bool {
        match (
            self.list_id.as_deref(),
            normalized_list_id(sender.list_id.as_deref()),
        ) {
            (Some(recorded), Some(scanned)) => recorded == scanned,
            _ => {
                let email = sender.email.to_lowercase();
                self.emails.iter().any(|recorded| *recorded == email)
            }
        }
    }

    fn note_email(&mut self, email: &str) {
        let email = email.to_lowercase();
        if !self.emails.contains(&email) {
            self.emails.push(email);
        }
    }
}

/// Reduce an account's history to one view per sender.
///
/// `scanned` is the current cached scan and may be empty: senders with a
/// history but no current mail still appear, they simply carry no outcome and
/// no next step, because both are answers about mail that is arriving now.
///
/// Rows are grouped by the same identity rule as
/// [`UnsubscribeAttempt::is_about`]. That rule is not an equivalence relation
/// -- a scanned sender carrying a `List-Id` also matches rows recorded at its
/// address with no list at all -- so groups a single scanned sender matches
/// are merged into one view rather than shown twice.
///
/// Newest activity first, ties broken by address, so the result never depends
/// on how the rows happened to be grouped.
#[must_use]
pub fn sender_histories(
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    scanned: &[SenderInfo],
    now: i64,
    grace_period_days: u32,
) -> Vec<SenderHistoryView> {
    let mut groups: HashMap<GroupKey, Group> = HashMap::new();

    for attempt in attempts {
        let key = GroupKey::of_attempt(attempt);
        let group = groups.entry(key).or_default();
        group.list_id = normalized_list_id(attempt.list_id.as_deref());
        group.note_email(&attempt.sender_email);
        group.attempts.push(attempt.clone());
    }
    for resumption in resumptions {
        let key = GroupKey::of_resumption(resumption);
        let group = groups.entry(key).or_default();
        // A resumption without a matching attempt cannot happen -- one is
        // recorded against an attempt id -- but the group still needs its
        // identity if it somehow arrives first.
        if group.list_id.is_none() {
            group.list_id = normalized_list_id(resumption.list_id.as_deref());
        }
        group.note_email(&resumption.sender_email);
        group.resumptions.push(resumption.clone());
    }

    let mut groups: Vec<Group> = groups.into_values().collect();
    let mut views: Vec<SenderHistoryView> = Vec::new();

    // Scanned senders first, each claiming (and merging) every group about it.
    for sender in scanned {
        let (mine, rest): (Vec<Group>, Vec<Group>) = groups
            .into_iter()
            .partition(|group| group.is_about(sender));
        groups = rest;
        if mine.is_empty() {
            continue;
        }
        let merged = merge(mine);
        if let Some(view) = view_of(
            &merged,
            Some(sender),
            attempts,
            resumptions,
            now,
            grace_period_days,
        ) {
            views.push(view);
        }
    }

    // Whatever is left has a history but no current mail.
    for group in groups {
        if let Some(view) = view_of(&group, None, attempts, resumptions, now, grace_period_days) {
            views.push(view);
        }
    }

    views.sort_by(|a, b| {
        b.last_activity_at()
            .cmp(&a.last_activity_at())
            .then_with(|| a.sender_email.cmp(&b.sender_email))
    });
    views
}

/// Fold several groups the same scanned sender matched into one.
fn merge(groups: Vec<Group>) -> Group {
    groups.into_iter().fold(Group::default(), |mut all, group| {
        all.attempts.extend(group.attempts);
        all.resumptions.extend(group.resumptions);
        all.list_id = all.list_id.or(group.list_id);
        for email in group.emails {
            all.note_email(&email);
        }
        all
    })
}

/// Build one view. `None` for a group with no attempt at all, which has
/// nothing to show and no date to sort by.
fn view_of(
    group: &Group,
    sender: Option<&SenderInfo>,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    now: i64,
    grace_period_days: u32,
) -> Option<SenderHistoryView> {
    let last = group
        .attempts
        .iter()
        .max_by_key(|attempt| attempt.attempted_at)?;

    // The measurement hangs off the newest *successful* attempt: a sender
    // that was never successfully unsubscribed from has ignored nothing.
    let unsubscribed = group
        .attempts
        .iter()
        .filter(|attempt| attempt.success)
        .max_by_key(|attempt| attempt.attempted_at);

    let outcome = sender.zip(unsubscribed).map(|(sender, attempt)| {
        classify_outcome(
            attempt.attempted_at,
            sender.last_seen,
            now,
            grace_period_days,
        )
    });

    // The same count the selection screen shows: what is on record, plus the
    // one this reading has just established.
    let newly_observed = usize::from(
        outcome.is_some_and(|outcome| outcome.is_resumed())
            && unsubscribed.is_some_and(|attempt| {
                !group
                    .resumptions
                    .iter()
                    .any(|resumption| resumption.attempt_id == attempt.id)
            }),
    );

    let mut timeline: Vec<TimelineEvent> = group
        .attempts
        .iter()
        .cloned()
        .map(TimelineEvent::Attempt)
        .chain(
            group
                .resumptions
                .iter()
                .cloned()
                .map(TimelineEvent::Resumption),
        )
        .collect();
    timeline.sort_by_key(TimelineEvent::at);

    Some(SenderHistoryView {
        sender_email: sender
            .map_or_else(|| last.sender_email.clone(), |s| s.email.clone()),
        sender_domain: sender
            .map_or_else(|| last.sender_domain.clone(), |s| s.domain.clone()),
        list_id: sender.map_or_else(|| last.list_id.clone(), |s| s.list_id.clone()),
        last_attempt_at: last.attempted_at,
        last_method: last.method.clone(),
        outcome,
        violation_count: group.resumptions.len() + newly_observed,
        // What to ask next depends on the rungs the sender is offering now,
        // which only a scanned sender has.
        next_step: sender.map(|sender| next_step(sender, attempts, resumptions)),
        timeline,
    })
}

// ---------------------------------------------------------------------------
// Ordering, filtering, search
// ---------------------------------------------------------------------------

/// How a history listing is ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistorySort {
    /// Newest attempt first.
    #[default]
    LastAttempt,
    /// Worst offender first.
    Violations,
    /// Alphabetical by address.
    Sender,
}

impl HistorySort {
    pub const ALL: [HistorySort; 3] = [Self::LastAttempt, Self::Violations, Self::Sender];

    /// The next order in the cycle, for a consumer with one key for it.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::LastAttempt => Self::Violations,
            Self::Violations => Self::Sender,
            Self::Sender => Self::LastAttempt,
        }
    }
}

/// What a consumer is currently showing of a history listing.
///
/// One filter for both front-ends: the History screen drives it key by key,
/// the `history` command fills it from flags. Filters select senders, not
/// events -- a matching sender keeps its whole timeline, because half a
/// timeline is a misleading record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    pub sort: HistorySort,
    /// Only senders that ignored an unsubscribe, now or on record.
    pub resumed_only: bool,
    /// Matched against address, domain and list id, case-insensitively.
    pub search: String,
    /// Only senders with activity at or after this Unix timestamp.
    pub since: Option<i64>,
}

impl HistoryFilter {
    /// Whether one sender survives the filter.
    #[must_use]
    pub fn matches(&self, view: &SenderHistoryView) -> bool {
        (!self.resumed_only || view.has_resumed())
            && self
                .since
                .is_none_or(|since| view.timeline.iter().any(|event| event.at() >= since))
            && matches_search(view, &self.search)
    }
}

/// Whether one view matches a search needle.
///
/// An empty needle matches everything, so a consumer can call this while the
/// user is still typing.
#[must_use]
pub fn matches_search(view: &SenderHistoryView, needle: &str) -> bool {
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    [
        Some(view.sender_email.as_str()),
        Some(view.sender_domain.as_str()),
        view.list_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|field| field.to_lowercase().contains(&needle))
}

/// The rows a filter selects, in its order, as indices into `views`.
///
/// Indices rather than references so a consumer can load the views once per
/// screen entry and re-derive the visible list as the user types.
#[must_use]
pub fn visible_histories(views: &[SenderHistoryView], filter: &HistoryFilter) -> Vec<usize> {
    let mut visible: Vec<usize> = views
        .iter()
        .enumerate()
        .filter(|(_, view)| filter.matches(view))
        .map(|(index, _)| index)
        .collect();

    visible.sort_by(|a, b| {
        let (a, b) = (&views[*a], &views[*b]);
        match filter.sort {
            // Ties broken by address so the order never depends on how the
            // rows happened to come out of the store.
            HistorySort::LastAttempt => b
                .last_attempt_at
                .cmp(&a.last_attempt_at)
                .then_with(|| a.sender_email.cmp(&b.sender_email)),
            HistorySort::Violations => b
                .violation_count
                .cmp(&a.violation_count)
                .then_with(|| b.last_attempt_at.cmp(&a.last_attempt_at)),
            HistorySort::Sender => a
                .sender_email
                .to_lowercase()
                .cmp(&b.sender_email.to_lowercase()),
        }
    });

    visible
}

/// Apply a filter to an owned listing, in the filter's order.
#[must_use]
pub fn filter_histories(
    views: Vec<SenderHistoryView>,
    filter: &HistoryFilter,
) -> Vec<SenderHistoryView> {
    let visible = visible_histories(&views, filter);
    let mut views: Vec<Option<SenderHistoryView>> = views.into_iter().map(Some).collect();
    visible
        .into_iter()
        .filter_map(|index| views.get_mut(index).and_then(Option::take))
        .collect()
}
