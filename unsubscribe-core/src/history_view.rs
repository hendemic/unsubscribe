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

// ---------------------------------------------------------------------------
// The flat event log
// ---------------------------------------------------------------------------

/// One line of the account-wide event feed.
///
/// The same [`TimelineEvent`] a sender's timeline is made of, carrying the
/// sender identity the flat feed needs in order to name who the event is
/// about. Pure data: consumers choose the wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// When the event happened, in Unix seconds (UTC).
    pub at: i64,
    pub sender_email: String,
    pub sender_domain: String,
    pub list_id: Option<String>,
    pub event: TimelineEvent,
    /// The attempt this one escalates from, when `follows_attempt_id` names a
    /// row the feed also holds. Resolved here so the consumer never has to
    /// index the attempts itself.
    pub follows: Option<LogReference>,
}

impl LogEntry {
    /// Whether the entry records something that did not work: a failed
    /// attempt, or a sender that kept mailing.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        match &self.event {
            TimelineEvent::Attempt(attempt) => !attempt.success,
            TimelineEvent::Resumption(_) => true,
        }
    }

    #[must_use]
    pub fn is_resumption(&self) -> bool {
        matches!(self.event, TimelineEvent::Resumption(_))
    }
}

/// Enough of an earlier attempt to name it in the entry that escalates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogReference {
    pub attempt_id: String,
    /// Stable method id, not a display string.
    pub method: String,
    pub at: i64,
}

/// Which kinds of event a log listing is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogKind {
    #[default]
    All,
    /// Failed attempts and resumptions -- everything that did not work.
    Failures,
    Resumptions,
}

impl LogKind {
    pub const ALL: [LogKind; 3] = [Self::All, Self::Failures, Self::Resumptions];

    /// The next kind in the cycle, for a consumer with one key for it.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Failures,
            Self::Failures => Self::Resumptions,
            Self::Resumptions => Self::All,
        }
    }

    #[must_use]
    pub fn matches(self, entry: &LogEntry) -> bool {
        match self {
            Self::All => true,
            Self::Failures => entry.is_failure(),
            Self::Resumptions => entry.is_resumption(),
        }
    }
}

/// What a consumer is currently showing of the event log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFilter {
    pub kind: LogKind,
    /// Matched against address, domain, list id, method and detail.
    pub search: String,
    /// Only events at or after this Unix timestamp.
    pub since: Option<i64>,
}

impl LogFilter {
    #[must_use]
    pub fn matches(&self, entry: &LogEntry) -> bool {
        self.kind.matches(entry)
            && self.since.is_none_or(|since| entry.at >= since)
            && matches_log_search(entry, &self.search)
    }
}

/// Every recorded event for an account, newest first.
///
/// The flat counterpart of [`sender_histories`]: no grouping and no verdicts,
/// because a chronological feed answers "what happened, in order" rather than
/// "what became of this sender". Ties are broken by address so the order never
/// depends on how the rows came out of the store.
#[must_use]
pub fn event_log(attempts: &[UnsubscribeAttempt], resumptions: &[Resumption]) -> Vec<LogEntry> {
    // Attempt id to what it was, for naming the attempt an escalation answers.
    let by_id: HashMap<&str, &UnsubscribeAttempt> = attempts
        .iter()
        .map(|attempt| (attempt.id.as_str(), attempt))
        .collect();

    let mut entries: Vec<LogEntry> = attempts
        .iter()
        .map(|attempt| LogEntry {
            at: attempt.attempted_at,
            sender_email: attempt.sender_email.clone(),
            sender_domain: attempt.sender_domain.clone(),
            list_id: attempt.list_id.clone(),
            follows: attempt
                .follows_attempt_id
                .as_deref()
                .and_then(|id| by_id.get(id))
                .map(|earlier| LogReference {
                    attempt_id: earlier.id.clone(),
                    method: earlier.method.clone(),
                    at: earlier.attempted_at,
                }),
            event: TimelineEvent::Attempt(attempt.clone()),
        })
        .chain(resumptions.iter().map(|resumption| LogEntry {
            at: resumption.observed_at,
            sender_email: resumption.sender_email.clone(),
            // A resumption carries no domain of its own; the address does.
            sender_domain: resumption
                .sender_email
                .split('@')
                .nth(1)
                .unwrap_or_default()
                .to_string(),
            list_id: resumption.list_id.clone(),
            follows: None,
            event: TimelineEvent::Resumption(resumption.clone()),
        }))
        .collect();

    entries.sort_by(|a, b| {
        b.at.cmp(&a.at)
            .then_with(|| a.sender_email.cmp(&b.sender_email))
    });
    entries
}

/// Whether one entry matches a search needle.
///
/// An empty needle matches everything, so a consumer can call this while the
/// user is still typing.
#[must_use]
pub fn matches_log_search(entry: &LogEntry, needle: &str) -> bool {
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let (method, detail) = match &entry.event {
        TimelineEvent::Attempt(attempt) => (attempt.method.as_str(), attempt.detail.as_str()),
        TimelineEvent::Resumption(_) => ("resumed", ""),
    };
    [
        Some(entry.sender_email.as_str()),
        Some(entry.sender_domain.as_str()),
        entry.list_id.as_deref(),
        Some(method),
        Some(detail),
    ]
    .into_iter()
    .flatten()
    .any(|field| field.to_lowercase().contains(&needle))
}

/// The entries a filter selects, as indices into `entries`.
///
/// Indices rather than references so a consumer can build the log once per
/// screen entry and re-derive the visible list as the user types. The feed is
/// already newest-first, so filtering never reorders it.
#[must_use]
pub fn visible_log(entries: &[LogEntry], filter: &LogFilter) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| filter.matches(entry))
        .map(|(index, _)| index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{judge_sender, LatestAttempts};
    use crate::types::{Folder, FolderMessage, MessageId, UnsubscribeMethod};

    const ACCOUNT: &str = "user@example.com";
    const DAY: i64 = 24 * 60 * 60;
    /// The moment every fixture measures from.
    const T0: i64 = 1_700_000_000;
    const GRACE: u32 = 14;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn sender(email: &str, list_id: Option<&str>, last_seen: Option<i64>) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: email.split('@').nth(1).unwrap_or("").to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: true,
            list_id: list_id.map(str::to_string),
            list_unsubscribe_raw: None,
            email_count: 3,
            messages: vec![FolderMessage {
                folder: Folder::new("INBOX"),
                message_id: MessageId::new("INBOX:1"),
            }],
            last_seen,
        }
    }

    fn attempt(
        id: &str,
        email: &str,
        list_id: Option<&str>,
        at: i64,
        success: bool,
    ) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: ACCOUNT.to_string(),
            sender_email: email.to_string(),
            sender_domain: email.split('@').nth(1).unwrap_or("").to_string(),
            list_id: list_id.map(str::to_string),
            attempted_at: at,
            method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            success,
            http_status: Some(200),
            url: "https://acme.example.com/unsub".to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        }
    }

    fn resumption(id: &str, attempt_id: &str, email: &str, list_id: Option<&str>, at: i64) -> Resumption {
        Resumption {
            id: id.to_string(),
            account: ACCOUNT.to_string(),
            sender_email: email.to_string(),
            list_id: list_id.map(str::to_string),
            attempt_id: attempt_id.to_string(),
            observed_at: at,
            last_seen: at - DAY,
            email_count: 2,
        }
    }

    /// The views for one reading, with the fixtures' fixed grace period.
    fn views(
        attempts: &[UnsubscribeAttempt],
        resumptions: &[Resumption],
        scanned: &[SenderInfo],
        now: i64,
    ) -> Vec<SenderHistoryView> {
        sender_histories(attempts, resumptions, scanned, now, GRACE)
    }

    fn addresses(views: &[SenderHistoryView]) -> Vec<&str> {
        views.iter().map(|v| v.sender_email.as_str()).collect()
    }

    // -----------------------------------------------------------------------
    // Grouping and matching
    // -----------------------------------------------------------------------

    #[test]
    fn a_sender_matching_both_a_list_group_and_an_unlisted_address_group_yields_one_view() {
        // Two rows about the same sender recorded either side of the day
        // List-Id started being captured: one carries the list, one does not.
        let attempts = [
            attempt("a-old", "news@acme.example.com", None, T0 - 90 * DAY, true),
            attempt(
                "a-new",
                "news@acme.example.com",
                Some("news.acme.example.com"),
                T0 - 30 * DAY,
                true,
            ),
        ];
        let scanned = [sender(
            "news@acme.example.com",
            Some("news.acme.example.com"),
            Some(T0 - DAY),
        )];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views.len(), 1, "the two groups must merge into one sender");
        assert_eq!(views[0].timeline.len(), 2);
        assert_eq!(views[0].last_attempt_at, T0 - 30 * DAY);
    }

    #[test]
    fn an_attempt_for_a_different_list_at_the_same_address_is_not_the_scanned_sender() {
        let attempts = [attempt(
            "a-deals",
            "news@acme.example.com",
            Some("deals.acme.example.com"),
            T0 - 30 * DAY,
            true,
        )];
        let scanned = [sender(
            "news@acme.example.com",
            Some("news.acme.example.com"),
            Some(T0 - DAY),
        )];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views.len(), 1);
        assert_eq!(
            views[0].list_id.as_deref(),
            Some("deals.acme.example.com"),
            "the row belongs to the list it was recorded for"
        );
        assert!(
            !views[0].in_current_scan(),
            "the scanned sender is a different list, so this row has no current mail"
        );
        assert_eq!(views[0].outcome, None);
        assert_eq!(views[0].next_step, None);
    }

    #[test]
    fn a_list_id_is_matched_ignoring_case_and_surrounding_space() {
        let attempts = [attempt(
            "a1",
            "bounce-77@esp.example.net",
            Some("  News.Acme.Example.Com "),
            T0 - 30 * DAY,
            true,
        )];
        // A rotated From address: only the list identifier ties the two.
        let scanned = [sender(
            "bounce-91@esp.example.net",
            Some("news.acme.example.com"),
            Some(T0 - DAY),
        )];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views.len(), 1);
        assert!(views[0].in_current_scan());
        assert_eq!(
            views[0].sender_email, "bounce-91@esp.example.net",
            "a matched view is named by the sender as the scan sees it now"
        );
    }

    #[test]
    fn an_address_is_matched_ignoring_case() {
        let attempts = [attempt("a1", "News@Acme.Example.Com", None, T0 - 30 * DAY, true)];
        let scanned = [sender("news@acme.example.com", None, Some(T0 - DAY))];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views.len(), 1);
        assert!(views[0].in_current_scan());
    }

    #[test]
    fn two_scanned_senders_do_not_share_one_groups_rows() {
        let attempts = [
            attempt("a1", "news@acme.example.com", None, T0 - 30 * DAY, true),
            attempt("a2", "deals@acme.example.com", None, T0 - 20 * DAY, true),
        ];
        let scanned = [
            sender("news@acme.example.com", None, Some(T0 - DAY)),
            sender("deals@acme.example.com", None, Some(T0 - DAY)),
        ];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views.len(), 2);
        for view in &views {
            assert_eq!(view.timeline.len(), 1, "each sender keeps only its own row");
        }
    }

    #[test]
    fn a_sender_with_history_but_absent_from_the_scan_has_no_outcome_and_no_next_step() {
        let attempts = [attempt("a1", "gone@acme.example.com", None, T0 - 60 * DAY, true)];

        let views = views(&attempts, &[], &[], T0);

        assert_eq!(addresses(&views), ["gone@acme.example.com"]);
        assert_eq!(views[0].outcome, None, "nothing has arrived to judge");
        assert_eq!(views[0].next_step, None);
        assert!(!views[0].in_current_scan());
    }

    #[test]
    fn a_group_with_resumptions_but_no_attempt_shows_nothing() {
        // Cannot happen through the normal path -- a resumption references an
        // attempt id -- but an orphan row must not produce a dateless view.
        let orphan = [resumption("r1", "missing", "ghost@acme.example.com", None, T0 - DAY)];

        assert!(views(&[], &orphan, &[], T0).is_empty());
    }

    #[test]
    fn no_history_at_all_yields_no_views() {
        let scanned = [sender("news@acme.example.com", None, Some(T0 - DAY))];

        assert!(views(&[], &[], &scanned, T0).is_empty());
    }

    // -----------------------------------------------------------------------
    // Outcome, violations, next step
    // -----------------------------------------------------------------------

    #[test]
    fn a_sender_mailing_again_after_the_grace_period_is_resumed() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, true)];
        // Newest mail arrived 20 days after the unsubscribe: past the 14-day grace.
        let scanned = [sender("news@acme.example.com", None, Some(T0 - 40 * DAY))];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views[0].outcome, Some(UnsubscribeOutcome::Resumed { days_after: 20 }));
        assert!(views[0].is_resumed());
        assert!(views[0].has_resumed());
    }

    #[test]
    fn mail_inside_the_grace_period_is_not_a_violation() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 20 * DAY, true)];
        // Ten days after the unsubscribe, inside the 14-day window.
        let scanned = [sender("news@acme.example.com", None, Some(T0 - 10 * DAY))];

        let views = views(&attempts, &[], &scanned, T0);

        assert!(matches!(
            views[0].outcome,
            Some(UnsubscribeOutcome::WithinGrace { .. })
        ));
        assert_eq!(views[0].violation_count, 0);
        assert!(!views[0].has_resumed());
    }

    #[test]
    fn an_outcome_hangs_off_the_newest_successful_attempt_not_the_newest_one() {
        let attempts = [
            attempt("a-ok", "news@acme.example.com", None, T0 - 60 * DAY, true),
            attempt("a-fail", "news@acme.example.com", None, T0 - 5 * DAY, false),
        ];
        // Newest mail is 20 days after the *successful* attempt, and predates
        // the failed one, so it is a resumption of the successful request.
        let scanned = [sender("news@acme.example.com", None, Some(T0 - 40 * DAY))];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views[0].outcome, Some(UnsubscribeOutcome::Resumed { days_after: 20 }));
        assert_eq!(
            views[0].last_attempt_at,
            T0 - 5 * DAY,
            "the row still reports when it was last asked"
        );
    }

    #[test]
    fn a_sender_that_was_never_successfully_unsubscribed_has_no_outcome() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, false)];
        let scanned = [sender("news@acme.example.com", None, Some(T0 - DAY))];

        let views = views(&attempts, &[], &scanned, T0);

        assert_eq!(views[0].outcome, None, "nothing was ever honoured to ignore");
        assert!(
            views[0].next_step.is_some(),
            "it is still in the scan, so there is something to try"
        );
    }

    #[test]
    fn a_violation_this_reading_establishes_is_counted_once_and_only_once() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, true)];
        let scanned = [sender("news@acme.example.com", None, Some(T0 - 40 * DAY))];

        let fresh = views(&attempts, &[], &scanned, T0);
        assert_eq!(fresh[0].violation_count, 1, "newly observed");

        // Once it is on record the same reading must not count it twice.
        let recorded = [resumption("r1", "a1", "news@acme.example.com", None, T0 - 39 * DAY)];
        let again = views(&attempts, &recorded, &scanned, T0);
        assert_eq!(again[0].violation_count, 1);
    }

    #[test]
    fn a_violation_only_on_record_still_counts_when_the_sender_is_gone() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, true)];
        let recorded = [resumption("r1", "a1", "news@acme.example.com", None, T0 - 39 * DAY)];

        let views = views(&attempts, &recorded, &[], T0);

        assert_eq!(views[0].violation_count, 1);
        assert!(!views[0].is_resumed(), "nothing is arriving right now");
        assert!(views[0].has_resumed(), "but it ignored an unsubscribe once");
    }

    #[test]
    fn violation_count_agrees_with_judge_sender_for_the_same_inputs() {
        // Two ignored unsubscribes on record and a third caught by this very
        // reading: the History screen and the selection screen must agree.
        let attempts = [
            attempt("a1", "news@acme.example.com", None, T0 - 200 * DAY, true),
            attempt("a2", "news@acme.example.com", None, T0 - 100 * DAY, true),
            attempt("a3", "news@acme.example.com", None, T0 - 60 * DAY, true),
        ];
        let recorded = [
            resumption("r1", "a1", "news@acme.example.com", None, T0 - 150 * DAY),
            resumption("r2", "a2", "news@acme.example.com", None, T0 - 80 * DAY),
        ];
        let scanned = sender("news@acme.example.com", None, Some(T0 - 40 * DAY));

        let views = views(&attempts, &recorded, std::slice::from_ref(&scanned), T0);
        let verdict = judge_sender(
            &scanned,
            &LatestAttempts::from_history(&attempts),
            &attempts,
            &recorded,
            T0,
            GRACE,
        )
        .expect("the sender has a successful unsubscribe behind it");

        assert_eq!(views[0].violation_count as u32, verdict.violation_count);
        assert_eq!(views[0].violation_count, 3);
        assert_eq!(views[0].outcome, Some(verdict.outcome));
        assert_eq!(views[0].next_step.as_ref(), Some(&verdict.next_step));
    }

    #[test]
    fn next_step_is_the_escalation_the_pipeline_would_plan() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, true)];
        let recorded = [resumption("r1", "a1", "news@acme.example.com", None, T0 - 39 * DAY)];
        let scanned = sender("news@acme.example.com", None, Some(T0 - 40 * DAY));

        let views = views(&attempts, &recorded, std::slice::from_ref(&scanned), T0);

        assert_eq!(
            views[0].next_step,
            Some(next_step(&scanned, &attempts, &recorded)),
            "the screen never works out its own next step"
        );
    }

    // -----------------------------------------------------------------------
    // Timeline
    // -----------------------------------------------------------------------

    #[test]
    fn the_timeline_interleaves_attempts_and_resumptions_by_time() {
        let attempts = [
            attempt("a1", "news@acme.example.com", None, T0 - 100 * DAY, true),
            attempt("a2", "news@acme.example.com", None, T0 - 50 * DAY, true),
        ];
        let recorded = [
            resumption("r1", "a1", "news@acme.example.com", None, T0 - 70 * DAY),
            resumption("r2", "a2", "news@acme.example.com", None, T0 - 20 * DAY),
        ];

        let views = views(&attempts, &recorded, &[], T0);
        let order: Vec<(&str, i64)> = views[0]
            .timeline
            .iter()
            .map(|event| (event.kind(), event.at()))
            .collect();

        assert_eq!(
            order,
            [
                ("attempt", T0 - 100 * DAY),
                ("resumption", T0 - 70 * DAY),
                ("attempt", T0 - 50 * DAY),
                ("resumption", T0 - 20 * DAY),
            ]
        );
    }

    #[test]
    fn an_escalated_attempt_points_at_the_attempt_it_answers() {
        let first = attempt("a1", "news@acme.example.com", None, T0 - 100 * DAY, true);
        let escalated = UnsubscribeAttempt {
            follows_attempt_id: Some("a1".to_string()),
            ..attempt("a2", "news@acme.example.com", None, T0 - 50 * DAY, true)
        };
        let attempts = [first, escalated];

        let views = views(&attempts, &[], &[], T0);
        let ids: Vec<Option<&str>> = views[0]
            .attempts()
            .map(|a| a.follows_attempt_id.as_deref())
            .collect();

        assert_eq!(ids, [None, Some("a1")]);
        assert!(
            views[0].attempts().any(|a| a.id == "a1"),
            "the attempt it follows is in the same timeline"
        );
    }

    #[test]
    fn last_activity_is_a_resumption_when_that_is_the_newest_event() {
        let attempts = [attempt("a1", "news@acme.example.com", None, T0 - 100 * DAY, true)];
        let recorded = [resumption("r1", "a1", "news@acme.example.com", None, T0 - 10 * DAY)];

        let views = views(&attempts, &recorded, &[], T0);

        assert_eq!(views[0].last_attempt_at, T0 - 100 * DAY);
        assert_eq!(views[0].last_activity_at(), T0 - 10 * DAY);
    }

    // -----------------------------------------------------------------------
    // Default ordering
    // -----------------------------------------------------------------------

    #[test]
    fn views_come_back_newest_activity_first() {
        let attempts = [
            attempt("a1", "old@acme.example.com", None, T0 - 100 * DAY, true),
            attempt("a2", "new@acme.example.com", None, T0 - 10 * DAY, true),
            attempt("a3", "middle@acme.example.com", None, T0 - 50 * DAY, true),
        ];

        let views = views(&attempts, &[], &[], T0);

        assert_eq!(
            addresses(&views),
            [
                "new@acme.example.com",
                "middle@acme.example.com",
                "old@acme.example.com"
            ]
        );
    }

    #[test]
    fn senders_with_identical_activity_are_ordered_by_address() {
        let attempts = [
            attempt("a1", "zeta@acme.example.com", None, T0 - 10 * DAY, true),
            attempt("a2", "alpha@acme.example.com", None, T0 - 10 * DAY, true),
            attempt("a3", "mid@acme.example.com", None, T0 - 10 * DAY, true),
        ];

        let views = views(&attempts, &[], &[], T0);

        assert_eq!(
            addresses(&views),
            [
                "alpha@acme.example.com",
                "mid@acme.example.com",
                "zeta@acme.example.com"
            ],
            "the order must not depend on how the rows happened to be grouped"
        );
    }

    // -----------------------------------------------------------------------
    // Filtering, search, ordering for display
    // -----------------------------------------------------------------------

    /// Three senders: one resumed, one honoured, one absent from the scan.
    fn listing() -> Vec<SenderHistoryView> {
        let attempts = [
            attempt("a1", "news@acme.example.com", None, T0 - 60 * DAY, true),
            attempt("a2", "quiet@beta.example.org", None, T0 - 30 * DAY, true),
            attempt("a3", "gone@gamma.example.net", None, T0 - 400 * DAY, true),
        ];
        let scanned = [
            // Mailing 20 days after its unsubscribe: a violation.
            sender("news@acme.example.com", Some("news.acme"), Some(T0 - 40 * DAY)),
            // Nothing since its unsubscribe.
            sender("quiet@beta.example.org", None, Some(T0 - 31 * DAY)),
        ];
        views(&attempts, &[], &scanned, T0)
    }

    fn visible_addresses(views: &[SenderHistoryView], filter: &HistoryFilter) -> Vec<String> {
        visible_histories(views, filter)
            .into_iter()
            .map(|index| views[index].sender_email.clone())
            .collect()
    }

    #[test]
    fn the_default_filter_shows_every_sender_newest_attempt_first() {
        let views = listing();

        assert_eq!(
            visible_addresses(&views, &HistoryFilter::default()),
            [
                "quiet@beta.example.org",
                "news@acme.example.com",
                "gone@gamma.example.net"
            ]
        );
    }

    #[test]
    fn resumed_only_keeps_the_sender_that_ignored_its_unsubscribe() {
        let views = listing();
        let filter = HistoryFilter {
            resumed_only: true,
            ..HistoryFilter::default()
        };

        assert_eq!(visible_addresses(&views, &filter), ["news@acme.example.com"]);
    }

    #[test]
    fn search_matches_the_address_case_insensitively() {
        let views = listing();
        let filter = HistoryFilter {
            search: "QUIET@".to_string(),
            ..HistoryFilter::default()
        };

        assert_eq!(visible_addresses(&views, &filter), ["quiet@beta.example.org"]);
    }

    #[test]
    fn search_matches_the_domain() {
        let views = listing();
        let filter = HistoryFilter {
            search: "gamma.example.net".to_string(),
            ..HistoryFilter::default()
        };

        assert_eq!(visible_addresses(&views, &filter), ["gone@gamma.example.net"]);
    }

    #[test]
    fn search_matches_the_list_id() {
        let views = listing();
        let filter = HistoryFilter {
            search: "News.Acme".to_string(),
            ..HistoryFilter::default()
        };

        assert_eq!(visible_addresses(&views, &filter), ["news@acme.example.com"]);
    }

    #[test]
    fn a_blank_search_matches_everything() {
        let views = listing();
        let filter = HistoryFilter {
            search: "   ".to_string(),
            ..HistoryFilter::default()
        };

        assert_eq!(visible_addresses(&views, &filter).len(), views.len());
    }

    #[test]
    fn a_search_that_matches_nothing_shows_nothing() {
        let views = listing();
        let filter = HistoryFilter {
            search: "nobody".to_string(),
            ..HistoryFilter::default()
        };

        assert!(visible_addresses(&views, &filter).is_empty());
    }

    #[test]
    fn a_sender_with_no_list_id_is_not_matched_by_a_list_search() {
        let views = listing();
        let filter = HistoryFilter {
            search: "news.acme".to_string(),
            ..HistoryFilter::default()
        };

        assert!(
            !visible_addresses(&views, &filter).contains(&"quiet@beta.example.org".to_string()),
            "a missing list id must not match, and must not panic"
        );
    }

    #[test]
    fn since_keeps_a_sender_whose_event_lands_exactly_on_the_boundary() {
        let views = listing();
        let on_the_line = HistoryFilter {
            since: Some(T0 - 60 * DAY),
            ..HistoryFilter::default()
        };
        let one_second_later = HistoryFilter {
            since: Some(T0 - 60 * DAY + 1),
            ..HistoryFilter::default()
        };

        assert!(visible_addresses(&views, &on_the_line).contains(&"news@acme.example.com".to_string()));
        assert!(
            !visible_addresses(&views, &one_second_later)
                .contains(&"news@acme.example.com".to_string())
        );
    }

    #[test]
    fn filters_combine_rather_than_replace_one_another() {
        let views = listing();
        let filter = HistoryFilter {
            resumed_only: true,
            search: "beta".to_string(),
            ..HistoryFilter::default()
        };

        assert!(
            visible_addresses(&views, &filter).is_empty(),
            "the resumed sender is not on beta, and the beta sender did not resume"
        );
    }

    #[test]
    fn sorting_by_violations_puts_the_worst_offender_first() {
        // Two senders, three violations against one and one against the other.
        let attempts = [
            attempt("a1", "bad@acme.example.com", None, T0 - 200 * DAY, true),
            attempt("a2", "bad@acme.example.com", None, T0 - 150 * DAY, true),
            attempt("a3", "bad@acme.example.com", None, T0 - 100 * DAY, true),
            attempt("b1", "mild@beta.example.org", None, T0 - 100 * DAY, true),
        ];
        let recorded = [
            resumption("r1", "a1", "bad@acme.example.com", None, T0 - 180 * DAY),
            resumption("r2", "a2", "bad@acme.example.com", None, T0 - 120 * DAY),
            resumption("r3", "a3", "bad@acme.example.com", None, T0 - 90 * DAY),
            resumption("r4", "b1", "mild@beta.example.org", None, T0 - 80 * DAY),
        ];
        let views = views(&attempts, &recorded, &[], T0);
        let filter = HistoryFilter {
            sort: HistorySort::Violations,
            ..HistoryFilter::default()
        };

        assert_eq!(
            visible_addresses(&views, &filter),
            ["bad@acme.example.com", "mild@beta.example.org"]
        );
    }

    #[test]
    fn violations_ties_are_broken_by_the_newest_attempt() {
        let attempts = [
            attempt("a1", "older@acme.example.com", None, T0 - 100 * DAY, true),
            attempt("b1", "newer@beta.example.org", None, T0 - 50 * DAY, true),
        ];
        let recorded = [
            resumption("r1", "a1", "older@acme.example.com", None, T0 - 90 * DAY),
            resumption("r2", "b1", "newer@beta.example.org", None, T0 - 40 * DAY),
        ];
        let views = views(&attempts, &recorded, &[], T0);
        let filter = HistoryFilter {
            sort: HistorySort::Violations,
            ..HistoryFilter::default()
        };

        assert_eq!(
            visible_addresses(&views, &filter),
            ["newer@beta.example.org", "older@acme.example.com"]
        );
    }

    #[test]
    fn sorting_by_sender_is_alphabetical_regardless_of_case() {
        let attempts = [
            attempt("a1", "Zeta@acme.example.com", None, T0 - 10 * DAY, true),
            attempt("a2", "alpha@acme.example.com", None, T0 - 20 * DAY, true),
            attempt("a3", "Mid@acme.example.com", None, T0 - 30 * DAY, true),
        ];
        let views = views(&attempts, &[], &[], T0);
        let filter = HistoryFilter {
            sort: HistorySort::Sender,
            ..HistoryFilter::default()
        };

        assert_eq!(
            visible_addresses(&views, &filter),
            [
                "alpha@acme.example.com",
                "Mid@acme.example.com",
                "Zeta@acme.example.com"
            ]
        );
    }

    #[test]
    fn sorting_by_last_attempt_breaks_ties_by_address() {
        let attempts = [
            attempt("a1", "zeta@acme.example.com", None, T0 - 10 * DAY, true),
            attempt("a2", "alpha@acme.example.com", None, T0 - 10 * DAY, true),
        ];
        let views = views(&attempts, &[], &[], T0);
        let filter = HistoryFilter {
            sort: HistorySort::LastAttempt,
            ..HistoryFilter::default()
        };

        assert_eq!(
            visible_addresses(&views, &filter),
            ["alpha@acme.example.com", "zeta@acme.example.com"]
        );
    }

    #[test]
    fn visible_histories_returns_indices_into_the_views_it_was_given() {
        let views = listing();
        let filter = HistoryFilter {
            sort: HistorySort::Sender,
            ..HistoryFilter::default()
        };

        for index in visible_histories(&views, &filter) {
            assert!(index < views.len(), "every index must address a real view");
        }
        let mut indices = visible_histories(&views, &filter);
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(indices.len(), views.len(), "no view listed twice or dropped");
    }

    #[test]
    fn filter_histories_yields_the_same_senders_in_the_same_order() {
        let views = listing();
        let filter = HistoryFilter {
            sort: HistorySort::Sender,
            ..HistoryFilter::default()
        };
        let expected = visible_addresses(&views, &filter);

        let owned: Vec<String> = filter_histories(views, &filter)
            .into_iter()
            .map(|view| view.sender_email)
            .collect();

        assert_eq!(owned, expected);
    }

    #[test]
    fn the_sort_cycle_visits_every_order_and_comes_back() {
        let mut sort = HistorySort::default();
        let mut seen = Vec::new();
        for _ in 0..HistorySort::ALL.len() {
            seen.push(sort);
            sort = sort.next();
        }

        assert_eq!(sort, HistorySort::default(), "the cycle closes");
        for order in HistorySort::ALL {
            assert!(seen.contains(&order), "{order:?} is reachable by cycling");
        }
    }

    // -----------------------------------------------------------------------
    // The flat event log
    // -----------------------------------------------------------------------

    /// An attempt that escalates from `earlier`, with its own method wording.
    fn escalated(
        id: &str,
        email: &str,
        at: i64,
        earlier: &str,
        method: UnsubscribeMethod,
    ) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            follows_attempt_id: Some(earlier.to_string()),
            method: method.as_id().to_string(),
            ..attempt(id, email, None, at, false)
        }
    }

    fn log_ids(entries: &[LogEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| match &entry.event {
                TimelineEvent::Attempt(attempt) => attempt.id.clone(),
                TimelineEvent::Resumption(resumption) => resumption.id.clone(),
            })
            .collect()
    }

    #[test]
    fn the_feed_lists_every_attempt_and_every_resumption_of_every_sender() {
        let attempts = [
            attempt("a1", "one@acme.example.com", None, T0 - 9 * DAY, true),
            attempt("a2", "two@beta.example.org", None, T0 - 8 * DAY, false),
        ];
        let resumptions = [resumption("r1", "a1", "one@acme.example.com", None, T0 - 7 * DAY)];

        let entries = event_log(&attempts, &resumptions);

        assert_eq!(entries.len(), 3, "nothing is grouped away");
        assert_eq!(log_ids(&entries), ["r1", "a2", "a1"]);
    }

    #[test]
    fn the_feed_is_newest_first_across_senders_rather_than_per_sender() {
        // Interleaved on purpose: a per-sender feed would keep one sender's
        // two rows together, which is not what a chronological log means.
        let attempts = [
            attempt("old-a", "aaa@acme.example.com", None, T0 - 30 * DAY, true),
            attempt("new-b", "zzz@beta.example.org", None, T0 - DAY, true),
            attempt("mid-a", "aaa@acme.example.com", None, T0 - 10 * DAY, true),
        ];

        assert_eq!(
            log_ids(&event_log(&attempts, &[])),
            ["new-b", "mid-a", "old-a"]
        );
    }

    #[test]
    fn two_events_at_the_same_instant_are_ordered_by_address_however_the_store_returned_them() {
        let forwards = [
            attempt("z", "zoe@acme.example.com", None, T0, true),
            attempt("a", "amy@acme.example.com", None, T0, true),
        ];
        let backwards = [forwards[1].clone(), forwards[0].clone()];

        assert_eq!(log_ids(&event_log(&forwards, &[])), ["a", "z"]);
        assert_eq!(
            log_ids(&event_log(&backwards, &[])),
            ["a", "z"],
            "the order must not depend on the store"
        );
    }

    #[test]
    fn an_escalated_attempt_names_the_attempt_it_follows() {
        let attempts = [
            attempt("first", "news@acme.example.com", None, T0 - 20 * DAY, false),
            escalated(
                "second",
                "news@acme.example.com",
                T0 - 10 * DAY,
                "first",
                UnsubscribeMethod::Get,
            ),
        ];

        let entries = event_log(&attempts, &[]);
        let follows = entries[0].follows.as_ref().expect("the escalation");

        assert_eq!(follows.attempt_id, "first");
        assert_eq!(follows.at, T0 - 20 * DAY);
        assert_eq!(follows.method, UnsubscribeMethod::OneClickPost.as_id());
        assert_eq!(entries[1].follows, None, "the first attempt follows nothing");
    }

    #[test]
    fn an_escalation_pointing_at_an_attempt_the_feed_does_not_hold_names_nothing() {
        // The pointed-at row can be missing: attempts are filtered by account
        // and by `--since` before they reach the feed.
        let attempts = [escalated(
            "second",
            "news@acme.example.com",
            T0,
            "pruned",
            UnsubscribeMethod::Get,
        )];

        assert_eq!(event_log(&attempts, &[])[0].follows, None);
    }

    #[test]
    fn a_resumption_never_claims_to_follow_an_attempt_even_though_it_names_one() {
        // A resumption carries `attempt_id`, but it escalates nothing -- it is
        // the observation that the attempt did not work.
        let resumptions = [resumption("r1", "a1", "news@acme.example.com", None, T0)];

        assert_eq!(event_log(&[], &resumptions)[0].follows, None);
    }

    #[test]
    fn a_resumption_takes_its_domain_from_the_address_it_is_about() {
        let resumptions = [resumption("r1", "a1", "news@acme.example.com", None, T0)];

        assert_eq!(event_log(&[], &resumptions)[0].sender_domain, "acme.example.com");
    }

    #[test]
    fn a_resumption_about_an_address_with_no_domain_part_is_still_listed() {
        let resumptions = [resumption("r1", "a1", "postmaster", None, T0)];

        let entries = event_log(&[], &resumptions);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sender_domain, "");
    }

    #[test]
    fn a_resumption_is_dated_by_when_it_was_observed_not_by_the_mail_that_proved_it() {
        let resumptions = [resumption("r1", "a1", "news@acme.example.com", None, T0)];

        let entry = &event_log(&[], &resumptions)[0];

        assert_eq!(entry.at, T0);
        assert_eq!(entry.at - DAY, resumption("r1", "a1", "x", None, T0).last_seen);
    }

    #[test]
    fn an_empty_history_yields_an_empty_feed() {
        assert!(event_log(&[], &[]).is_empty());
    }

    // -- what counts as a failure -------------------------------------------

    #[test]
    fn a_failed_attempt_and_a_resumption_are_both_failures_and_a_success_is_not() {
        let attempts = [
            attempt("ok", "one@acme.example.com", None, T0 - 3 * DAY, true),
            attempt("bad", "two@acme.example.com", None, T0 - 2 * DAY, false),
        ];
        let resumptions = [resumption("r1", "ok", "one@acme.example.com", None, T0 - DAY)];

        let entries = event_log(&attempts, &resumptions);
        let failures: Vec<bool> = entries.iter().map(LogEntry::is_failure).collect();
        let resumed: Vec<bool> = entries.iter().map(LogEntry::is_resumption).collect();

        // Newest first: r1, bad, ok.
        assert_eq!(failures, [true, true, false]);
        assert_eq!(resumed, [true, false, false]);
    }

    // -- the filter ----------------------------------------------------------

    fn feed() -> Vec<LogEntry> {
        let attempts = [
            attempt("ok", "one@acme.example.com", Some("news.acme"), T0 - 3 * DAY, true),
            attempt("bad", "two@beta.example.org", None, T0 - 2 * DAY, false),
        ];
        let resumptions = [resumption("r1", "ok", "one@acme.example.com", Some("news.acme"), T0 - DAY)];
        event_log(&attempts, &resumptions)
    }

    fn shown(entries: &[LogEntry], filter: &LogFilter) -> Vec<String> {
        visible_log(entries, filter)
            .into_iter()
            .map(|index| log_ids(&entries[index..=index]).remove(0))
            .collect()
    }

    #[test]
    fn the_default_listing_shows_everything_in_feed_order() {
        let entries = feed();

        assert_eq!(shown(&entries, &LogFilter::default()), ["r1", "bad", "ok"]);
    }

    #[test]
    fn the_failures_listing_keeps_what_did_not_work_and_drops_what_did() {
        let entries = feed();
        let filter = LogFilter {
            kind: LogKind::Failures,
            ..LogFilter::default()
        };

        assert_eq!(shown(&entries, &filter), ["r1", "bad"]);
    }

    #[test]
    fn the_resumptions_listing_drops_failed_attempts_too() {
        let entries = feed();
        let filter = LogFilter {
            kind: LogKind::Resumptions,
            ..LogFilter::default()
        };

        assert_eq!(shown(&entries, &filter), ["r1"]);
    }

    #[test]
    fn the_filter_cycle_visits_every_kind_and_comes_back_to_everything() {
        let mut kind = LogKind::default();
        let mut seen = Vec::new();
        for _ in 0..LogKind::ALL.len() {
            seen.push(kind);
            kind = kind.next();
        }

        assert_eq!(kind, LogKind::All, "the cycle closes");
        for expected in LogKind::ALL {
            assert!(seen.contains(&expected), "{expected:?} is reachable");
        }
    }

    #[test]
    fn visible_log_returns_indices_into_the_feed_it_was_handed() {
        let entries = feed();
        let filter = LogFilter {
            kind: LogKind::Resumptions,
            ..LogFilter::default()
        };

        let visible = visible_log(&entries, &filter);

        assert_eq!(visible, [0], "the resumption is the newest row");
        assert!(entries[visible[0]].is_resumption());
    }

    #[test]
    fn filtering_never_reorders_the_feed() {
        let entries = feed();
        let filter = LogFilter {
            kind: LogKind::Failures,
            ..LogFilter::default()
        };

        let visible = visible_log(&entries, &filter);

        assert!(visible.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn since_keeps_an_event_landing_exactly_on_the_boundary() {
        let entries = feed();
        let filter = LogFilter {
            since: Some(T0 - 2 * DAY),
            ..LogFilter::default()
        };

        assert_eq!(shown(&entries, &filter), ["r1", "bad"]);
    }

    // -- search --------------------------------------------------------------

    fn matches(needle: &str) -> Vec<String> {
        let entries = feed();
        let filter = LogFilter {
            search: needle.to_string(),
            ..LogFilter::default()
        };
        shown(&entries, &filter)
    }

    #[test]
    fn a_blank_search_matches_every_event() {
        assert_eq!(matches("").len(), 3);
        assert_eq!(matches("   ").len(), 3, "a needle of spaces is still blank");
    }

    #[test]
    fn a_search_matches_the_address_whatever_case_it_is_typed_in() {
        assert_eq!(matches("TWO@BETA"), ["bad"]);
        assert_eq!(matches("two@beta"), ["bad"]);
    }

    #[test]
    fn a_search_matches_the_domain_and_the_list_id() {
        assert_eq!(matches("beta.example.org"), ["bad"]);
        assert_eq!(matches("news.acme"), ["r1", "ok"]);
    }

    #[test]
    fn a_search_matches_the_method_and_the_recorded_detail_of_an_attempt() {
        let entries = feed();
        let method = LogFilter {
            search: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            ..LogFilter::default()
        };

        assert_eq!(shown(&entries, &method), ["bad", "ok"], "resumptions have no method");
        assert_eq!(matches("HTTP 200"), ["bad", "ok"]);
    }

    #[test]
    fn a_resumption_is_found_by_the_word_the_feed_uses_for_it() {
        assert_eq!(matches("resumed"), ["r1"]);
    }

    #[test]
    fn a_log_search_that_matches_nothing_shows_nothing() {
        assert!(matches("nobody@nowhere.invalid").is_empty());
    }

    #[test]
    fn a_needle_is_trimmed_before_it_is_matched() {
        assert_eq!(matches("  beta  "), ["bad"]);
    }

    #[test]
    fn a_sender_with_no_list_id_is_never_matched_by_a_list_search() {
        // "beta" is in two@beta's domain; the list needle must not leak.
        assert!(matches("news.acme").iter().all(|id| id != "bad"));
    }

    #[test]
    fn the_kind_and_the_needle_narrow_together_rather_than_one_replacing_the_other() {
        let entries = feed();
        let filter = LogFilter {
            kind: LogKind::Failures,
            search: "acme".to_string(),
            ..LogFilter::default()
        };

        assert_eq!(shown(&entries, &filter), ["r1"], "the failed attempt is at beta");
    }

    // -- a log with real volume in it ---------------------------------------

    #[test]
    fn a_few_thousand_events_stay_in_order_and_filter_correctly() {
        const N: i64 = 2_000;
        let attempts: Vec<UnsubscribeAttempt> = (0..N)
            .map(|i| {
                attempt(
                    &format!("a{i}"),
                    &format!("s{i:04}@acme.example.com"),
                    None,
                    T0 + i,
                    i % 2 == 0,
                )
            })
            .collect();
        let resumptions: Vec<Resumption> = (0..N)
            .map(|i| {
                resumption(
                    &format!("r{i}"),
                    &format!("a{i}"),
                    &format!("s{i:04}@acme.example.com"),
                    None,
                    T0 + N + i,
                )
            })
            .collect();

        let entries = event_log(&attempts, &resumptions);

        assert_eq!(entries.len(), 4_000);
        assert!(
            entries.windows(2).all(|pair| pair[0].at >= pair[1].at),
            "newest first, all the way down"
        );
        // Half the attempts failed, and every resumption is a failure.
        let failures = LogFilter {
            kind: LogKind::Failures,
            ..LogFilter::default()
        };
        assert_eq!(visible_log(&entries, &failures).len(), 1_000 + 2_000);
        // The addresses are zero-padded, so exactly one sender matches.
        let one = LogFilter {
            search: "s0007@".to_string(),
            ..LogFilter::default()
        };
        assert_eq!(visible_log(&entries, &one).len(), 2, "its attempt and its resumption");
    }

}
