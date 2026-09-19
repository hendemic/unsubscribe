//! Durable record of unsubscribe attempts.
//!
//! Attempts are append-only evidence, not a cache: an attempt records what was
//! sent, where it landed, and when, so a later violation report can show that a
//! sender kept mailing after a successful unsubscribe. Nothing here can be
//! reconstructed after the fact, which is why failures are recorded too.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{SenderInfo, UnsubscribeMethod, UnsubscribeResult};

/// One recorded unsubscribe attempt against one sender.
///
/// Every evidence-relevant value is its own field -- `detail` is the
/// human-readable summary and is never the only place a fact lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeAttempt {
    /// UUID for this attempt. Histories from two devices merge as a union of
    /// events, so ids are globally unique rather than sequential.
    pub id: String,
    /// Account the attempt was made from.
    pub account: String,
    /// Sender address the attempt was made against.
    pub sender_email: String,
    /// Domain of `sender_email`.
    pub sender_domain: String,
    /// RFC 2919 list identifier, when the sender's mail carried one.
    pub list_id: Option<String>,
    /// When the attempt completed, in Unix seconds (UTC).
    pub attempted_at: i64,
    /// Stable `UnsubscribeMethod` identifier (see [`UnsubscribeMethod::as_id`]).
    pub method: String,
    /// Whether the attempt appeared to succeed.
    pub success: bool,
    /// Status of the final HTTP response, when the attempt made one.
    pub http_status: Option<u16>,
    /// URL the attempt targeted.
    pub url: String,
    /// URL the attempt ended on after redirects, when known.
    pub final_url: Option<String>,
    /// The `List-Unsubscribe` header as received, kept verbatim as evidence.
    pub list_unsubscribe_raw: Option<String>,
    /// Human-readable summary of the outcome.
    pub detail: String,
}

impl UnsubscribeAttempt {
    /// Build an attempt with a freshly generated id.
    ///
    /// Callers pass the method as an enum; it is stored as its stable
    /// identifier so the record survives renames of the display labels.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        account: String,
        sender_email: String,
        sender_domain: String,
        list_id: Option<String>,
        attempted_at: i64,
        method: UnsubscribeMethod,
        success: bool,
        http_status: Option<u16>,
        url: String,
        final_url: Option<String>,
        list_unsubscribe_raw: Option<String>,
        detail: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            account,
            sender_email,
            sender_domain,
            list_id,
            attempted_at,
            method: method.as_id().to_string(),
            success,
            http_status,
            url,
            final_url,
            list_unsubscribe_raw,
            detail,
        }
    }

    /// Build the history record for a completed attempt.
    ///
    /// The sender supplies the identity evidence (domain, list id, the raw
    /// `List-Unsubscribe` header) and the result supplies what the attempt
    /// did. `attempted_at` is passed in rather than read from the clock so
    /// the mapping stays testable and the caller decides what "now" means.
    #[must_use]
    pub fn from_result(
        account: &str,
        sender: &SenderInfo,
        result: &UnsubscribeResult,
        attempted_at: i64,
    ) -> Self {
        Self::new(
            account.to_string(),
            sender.email.clone(),
            sender.domain.clone(),
            sender.list_id.clone(),
            attempted_at,
            result.method,
            result.success,
            result.http_status,
            result.url.clone(),
            result.final_url.clone(),
            sender.list_unsubscribe_raw.clone(),
            result.detail.clone(),
        )
    }
}

/// Reduce a history to the most recent *successful* attempt per sender address.
///
/// Keys are lowercased sender addresses, so callers match scanned senders
/// case-insensitively. Failures are ignored: a sender that was never
/// successfully unsubscribed from has nothing to have ignored.
#[must_use]
pub fn latest_successful_attempts(
    attempts: &[UnsubscribeAttempt],
) -> HashMap<String, UnsubscribeAttempt> {
    latest_successful_by(attempts, |attempt| {
        Some(attempt.sender_email.to_lowercase())
    })
}

/// The same reduction keyed by RFC 2919 `List-Id`, skipping attempts that
/// carried none.
///
/// Senders rotate From addresses and send through ESPs, so the list identifier
/// is the stabler half of a sender's identity and is tried first.
#[must_use]
pub fn latest_successful_attempts_by_list_id(
    attempts: &[UnsubscribeAttempt],
) -> HashMap<String, UnsubscribeAttempt> {
    latest_successful_by(attempts, |attempt| normalized_list_id(attempt.list_id.as_deref()))
}

/// Keep the newest successful attempt per key, ignoring attempts with no key.
fn latest_successful_by(
    attempts: &[UnsubscribeAttempt],
    key_of: impl Fn(&UnsubscribeAttempt) -> Option<String>,
) -> HashMap<String, UnsubscribeAttempt> {
    attempts
        .iter()
        .filter(|a| a.success)
        .filter_map(|attempt| key_of(attempt).map(|key| (key, attempt)))
        .fold(HashMap::new(), |mut latest, (key, attempt)| {
            let keep = latest
                .get(&key)
                .is_none_or(|existing: &UnsubscribeAttempt| {
                    attempt.attempted_at >= existing.attempted_at
                });
            if keep {
                latest.insert(key, attempt.clone());
            }
            latest
        })
}

/// A `List-Id` trimmed and lowercased, or `None` when there is nothing usable.
fn normalized_list_id(list_id: Option<&str>) -> Option<String> {
    list_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_lowercase)
}

/// An account's successful unsubscribes, indexed the two ways a sender can be
/// recognised.
///
/// Built once per run and asked about each scanned sender, because the answer
/// drives both what the screens show and whether a resumption gets recorded.
#[derive(Debug, Clone, Default)]
pub struct LatestAttempts {
    by_list_id: HashMap<String, UnsubscribeAttempt>,
    by_email: HashMap<String, UnsubscribeAttempt>,
}

impl LatestAttempts {
    /// Index an account's history.
    #[must_use]
    pub fn from_history(attempts: &[UnsubscribeAttempt]) -> Self {
        Self {
            by_list_id: latest_successful_attempts_by_list_id(attempts),
            by_email: latest_successful_attempts(attempts),
        }
    }

    /// The successful attempt this sender's history hangs off.
    ///
    /// `List-Id` wins when both the sender and a recorded attempt carry one,
    /// since the address may since have rotated; otherwise the address decides,
    /// case-insensitively.
    #[must_use]
    pub fn for_sender(&self, sender: &SenderInfo) -> Option<&UnsubscribeAttempt> {
        normalized_list_id(sender.list_id.as_deref())
            .and_then(|id| self.by_list_id.get(&id))
            .or_else(|| self.by_email.get(&sender.email.to_lowercase()))
    }

    /// Whether the account has any successful unsubscribe on record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_list_id.is_empty() && self.by_email.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Resumptions: senders that ignored a successful unsubscribe
// ---------------------------------------------------------------------------

/// One observation that a sender kept mailing after a successful unsubscribe.
///
/// Append-only evidence like an attempt, and keyed to the attempt that was
/// ignored, so a violation report can show the pair: this is when they were
/// told, this is what arrived afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resumption {
    /// UUID for this observation.
    pub id: String,
    /// Account the mail arrived in.
    pub account: String,
    /// Sender address as the scan saw it.
    pub sender_email: String,
    /// RFC 2919 list identifier, when the sender's mail carried one.
    pub list_id: Option<String>,
    /// Id of the successful attempt that was ignored. At most one resumption
    /// is ever recorded per attempt.
    pub attempt_id: String,
    /// When the observation was made, in Unix seconds (UTC).
    pub observed_at: i64,
    /// Date of the newest message seen from the sender, in Unix seconds (UTC).
    pub last_seen: i64,
    /// How many messages the scan attributed to the sender.
    pub email_count: u32,
}

impl Resumption {
    /// Build an observation with a freshly generated id.
    #[must_use]
    pub fn new(
        account: String,
        sender_email: String,
        list_id: Option<String>,
        attempt_id: String,
        observed_at: i64,
        last_seen: i64,
        email_count: u32,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            account,
            sender_email,
            list_id,
            attempt_id,
            observed_at,
            last_seen,
            email_count,
        }
    }

    /// Whether this observation is about the same sender as `sender`.
    ///
    /// Matched the same way attempts are: `List-Id` when both sides have one,
    /// the address otherwise.
    #[must_use]
    pub fn is_about(&self, sender: &SenderInfo) -> bool {
        match (
            normalized_list_id(self.list_id.as_deref()),
            normalized_list_id(sender.list_id.as_deref()),
        ) {
            (Some(recorded), Some(scanned)) => recorded == scanned,
            _ => self.sender_email.eq_ignore_ascii_case(&sender.email),
        }
    }
}

/// What a sender has done since a successful unsubscribe.
///
/// "Success" is not an HTTP 200 -- it is the mail stopping -- so this is the
/// measurement that decides whether the loop is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsubscribeOutcome {
    /// Nothing arrived after the unsubscribe, or the scan could not date the
    /// sender's mail. Unknown is not a violation.
    NoNewMail,
    /// Mail arrived, but inside the window the sender is allowed to act in.
    WithinGrace {
        /// Whole days left before the window closes; zero once it has.
        days_left: i64,
    },
    /// Mail arrived after the window closed: the unsubscribe was ignored.
    Resumed {
        /// Whole days between the unsubscribe and the newest message seen.
        days_after: i64,
    },
}

impl UnsubscribeOutcome {
    /// Whether this sender ignored its unsubscribe.
    #[must_use]
    pub fn is_resumed(&self) -> bool {
        matches!(self, Self::Resumed { .. })
    }
}

/// Seconds in a day, for turning timestamps into the whole days people read.
const SECS_PER_DAY: i64 = 24 * 60 * 60;

/// Judge one sender's mail against the unsubscribe that was supposed to stop it.
///
/// Pure, and the grace period arrives as an argument: what counts as "long
/// enough to act" is the user's setting, not core's opinion. `last_seen` is
/// the newest message the scan attributed to the sender.
#[must_use]
pub fn classify_outcome(
    unsubscribed_at: i64,
    last_seen: Option<i64>,
    now: i64,
    grace_period_days: u32,
) -> UnsubscribeOutcome {
    // An undated sender says nothing either way, and a message at or before
    // the attempt is the mail we archived, not new mail.
    let Some(last_seen) = last_seen.filter(|seen| *seen > unsubscribed_at) else {
        return UnsubscribeOutcome::NoNewMail;
    };

    let grace_ends_at = unsubscribed_at + i64::from(grace_period_days) * SECS_PER_DAY;
    if last_seen <= grace_ends_at {
        return UnsubscribeOutcome::WithinGrace {
            days_left: (grace_ends_at - now).div_euclid(SECS_PER_DAY).max(0),
        };
    }

    UnsubscribeOutcome::Resumed {
        days_after: (last_seen - unsubscribed_at).div_euclid(SECS_PER_DAY),
    }
}

/// What the history says about a scanned sender that was unsubscribed before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderVerdict {
    /// Id of the successful attempt being judged -- what a resumption is
    /// recorded against.
    pub attempt_id: String,
    /// When that attempt succeeded, in Unix seconds (UTC).
    pub unsubscribed_at: i64,
    /// What has arrived since.
    pub outcome: UnsubscribeOutcome,
    /// Resumptions on record for this sender, counting one observed just now.
    pub violation_count: u32,
}

/// Judge a scanned sender against an account's history.
///
/// `None` means the sender has no successful unsubscribe behind it: nothing
/// was ever ignored, so there is nothing to measure.
#[must_use]
pub fn judge_sender(
    sender: &SenderInfo,
    latest: &LatestAttempts,
    resumptions: &[Resumption],
    now: i64,
    grace_period_days: u32,
) -> Option<SenderVerdict> {
    let attempt = latest.for_sender(sender)?;
    let outcome = classify_outcome(
        attempt.attempted_at,
        sender.last_seen,
        now,
        grace_period_days,
    );

    let recorded = resumptions.iter().filter(|r| r.is_about(sender)).count() as u32;
    // A resumption we are about to record for the first time still counts
    // towards what the user is shown.
    let newly_observed = u32::from(
        outcome.is_resumed()
            && !resumptions
                .iter()
                .any(|r| r.attempt_id == attempt.id),
    );

    Some(SenderVerdict {
        attempt_id: attempt.id.clone(),
        unsubscribed_at: attempt.attempted_at,
        outcome,
        violation_count: recorded + newly_observed,
    })
}

/// A scanned sender that has been successfully unsubscribed from before.
///
/// Seeing one again means the unsubscribe may have been ignored, which is the
/// whole point of keeping a history -- so consumers surface these first.
#[derive(Debug, Clone)]
pub struct PreviouslyUnsubscribed {
    pub sender: SenderInfo,
    pub verdict: SenderVerdict,
}

impl PreviouslyUnsubscribed {
    /// When the last successful unsubscribe happened, in Unix seconds (UTC).
    #[must_use]
    pub fn unsubscribed_at(&self) -> i64 {
        self.verdict.unsubscribed_at
    }

    /// The observation to record when this sender ignored its unsubscribe and
    /// that has not been recorded yet.
    #[must_use]
    pub fn new_resumption(&self, account: &str, known: &[Resumption], observed_at: i64) -> Option<Resumption> {
        let UnsubscribeOutcome::Resumed { .. } = self.verdict.outcome else {
            return None;
        };
        // At most one per ignored attempt: seeing the same one on a later scan
        // records nothing new.
        if known
            .iter()
            .any(|r| r.attempt_id == self.verdict.attempt_id)
        {
            return None;
        }
        Some(Resumption::new(
            account.to_string(),
            self.sender.email.clone(),
            self.sender.list_id.clone(),
            self.verdict.attempt_id.clone(),
            observed_at,
            self.sender.last_seen.unwrap_or(observed_at),
            self.sender.email_count,
        ))
    }
}

/// Scanned senders split by whether they have been unsubscribed from before.
#[derive(Debug, Clone, Default)]
pub struct SenderSections {
    /// Senders with a prior successful unsubscribe, in their scanned order.
    pub previously_unsubscribed: Vec<PreviouslyUnsubscribed>,
    /// Everything else, in their scanned order.
    pub remaining: Vec<SenderInfo>,
}

/// Split scanned senders against an account's unsubscribe history.
///
/// A sender with only failed attempts is not "previously unsubscribed",
/// because nothing was ever ignored. Pure and UI-free so the TUI and a headless
/// server classify senders the same way.
#[must_use]
pub fn split_previously_unsubscribed(
    senders: Vec<SenderInfo>,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
    now: i64,
    grace_period_days: u32,
) -> SenderSections {
    let latest = LatestAttempts::from_history(attempts);

    senders
        .into_iter()
        .fold(SenderSections::default(), |mut sections, sender| {
            match judge_sender(&sender, &latest, resumptions, now, grace_period_days) {
                Some(verdict) => sections
                    .previously_unsubscribed
                    .push(PreviouslyUnsubscribed { sender, verdict }),
                None => sections.remaining.push(sender),
            }
            sections
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UnsubscribeMethod;

    /// A successful attempt against `sender_email` at `attempted_at`.
    fn success(sender_email: &str, attempted_at: i64) -> UnsubscribeAttempt {
        attempt(sender_email, attempted_at, true)
    }

    /// A failed attempt against `sender_email` at `attempted_at`.
    fn failure(sender_email: &str, attempted_at: i64) -> UnsubscribeAttempt {
        attempt(sender_email, attempted_at, false)
    }

    fn attempt(sender_email: &str, attempted_at: i64, success: bool) -> UnsubscribeAttempt {
        UnsubscribeAttempt::new(
            "user@example.com".to_string(),
            sender_email.to_string(),
            sender_email.rsplit('@').next().unwrap_or("").to_string(),
            None,
            attempted_at,
            UnsubscribeMethod::OneClickPost,
            success,
            Some(200),
            "https://example.com/unsub".to_string(),
            None,
            None,
            "HTTP 200".to_string(),
        )
    }

    /// Split with no resumptions on record and the default grace period,
    /// which is all these matching tests care about.
    fn split(senders: Vec<SenderInfo>, attempts: &[UnsubscribeAttempt]) -> SenderSections {
        split_previously_unsubscribed(senders, attempts, &[], 10_000, 14)
    }

    fn sender(email: &str) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: Vec::new(),
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 1,
            messages: Vec::new(),
            last_seen: None,
        }
    }

    // -----------------------------------------------------------------------
    // latest_successful_attempts
    // -----------------------------------------------------------------------

    #[test]
    fn empty_history_reduces_to_nothing() {
        assert!(latest_successful_attempts(&[]).is_empty());
    }

    #[test]
    fn most_recent_success_wins_over_earlier_ones() {
        let attempts = vec![
            success("news@acme.com", 1_000),
            success("news@acme.com", 3_000),
            success("news@acme.com", 2_000),
        ];
        let latest = latest_successful_attempts(&attempts);
        assert_eq!(latest.len(), 1);
        assert_eq!(latest["news@acme.com"].attempted_at, 3_000);
    }

    #[test]
    fn a_later_failure_does_not_erase_an_earlier_success() {
        let attempts = vec![
            success("news@acme.com", 1_000),
            failure("news@acme.com", 9_000),
        ];
        let latest = latest_successful_attempts(&attempts);
        assert_eq!(latest["news@acme.com"].attempted_at, 1_000);
    }

    #[test]
    fn senders_with_only_failures_are_absent() {
        let attempts = vec![
            failure("news@acme.com", 1_000),
            failure("news@acme.com", 2_000),
        ];
        assert!(latest_successful_attempts(&attempts).is_empty());
    }

    #[test]
    fn distinct_senders_each_keep_their_own_latest_success() {
        let attempts = vec![
            success("news@acme.com", 1_000),
            success("deals@other.com", 5_000),
            success("news@acme.com", 2_000),
        ];
        let latest = latest_successful_attempts(&attempts);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest["news@acme.com"].attempted_at, 2_000);
        assert_eq!(latest["deals@other.com"].attempted_at, 5_000);
    }

    #[test]
    fn keys_are_lowercased_regardless_of_recorded_casing() {
        let attempts = vec![success("News@Acme.COM", 1_000)];
        let latest = latest_successful_attempts(&attempts);
        assert!(latest.contains_key("news@acme.com"));
        // The stored attempt keeps the address exactly as it was recorded.
        assert_eq!(latest["news@acme.com"].sender_email, "News@Acme.COM");
    }

    #[test]
    fn case_variants_of_one_address_collapse_to_one_entry() {
        let attempts = vec![
            success("news@acme.com", 1_000),
            success("NEWS@ACME.COM", 4_000),
        ];
        let latest = latest_successful_attempts(&attempts);
        assert_eq!(latest.len(), 1);
        assert_eq!(latest["news@acme.com"].attempted_at, 4_000);
    }

    // -----------------------------------------------------------------------
    // split_previously_unsubscribed
    // -----------------------------------------------------------------------

    #[test]
    fn no_history_leaves_every_sender_in_remaining() {
        let sections = split(
            vec![sender("a@acme.com"), sender("b@acme.com")],
            &[],
        );
        assert!(sections.previously_unsubscribed.is_empty());
        assert_eq!(
            sections.remaining.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["a@acme.com", "b@acme.com"]
        );
    }

    #[test]
    fn no_senders_yields_empty_sections() {
        let sections = split(vec![], &[success("news@acme.com", 1_000)]);
        assert!(sections.previously_unsubscribed.is_empty());
        assert!(sections.remaining.is_empty());
    }

    #[test]
    fn match_ignores_case_on_both_sides() {
        let sections = split(
            vec![sender("News@Acme.com")],
            &[success("NEWS@ACME.COM", 1_000)],
        );
        assert_eq!(sections.previously_unsubscribed.len(), 1);
        assert!(sections.remaining.is_empty());
    }

    #[test]
    fn same_domain_different_address_does_not_match() {
        let sections = split(
            vec![sender("deals@acme.com")],
            &[success("news@acme.com", 1_000)],
        );
        assert!(sections.previously_unsubscribed.is_empty());
        assert_eq!(sections.remaining.len(), 1);
    }

    #[test]
    fn a_sender_with_only_failed_attempts_is_not_previously_unsubscribed() {
        let sections = split(
            vec![sender("news@acme.com")],
            &[failure("news@acme.com", 1_000)],
        );
        assert!(sections.previously_unsubscribed.is_empty());
        assert_eq!(sections.remaining.len(), 1);
    }

    #[test]
    fn unsubscribed_at_is_the_latest_successful_attempt() {
        let attempts = vec![
            success("news@acme.com", 1_000),
            success("news@acme.com", 7_500),
            failure("news@acme.com", 9_000),
        ];
        let sections = split(vec![sender("news@acme.com")], &attempts);
        assert_eq!(sections.previously_unsubscribed[0].unsubscribed_at(), 7_500);
    }

    #[test]
    fn both_sections_keep_their_scanned_order() {
        let senders = vec![
            sender("p1@acme.com"),
            sender("r1@acme.com"),
            sender("p2@acme.com"),
            sender("r2@acme.com"),
        ];
        let attempts = vec![success("p1@acme.com", 1), success("p2@acme.com", 2)];
        let sections = split(senders, &attempts);

        assert_eq!(
            sections
                .previously_unsubscribed
                .iter()
                .map(|p| p.sender.email.as_str())
                .collect::<Vec<_>>(),
            ["p1@acme.com", "p2@acme.com"]
        );
        assert_eq!(
            sections.remaining.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["r1@acme.com", "r2@acme.com"]
        );
    }

    #[test]
    fn every_sender_lands_in_exactly_one_section() {
        let senders: Vec<_> = (0..6).map(|i| sender(&format!("s{i}@acme.com"))).collect();
        let attempts = vec![success("s1@acme.com", 1), success("s4@acme.com", 1)];
        let sections = split(senders, &attempts);
        assert_eq!(
            sections.previously_unsubscribed.len() + sections.remaining.len(),
            6
        );
    }
}

/// Mapping a finished attempt onto its history record.
///
/// These moved here with `UnsubscribeAttempt::from_result` when the run
/// pipeline took over recording; they check the same evidence fields they
/// always did.
#[cfg(test)]
mod from_result_tests {
    use super::*;
    use crate::types::{UnsubscribeMethod, UnsubscribeResult};
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
        if [8, 4, 4, 4, 12]
            != [
                groups[0].len(),
                groups[1].len(),
                groups[2].len(),
                groups[3].len(),
                groups[4].len(),
            ]
        {
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
        let attempt = UnsubscribeAttempt::from_result(
            "me@example.com",
            &evidence_sender(),
            &successful_result(),
            1_700_000_500,
        );

        assert_eq!(attempt.account, "me@example.com");
        assert_eq!(attempt.sender_email, "news@acme.com");
        assert_eq!(attempt.sender_domain, "acme.com");
        assert_eq!(attempt.list_id.as_deref(), Some("weekly.acme.com"));
        assert_eq!(attempt.attempted_at, 1_700_000_500);
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
        let attempt = UnsubscribeAttempt::from_result(
            "me@gmail.com",
            &evidence_sender(),
            &successful_result(),
            0,
        );
        assert_eq!(attempt.sender_domain, "acme.com");
        assert_eq!(attempt.account, "me@gmail.com");
    }

    #[test]
    fn attempt_stores_the_stable_method_id_not_the_display_label() {
        // MailtoSent is the case where the two differ: id "mailto_sent",
        // label "mailto". Storing the label would break history on a rename.
        let mut result = successful_result();
        result.method = UnsubscribeMethod::MailtoSent;

        let attempt =
            UnsubscribeAttempt::from_result("me@example.com", &evidence_sender(), &result, 0);

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

        let attempt =
            UnsubscribeAttempt::from_result("me@example.com", &evidence_sender(), &result, 0);

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

        let attempt = UnsubscribeAttempt::from_result("me@example.com", &sender, &result, 0);

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
            .map(|_| UnsubscribeAttempt::from_result("me@example.com", &sender, &result, 0).id)
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
    fn attempted_at_is_the_timestamp_the_caller_supplied() {
        // The clock is the caller's business now; the mapping must not
        // substitute one of its own.
        let attempt = UnsubscribeAttempt::from_result(
            "me@example.com",
            &evidence_sender(),
            &successful_result(),
            -42,
        );
        assert_eq!(attempt.attempted_at, -42);
    }
}
