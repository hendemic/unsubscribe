//! Durable record of unsubscribe attempts.
//!
//! Attempts are append-only evidence, not a cache: an attempt records what was
//! sent, where it landed, and when, so a later violation report can show that a
//! sender kept mailing after a successful unsubscribe. Nothing here can be
//! reconstructed after the fact, which is why failures are recorded too.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{SenderInfo, UnsubscribeMethod};

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
    attempts
        .iter()
        .filter(|a| a.success)
        .fold(HashMap::new(), |mut latest, attempt| {
            let key = attempt.sender_email.to_lowercase();
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

/// A scanned sender that has been successfully unsubscribed from before.
///
/// Seeing one again means the unsubscribe was ignored, which is the whole point
/// of keeping a history -- so consumers surface these first.
#[derive(Debug, Clone)]
pub struct PreviouslyUnsubscribed {
    pub sender: SenderInfo,
    /// When the last successful unsubscribe happened, in Unix seconds (UTC).
    pub unsubscribed_at: i64,
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
/// Matching is on the exact sender address, case-insensitively: a sender with
/// only failed attempts is not "previously unsubscribed", because nothing was
/// ever ignored. Pure and UI-free so the TUI and a headless server classify
/// senders the same way.
#[must_use]
pub fn split_previously_unsubscribed(
    senders: Vec<SenderInfo>,
    attempts: &[UnsubscribeAttempt],
) -> SenderSections {
    let latest = latest_successful_attempts(attempts);

    senders.into_iter().fold(
        SenderSections::default(),
        |mut sections, sender| {
            match latest.get(&sender.email.to_lowercase()) {
                Some(attempt) => sections.previously_unsubscribed.push(PreviouslyUnsubscribed {
                    unsubscribed_at: attempt.attempted_at,
                    sender,
                }),
                None => sections.remaining.push(sender),
            }
            sections
        },
    )
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
        let sections = split_previously_unsubscribed(
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
        let sections = split_previously_unsubscribed(vec![], &[success("news@acme.com", 1_000)]);
        assert!(sections.previously_unsubscribed.is_empty());
        assert!(sections.remaining.is_empty());
    }

    #[test]
    fn match_ignores_case_on_both_sides() {
        let sections = split_previously_unsubscribed(
            vec![sender("News@Acme.com")],
            &[success("NEWS@ACME.COM", 1_000)],
        );
        assert_eq!(sections.previously_unsubscribed.len(), 1);
        assert!(sections.remaining.is_empty());
    }

    #[test]
    fn same_domain_different_address_does_not_match() {
        let sections = split_previously_unsubscribed(
            vec![sender("deals@acme.com")],
            &[success("news@acme.com", 1_000)],
        );
        assert!(sections.previously_unsubscribed.is_empty());
        assert_eq!(sections.remaining.len(), 1);
    }

    #[test]
    fn a_sender_with_only_failed_attempts_is_not_previously_unsubscribed() {
        let sections = split_previously_unsubscribed(
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
        let sections = split_previously_unsubscribed(vec![sender("news@acme.com")], &attempts);
        assert_eq!(sections.previously_unsubscribed[0].unsubscribed_at, 7_500);
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
        let sections = split_previously_unsubscribed(senders, &attempts);

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
        let sections = split_previously_unsubscribed(senders, &attempts);
        assert_eq!(
            sections.previously_unsubscribed.len() + sections.remaining.len(),
            6
        );
    }
}
