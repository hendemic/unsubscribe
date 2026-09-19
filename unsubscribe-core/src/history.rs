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
