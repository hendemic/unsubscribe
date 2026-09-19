//! Machine-readable shapes for `--json`.
//!
//! Every value here is a stable identifier from core -- method ids, outcome
//! names, rung ids -- never a display string, so reworded output never breaks a
//! script. The mapping lives in the CLI rather than in core because rendering
//! is a consumer concern: core's public API stays free of serialization
//! decisions, and the TUI and a future FFI consumer render the same types their
//! own way.

use serde_json::{json, Map, Value};
use unsubscribe_core::{
    Escalation, NextStep, PlannedSender, SelectionReason, SenderInfo, UnsubscribeAttempt,
    UnsubscribeOutcome, UnsubscribeResult,
};

use crate::output::SCHEMA_VERSION;

/// The envelope every result document shares.
#[must_use]
pub fn document(command: &str, account: &str) -> Map<String, Value> {
    let mut doc = Map::new();
    doc.insert("schema_version".to_string(), json!(SCHEMA_VERSION));
    doc.insert("command".to_string(), json!(command));
    doc.insert("account".to_string(), json!(account));
    doc
}

/// Who a sender is: the identity the history matches on.
#[must_use]
pub fn identity(sender: &SenderInfo) -> Value {
    json!({
        "email": sender.email,
        "display_name": sender.display_name,
        "domain": sender.domain,
        "list_id": sender.list_id,
    })
}

/// Which mechanism a sender's header offers, as `scan` reports it.
#[must_use]
pub fn offered_method(sender: &SenderInfo) -> &'static str {
    if sender.one_click {
        "one_click"
    } else if !sender.unsubscribe_urls.is_empty() {
        "http"
    } else {
        "mailto"
    }
}

/// What a sender has done since a successful unsubscribe.
#[must_use]
pub fn outcome(outcome: UnsubscribeOutcome) -> Value {
    match outcome {
        UnsubscribeOutcome::NoNewMail => json!({ "state": "no_new_mail" }),
        UnsubscribeOutcome::WithinGrace { days_left } => json!({
            "state": "within_grace",
            "days_left": days_left,
        }),
        UnsubscribeOutcome::Resumed { days_after } => json!({
            "state": "resumed",
            "days_after": days_after,
        }),
    }
}

/// The rung an escalation climbs to, and the one it answers.
#[must_use]
pub fn escalation(escalation: &Escalation) -> Value {
    json!({
        "method": escalation.rung.method.as_id(),
        "target": escalation.rung.target,
        "from": escalation.from.map(|m| m.as_id()),
        "follows_attempt_id": escalation.follows_attempt_id,
    })
}

/// What the ladder says to do about a sender next.
#[must_use]
pub fn next_step(step: &NextStep) -> Value {
    match step {
        NextStep::FirstAttempt => json!({ "kind": "first_attempt" }),
        NextStep::Escalate(e) => {
            let mut value = json!({ "kind": "escalate" });
            merge(&mut value, escalation(e));
            value
        }
        NextStep::Exhausted => json!({ "kind": "exhausted" }),
    }
}

/// One attempt's outcome, field for field.
#[must_use]
pub fn result(result: &UnsubscribeResult) -> Value {
    json!({
        "method": result.method.as_id(),
        "success": result.success,
        "detail": result.detail,
        "url": result.url,
        "http_status": result.http_status,
        "final_url": result.final_url,
    })
}

/// One recorded attempt, as the history holds it.
#[must_use]
pub fn attempt(attempt: &UnsubscribeAttempt) -> Value {
    json!({
        "id": attempt.id,
        "sender_email": attempt.sender_email,
        "sender_domain": attempt.sender_domain,
        "list_id": attempt.list_id,
        "attempted_at": attempt.attempted_at,
        "method": attempt.method,
        "success": attempt.success,
        "http_status": attempt.http_status,
        "url": attempt.url,
        "final_url": attempt.final_url,
        "follows_attempt_id": attempt.follows_attempt_id,
        "detail": attempt.detail,
    })
}

/// A sender the run planned to unsubscribe from, before it was attempted.
#[must_use]
pub fn planned(planned: &PlannedSender, reason: Option<SelectionReason>) -> Value {
    let mut value = identity(&planned.sender);
    merge(
        &mut value,
        json!({
            "email_count": planned.sender.email_count,
            "messages": planned.sender.messages.len(),
            "selection_reason": reason.map(SelectionReason::as_id),
            "action": "unsubscribe",
            "next_step": next_step(&planned.step),
        }),
    );
    value
}

/// Fold `extra`'s fields into `target`. Both are expected to be objects.
pub fn merge(target: &mut Value, extra: Value) {
    let (Some(target), Value::Object(extra)) = (target.as_object_mut(), extra) else {
        return;
    };
    target.extend(extra);
}
