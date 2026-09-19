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

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::{
        Folder, FolderMessage, MessageId, NextStep, Rung, RungMethod, UnsubscribeMethod,
    };

    fn sender() -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: "news@acme.example.com".to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/u?id=1".to_string()],
            unsubscribe_mailto: vec!["mailto:leave@acme.example.com".to_string()],
            one_click: true,
            list_id: Some("acme.list.example.com".to_string()),
            list_unsubscribe_raw: Some("<https://acme.example.com/u?id=1>".to_string()),
            email_count: 7,
            messages: vec![
                FolderMessage {
                    folder: Folder::new("INBOX"),
                    message_id: MessageId::new("INBOX:1"),
                },
                FolderMessage {
                    folder: Folder::new("Promotions"),
                    message_id: MessageId::new("Promotions:2"),
                },
            ],
            last_seen: Some(1_700_000_000),
        }
    }

    // -----------------------------------------------------------------------
    // Envelope and identity
    // -----------------------------------------------------------------------

    #[test]
    fn every_document_says_which_schema_and_command_produced_it() {
        let doc = Value::Object(document("scan", "user@example.com"));
        assert_eq!(doc["schema_version"], json!(SCHEMA_VERSION));
        assert_eq!(doc["command"], json!("scan"));
        assert_eq!(doc["account"], json!("user@example.com"));
    }

    #[test]
    fn identity_carries_the_fields_history_matches_on() {
        assert_eq!(
            identity(&sender()),
            json!({
                "email": "news@acme.example.com",
                "display_name": "Acme News",
                "domain": "acme.example.com",
                "list_id": "acme.list.example.com",
            })
        );
    }

    #[test]
    fn a_sender_with_no_list_id_reports_null_rather_than_omitting_the_field() {
        // A script reads `list_id` on every row; a missing key is a different
        // shape from a sender that carries no list identifier.
        let mut sender = sender();
        sender.list_id = None;
        assert_eq!(identity(&sender)["list_id"], Value::Null);
    }

    // -----------------------------------------------------------------------
    // offered_method
    // -----------------------------------------------------------------------

    #[test]
    fn one_click_is_reported_whenever_the_header_offers_it() {
        assert_eq!(offered_method(&sender()), "one_click");
    }

    #[test]
    fn a_plain_http_url_is_reported_when_one_click_is_not_offered() {
        let mut sender = sender();
        sender.one_click = false;
        assert_eq!(offered_method(&sender), "http");
    }

    #[test]
    fn mailto_is_reported_only_when_there_is_no_url_at_all() {
        let mut sender = sender();
        sender.one_click = false;
        sender.unsubscribe_urls.clear();
        assert_eq!(offered_method(&sender), "mailto");
    }

    // -----------------------------------------------------------------------
    // Outcomes
    // -----------------------------------------------------------------------

    #[test]
    fn each_outcome_is_a_stable_state_with_its_own_measurement() {
        assert_eq!(
            outcome(UnsubscribeOutcome::NoNewMail),
            json!({ "state": "no_new_mail" })
        );
        assert_eq!(
            outcome(UnsubscribeOutcome::WithinGrace { days_left: 4 }),
            json!({ "state": "within_grace", "days_left": 4 })
        );
        assert_eq!(
            outcome(UnsubscribeOutcome::Resumed { days_after: 20 }),
            json!({ "state": "resumed", "days_after": 20 })
        );
    }

    // -----------------------------------------------------------------------
    // Next step
    // -----------------------------------------------------------------------

    #[test]
    fn a_first_attempt_is_a_kind_with_nothing_else_to_say() {
        assert_eq!(next_step(&NextStep::FirstAttempt), json!({ "kind": "first_attempt" }));
    }

    #[test]
    fn an_exhausted_sender_is_reported_as_such_rather_than_omitted() {
        assert_eq!(next_step(&NextStep::Exhausted), json!({ "kind": "exhausted" }));
    }

    #[test]
    fn an_escalation_names_the_rung_it_climbs_to_and_the_one_it_answers() {
        let step = NextStep::Escalate(Escalation {
            rung: Rung::new(RungMethod::HttpFlow, "https://acme.example.com/u?id=1"),
            from: Some(RungMethod::OneClickPost),
            follows_attempt_id: Some("attempt-1".to_string()),
        });
        assert_eq!(
            next_step(&step),
            json!({
                "kind": "escalate",
                "method": "http_flow",
                "target": "https://acme.example.com/u?id=1",
                "from": "one_click_post",
                "follows_attempt_id": "attempt-1",
            })
        );
    }

    #[test]
    fn an_escalation_that_answers_nothing_reports_null_for_what_it_follows() {
        let escalated = escalation(&Escalation {
            rung: Rung::new(RungMethod::Mailto, "mailto:leave@acme.example.com"),
            from: None,
            follows_attempt_id: None,
        });
        assert_eq!(escalated["from"], Value::Null);
        assert_eq!(escalated["follows_attempt_id"], Value::Null);
        assert_eq!(escalated["method"], json!("mailto"));
    }

    // -----------------------------------------------------------------------
    // Results and attempts
    // -----------------------------------------------------------------------

    #[test]
    fn a_result_reports_the_method_id_rather_than_its_label() {
        let value = result(&UnsubscribeResult {
            email: "news@acme.example.com".to_string(),
            method: UnsubscribeMethod::OneClickPost,
            success: true,
            detail: "HTTP 200".to_string(),
            url: "https://acme.example.com/u?id=1".to_string(),
            http_status: Some(200),
            final_url: Some("https://acme.example.com/done".to_string()),
        });
        assert_eq!(value["method"], json!("one_click_post"));
        assert_eq!(value["success"], json!(true));
        assert_eq!(value["http_status"], json!(200));
        assert_eq!(value["final_url"], json!("https://acme.example.com/done"));
        // The address lives on the row, not inside the result.
        assert_eq!(value.get("email"), None);
    }

    #[test]
    fn a_failed_result_still_carries_every_field_a_report_would_need() {
        let value = result(&UnsubscribeResult {
            email: "news@acme.example.com".to_string(),
            method: UnsubscribeMethod::MailtoFailed,
            success: false,
            detail: "SMTP refused the message".to_string(),
            url: "mailto:leave@acme.example.com".to_string(),
            http_status: None,
            final_url: None,
        });
        assert_eq!(value["success"], json!(false));
        assert_eq!(value["detail"], json!("SMTP refused the message"));
        assert_eq!(value["http_status"], Value::Null);
        assert_eq!(value["final_url"], Value::Null);
    }

    #[test]
    fn a_recorded_attempt_is_reported_field_for_field() {
        let recorded = UnsubscribeAttempt {
            id: "attempt-1".to_string(),
            account: "user@example.com".to_string(),
            sender_email: "news@acme.example.com".to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: Some("acme.list.example.com".to_string()),
            attempted_at: 1_700_000_000,
            method: "one_click_post".to_string(),
            success: true,
            http_status: Some(200),
            url: "https://acme.example.com/u?id=1".to_string(),
            final_url: None,
            list_unsubscribe_raw: Some("<https://acme.example.com/u?id=1>".to_string()),
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        };
        let value = attempt(&recorded);
        assert_eq!(value["id"], json!("attempt-1"));
        assert_eq!(value["attempted_at"], json!(1_700_000_000_i64));
        assert_eq!(value["method"], json!("one_click_post"));
        assert_eq!(value["list_id"], json!("acme.list.example.com"));
        // The account is on the envelope; repeating it on every row would be
        // noise and a second place for it to disagree.
        assert_eq!(value.get("account"), None);
    }

    // -----------------------------------------------------------------------
    // Planned senders
    // -----------------------------------------------------------------------

    #[test]
    fn a_planned_sender_carries_its_identity_its_reason_and_its_next_step() {
        let value = planned(
            &PlannedSender {
                sender: sender(),
                step: NextStep::FirstAttempt,
            },
            Some(SelectionReason::Resumed),
        );
        assert_eq!(value["email"], json!("news@acme.example.com"));
        assert_eq!(value["list_id"], json!("acme.list.example.com"));
        assert_eq!(value["email_count"], json!(7));
        assert_eq!(value["messages"], json!(2));
        assert_eq!(value["selection_reason"], json!("resumed"));
        assert_eq!(value["action"], json!("unsubscribe"));
        assert_eq!(value["next_step"], json!({ "kind": "first_attempt" }));
    }

    #[test]
    fn a_sender_chosen_on_a_screen_has_no_policy_reason_to_report() {
        let value = planned(
            &PlannedSender {
                sender: sender(),
                step: NextStep::FirstAttempt,
            },
            None,
        );
        assert_eq!(value["selection_reason"], Value::Null);
    }

    #[test]
    fn the_message_count_is_the_messages_in_hand_not_the_lifetime_total() {
        // `email_count` is what the scan attributed to the sender;
        // `messages` is how many this run can actually archive.
        let value = planned(
            &PlannedSender {
                sender: sender(),
                step: NextStep::Exhausted,
            },
            None,
        );
        assert_ne!(value["email_count"], value["messages"]);
        assert_eq!(value["messages"], json!(2));
    }

    // -----------------------------------------------------------------------
    // merge
    // -----------------------------------------------------------------------

    #[test]
    fn merging_folds_the_extra_fields_in_beside_the_existing_ones() {
        let mut target = json!({ "a": 1 });
        merge(&mut target, json!({ "b": 2 }));
        assert_eq!(target, json!({ "a": 1, "b": 2 }));
    }

    #[test]
    fn a_merged_field_replaces_one_of_the_same_name() {
        let mut target = json!({ "a": 1 });
        merge(&mut target, json!({ "a": 2 }));
        assert_eq!(target, json!({ "a": 2 }));
    }

    #[test]
    fn merging_something_that_is_not_an_object_leaves_the_target_alone() {
        let mut target = json!({ "a": 1 });
        merge(&mut target, json!([1, 2, 3]));
        merge(&mut target, Value::Null);
        assert_eq!(target, json!({ "a": 1 }));
    }

    #[test]
    fn merging_into_something_that_is_not_an_object_changes_nothing() {
        let mut target = json!([1]);
        merge(&mut target, json!({ "a": 1 }));
        assert_eq!(target, json!([1]));
    }
}
