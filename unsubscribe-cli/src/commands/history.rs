//! `history` command: what has been asked of each sender, and what it did.
//!
//! Reads only. The grouping, the judgement and the filters are
//! [`unsubscribe_core::history_view`], shared with the TUI's History screen so
//! the two can never disagree about what the record says; what is left here is
//! a table and a JSON document.

use anyhow::Result;
use serde_json::{json, Value};
use unsubscribe_core::{
    filter_histories, load_cached_senders, sender_histories, AccountConfig, HistoryFilter,
    HistoryStore, Preferences, ScanCacheStore, SenderHistoryView, TimelineEvent,
    UnsubscribeOutcome,
};

use crate::commands::load_history;
use crate::exit::{Exit, ExitError};
use crate::json as json_out;
use crate::note;
use crate::output;
use crate::progress::CliWarningsOnly;
use crate::terminal::{Ansi, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{format_unix_date, now_unix_secs, parse_date};

/// What `history` was asked to show.
#[derive(Debug, Clone, Default)]
pub struct HistoryRequest {
    /// Substring of an address or list id.
    pub sender: Option<String>,
    /// Only senders that ignored an unsubscribe.
    pub resumed: bool,
    /// Date as typed, `YYYY-MM-DD`.
    pub since: Option<String>,
    /// Show every attempt and resumption, not just the summary row.
    pub timeline: bool,
    pub json: bool,
}

pub fn cmd_history(
    account: &AccountConfig,
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    preferences: &Preferences,
    request: &HistoryRequest,
) -> Result<Exit> {
    let filter = build_filter(request)?;

    // The cached scan is what lets a sender be judged: without it we can still
    // show what was attempted, just not what has arrived since. `history`
    // never scans -- it is a read of records that already exist.
    let scanned = load_cached_senders(cache_store, &account.account_id, 0, &CliWarningsOnly)
        .map(|obtained| obtained.senders)
        .unwrap_or_default();

    let stored = load_history(history, &account.account_id);
    let views = filter_histories(
        sender_histories(
            &stored.attempts,
            &stored.resumptions,
            &scanned,
            now_unix_secs(),
            preferences.grace_period_days,
        ),
        &filter,
    );

    if request.json {
        output::emit_json(&history_document(account, &views, &filter))?;
        return Ok(if views.is_empty() {
            Exit::NothingToDo
        } else {
            Exit::Success
        });
    }

    if views.is_empty() {
        note!("{YELLOW}No unsubscribe history matched.{RESET}");
        return Ok(Exit::NothingToDo);
    }

    print_table(&views, request.timeline);
    Ok(Exit::Success)
}

/// Turn the flags into the pure filter core applies.
fn build_filter(request: &HistoryRequest) -> Result<HistoryFilter> {
    let since = match &request.since {
        Some(text) => Some(parse_date(text).ok_or_else(|| {
            ExitError::usage(format!(
                "Could not read `--since {text}`. Use a date like 2026-03-18."
            ))
        })?),
        None => None,
    };
    Ok(HistoryFilter {
        sender: request.sender.clone(),
        resumed_only: request.resumed,
        since,
    })
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

fn print_table(views: &[SenderHistoryView], with_timeline: bool) {
    note!("\n{BOLD}{CYAN}Unsubscribe history ({} senders){RESET}\n", views.len());
    println!(
        "{DIM}{:<40} {:<14} {:<12} {:<26} {}{RESET}",
        "Sender", "Last attempt", "Method", "Outcome", "Next"
    );
    println!("{DIM}{}{RESET}", "-".repeat(110));

    for view in views {
        let (outcome, color) = outcome_cell(view);
        println!(
            " {:<39} {:<14} {:<12} {color}{:<26}{RESET} {DIM}{}{RESET}",
            truncate(&view.sender_email, 39),
            format_unix_date(view.last_attempt_at),
            truncate(&view.last_method, 12),
            outcome,
            view.next_step
                .as_ref()
                .map_or_else(|| "not in last scan".to_string(), |step| step.label()),
        );
        if with_timeline {
            print_timeline(view);
        }
    }
}

fn print_timeline(view: &SenderHistoryView) {
    for event in &view.timeline {
        match event {
            TimelineEvent::Attempt(attempt) => {
                let tag = if attempt.success {
                    format!("{GREEN}ok{RESET}    ")
                } else {
                    format!("{RED}failed{RESET}")
                };
                println!(
                    "   {DIM}{}{RESET}  {tag}  {:<14} {DIM}{}{RESET}",
                    format_unix_date(attempt.attempted_at),
                    attempt.method,
                    attempt.detail
                );
            }
            TimelineEvent::Resumption(resumption) => {
                println!(
                    "   {DIM}{}{RESET}  {RED}resumed{RESET} {} email(s) still arriving",
                    format_unix_date(resumption.observed_at),
                    resumption.email_count
                );
            }
        }
    }
    println!();
}

/// The outcome column, with the colour that matches how bad it is.
fn outcome_cell(view: &SenderHistoryView) -> (String, Ansi) {
    let violations = if view.violation_count > 1 {
        format!(" x{}", view.violation_count)
    } else {
        String::new()
    };
    match view.outcome {
        Some(UnsubscribeOutcome::Resumed { days_after }) => {
            (format!("resumed {days_after}d after{violations}"), RED)
        }
        Some(UnsubscribeOutcome::WithinGrace { days_left }) => {
            (format!("grace: {days_left}d left"), YELLOW)
        }
        Some(UnsubscribeOutcome::NoNewMail) => ("unsubscribed".to_string(), DIM),
        // No verdict, but the violations on record still stand.
        None if view.violation_count > 0 => {
            (format!("resumed before{violations}"), RED)
        }
        None => ("no verdict".to_string(), DIM),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn history_document(
    account: &AccountConfig,
    views: &[SenderHistoryView],
    filter: &HistoryFilter,
) -> Value {
    let senders: Vec<Value> = views
        .iter()
        .map(|view| {
            json!({
                "sender_email": view.sender_email,
                "sender_domain": view.sender_domain,
                "list_id": view.list_id,
                "last_attempt_at": view.last_attempt_at,
                "last_method": view.last_method,
                "outcome": view.outcome.map(json_out::outcome),
                "violation_count": view.violation_count,
                "next_step": view.next_step.as_ref().map(json_out::next_step),
                "in_current_scan": view.is_in_current_scan(),
                "timeline": view.timeline.iter().map(timeline_event).collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut doc = json_out::document("history", &account.account_id);
    doc.insert(
        "filter".to_string(),
        json!({
            "sender": filter.sender,
            "resumed": filter.resumed_only,
            "since": filter.since,
        }),
    );
    doc.insert("senders".to_string(), json!(senders));
    doc.insert("count".to_string(), json!(views.len()));
    Value::Object(doc)
}

fn timeline_event(event: &TimelineEvent) -> Value {
    let mut value = json!({ "kind": event.kind(), "at": event.at() });
    let detail = match event {
        TimelineEvent::Attempt(attempt) => json_out::attempt(attempt),
        TimelineEvent::Resumption(resumption) => json!({
            "id": resumption.id,
            "attempt_id": resumption.attempt_id,
            "sender_email": resumption.sender_email,
            "list_id": resumption.list_id,
            "observed_at": resumption.observed_at,
            "last_seen": resumption.last_seen,
            "email_count": resumption.email_count,
        }),
    };
    json_out::merge(&mut value, detail);
    value
}
