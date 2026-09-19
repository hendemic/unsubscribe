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
        search: request.sender.clone().unwrap_or_default(),
        resumed_only: request.resumed,
        since,
        ..HistoryFilter::default()
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
                "in_current_scan": view.in_current_scan(),
                "timeline": view.timeline.iter().map(timeline_event).collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut doc = json_out::document("history", &account.account_id);
    doc.insert(
        "filter".to_string(),
        json!({
            "sender": Some(&filter.search).filter(|needle| !needle.is_empty()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::{AuthType, HistorySort, NextStep, ProviderType, Resumption, UnsubscribeAttempt};

    fn account() -> AccountConfig {
        AccountConfig {
            account_id: "user@example.com".to_string(),
            provider_type: ProviderType::Imap,
            host: Some("imap.example.com".to_string()),
            port: Some(993),
            username: "user@example.com".to_string(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".to_string()],
            archive_folder: "Unsubscribed".to_string(),
            smtp_host: None,
            smtp_port: None,
        }
    }

    fn request() -> HistoryRequest {
        HistoryRequest::default()
    }

    // -----------------------------------------------------------------------
    // build_filter
    // -----------------------------------------------------------------------

    #[test]
    fn no_flags_build_a_filter_that_keeps_everything() {
        let filter = build_filter(&request()).unwrap();
        assert_eq!(filter, HistoryFilter::default());
        assert!(filter.search.is_empty());
        assert!(!filter.resumed_only);
        assert_eq!(filter.since, None);
    }

    #[test]
    fn the_sender_flag_becomes_the_search_needle() {
        let filter = build_filter(&HistoryRequest {
            sender: Some("acme".to_string()),
            ..request()
        })
        .unwrap();
        assert_eq!(filter.search, "acme");
    }

    #[test]
    fn the_resumed_flag_asks_for_senders_that_ignored_an_unsubscribe() {
        let filter = build_filter(&HistoryRequest {
            resumed: true,
            ..request()
        })
        .unwrap();
        assert!(filter.resumed_only);
    }

    #[test]
    fn a_since_date_is_read_as_midnight_utc_on_that_day() {
        // 2026-03-18T00:00:00Z, counted from the epoch rather than computed
        // the way the parser does.
        let filter = build_filter(&HistoryRequest {
            since: Some("2026-03-18".to_string()),
            ..request()
        })
        .unwrap();
        assert_eq!(filter.since, Some(1_773_792_000));
    }

    #[test]
    fn a_since_date_that_is_not_a_date_is_a_usage_error() {
        for text in ["notadate", "18/03/2026", "march", ""] {
            let error = build_filter(&HistoryRequest {
                since: Some(text.to_string()),
                ..request()
            })
            .unwrap_err();
            assert_eq!(
                crate::exit::exit_code(&Err(error)),
                Exit::Usage.code(),
                "`--since {text}` should be a usage error"
            );
        }
    }

    #[test]
    fn a_date_that_could_not_exist_is_a_usage_error() {
        // `--since 2026-13-01` is currently read as 2027-01-01 and
        // `--since 2026-02-30` as 2026-03-02, so a typo silently selects the
        // wrong window instead of being reported.
        for text in ["2026-13-01", "2026-00-10", "2026-02-30", "2026-01-32"] {
            assert!(
                build_filter(&HistoryRequest {
                    since: Some(text.to_string()),
                    ..request()
                })
                .is_err(),
                "`--since {text}` names a date that does not exist"
            );
        }
    }

    #[test]
    fn an_unreadable_date_is_quoted_back_with_an_example_of_a_good_one() {
        let error = build_filter(&HistoryRequest {
            since: Some("last tuesday".to_string()),
            ..request()
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("last tuesday"), "{message}");
        assert!(message.contains("2026-03-18"), "{message}");
    }

    #[test]
    fn the_command_never_changes_the_sort_the_shared_filter_defaults_to() {
        // Newest attempt first is what both front-ends show; `history` has no
        // flag for it, so it must not quietly pick something else.
        let filter = build_filter(&request()).unwrap();
        assert_eq!(filter.sort, HistorySort::LastAttempt);
    }

    // -----------------------------------------------------------------------
    // The JSON document
    // -----------------------------------------------------------------------

    fn attempt() -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: "11111111-1111-4111-8111-111111111111".to_string(),
            account: "user@example.com".to_string(),
            sender_email: "news@acme.example.com".to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: Some("acme.list.example.com".to_string()),
            attempted_at: 1_700_000_000,
            method: "one_click_post".to_string(),
            success: true,
            http_status: Some(200),
            url: "https://acme.example.com/u?id=1".to_string(),
            final_url: Some("https://acme.example.com/done".to_string()),
            list_unsubscribe_raw: Some("<https://acme.example.com/u?id=1>".to_string()),
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        }
    }

    fn resumption() -> Resumption {
        Resumption {
            id: "22222222-2222-4222-8222-222222222222".to_string(),
            account: "user@example.com".to_string(),
            sender_email: "news@acme.example.com".to_string(),
            list_id: Some("acme.list.example.com".to_string()),
            attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
            observed_at: 1_702_592_000,
            last_seen: 1_702_500_000,
            email_count: 4,
        }
    }

    /// A sender caught ignoring its unsubscribe, still in the current scan.
    fn resumed_view() -> SenderHistoryView {
        SenderHistoryView {
            sender_email: "news@acme.example.com".to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: Some("acme.list.example.com".to_string()),
            last_attempt_at: 1_700_000_000,
            last_method: "one_click_post".to_string(),
            outcome: Some(UnsubscribeOutcome::Resumed { days_after: 30 }),
            violation_count: 1,
            next_step: Some(NextStep::Exhausted),
            timeline: vec![
                TimelineEvent::Attempt(attempt()),
                TimelineEvent::Resumption(resumption()),
            ],
        }
    }

    /// A sender the history remembers but the last scan did not see.
    fn vanished_view() -> SenderHistoryView {
        SenderHistoryView {
            sender_email: "old@gone.example.com".to_string(),
            sender_domain: "gone.example.com".to_string(),
            list_id: None,
            last_attempt_at: 1_690_000_000,
            last_method: "get".to_string(),
            outcome: None,
            violation_count: 0,
            next_step: None,
            timeline: Vec::new(),
        }
    }

    #[test]
    fn the_history_document_matches_its_golden_shape() {
        // Pinned so an accidental rename or removal of a field fails a test
        // rather than a user's script.
        let document = history_document(
            &account(),
            &[resumed_view(), vanished_view()],
            &HistoryFilter::default(),
        );
        let golden: Value =
            serde_json::from_str(include_str!("testdata/history_document.json")).unwrap();
        assert_eq!(document, golden);
    }

    #[test]
    fn the_document_reports_the_filter_it_was_produced_under() {
        let document = history_document(
            &account(),
            &[],
            &HistoryFilter {
                search: "acme".to_string(),
                resumed_only: true,
                since: Some(1_773_792_000),
                ..HistoryFilter::default()
            },
        );
        assert_eq!(
            document["filter"],
            json!({ "sender": "acme", "resumed": true, "since": 1_773_792_000_i64 })
        );
    }

    #[test]
    fn an_absent_sender_filter_is_null_rather_than_an_empty_string() {
        // "no filter" and "filtered on the empty string" are different facts.
        let document = history_document(&account(), &[], &HistoryFilter::default());
        assert_eq!(document["filter"]["sender"], Value::Null);
    }

    #[test]
    fn the_count_matches_the_senders_listed() {
        let document = history_document(
            &account(),
            &[resumed_view(), vanished_view()],
            &HistoryFilter::default(),
        );
        assert_eq!(document["count"], json!(2));
        assert_eq!(document["senders"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_sender_missing_from_the_last_scan_says_so_instead_of_guessing() {
        let document = history_document(&account(), &[vanished_view()], &HistoryFilter::default());
        let row = &document["senders"][0];
        assert_eq!(row["in_current_scan"], json!(false));
        assert_eq!(row["outcome"], Value::Null);
        assert_eq!(row["next_step"], Value::Null);
    }

    #[test]
    fn every_timeline_entry_says_what_kind_it_is_and_when_it_happened() {
        let document = history_document(&account(), &[resumed_view()], &HistoryFilter::default());
        let timeline = document["senders"][0]["timeline"].as_array().unwrap();
        assert_eq!(timeline[0]["kind"], json!("attempt"));
        assert_eq!(timeline[0]["at"], json!(1_700_000_000_i64));
        assert_eq!(timeline[1]["kind"], json!("resumption"));
        assert_eq!(timeline[1]["at"], json!(1_702_592_000_i64));
    }

    #[test]
    fn a_timeline_entry_carries_the_record_it_came_from() {
        let document = history_document(&account(), &[resumed_view()], &HistoryFilter::default());
        let timeline = &document["senders"][0]["timeline"];
        assert_eq!(timeline[0]["id"], json!(attempt().id));
        assert_eq!(timeline[1]["attempt_id"], json!(attempt().id));
        assert_eq!(timeline[1]["email_count"], json!(4));
    }

    #[test]
    fn the_document_names_the_command_and_the_account_it_is_about() {
        let document = history_document(&account(), &[], &HistoryFilter::default());
        assert_eq!(document["command"], json!("history"));
        assert_eq!(document["account"], json!("user@example.com"));
        assert_eq!(document["schema_version"], json!(output::SCHEMA_VERSION));
    }

    // -----------------------------------------------------------------------
    // Table cells
    // -----------------------------------------------------------------------

    #[test]
    fn a_repeat_offender_is_counted_in_the_outcome_cell() {
        let mut view = resumed_view();
        view.violation_count = 3;
        assert_eq!(outcome_cell(&view).0, "resumed 30d after x3");
    }

    #[test]
    fn a_single_violation_is_not_labelled_with_a_count() {
        assert_eq!(outcome_cell(&resumed_view()).0, "resumed 30d after");
    }

    #[test]
    fn a_sender_out_of_scan_with_violations_on_record_still_reports_them() {
        // No current verdict is possible, but what is on record still stands.
        let mut view = vanished_view();
        view.violation_count = 2;
        assert_eq!(outcome_cell(&view).0, "resumed before x2");
    }

    #[test]
    fn a_sender_with_nothing_to_judge_gets_no_verdict() {
        assert_eq!(outcome_cell(&vanished_view()).0, "no verdict");
    }

    #[test]
    fn a_sender_that_honoured_its_unsubscribe_reads_as_unsubscribed() {
        let mut view = resumed_view();
        view.outcome = Some(UnsubscribeOutcome::NoNewMail);
        view.violation_count = 0;
        assert_eq!(outcome_cell(&view).0, "unsubscribed");
    }

    #[test]
    fn a_sender_inside_its_grace_period_reports_the_days_it_has_left() {
        let mut view = resumed_view();
        view.outcome = Some(UnsubscribeOutcome::WithinGrace { days_left: 4 });
        assert_eq!(outcome_cell(&view).0, "grace: 4d left");
    }

    #[test]
    fn truncating_a_cell_never_splits_a_character_in_half() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("abc", 10), "abc");
        // Multi-byte input: slicing by bytes here would panic.
        assert_eq!(truncate("émile@example.com", 5), "émile");
    }
}
