//! The history filter both front-ends share, through the public API only.
//!
//! `history --sender/--resumed/--since` and the app's History screen are the
//! same `HistoryFilter` applied by the same `filter_histories`, so these pin
//! the behaviour once rather than in either consumer.

use unsubscribe_core::{
    filter_histories, sender_histories, HistoryFilter, HistorySort, Resumption, SenderHistoryView,
    TimelineEvent, UnsubscribeAttempt,
};

const ACCOUNT: &str = "user@example.com";
const DAY: i64 = 86_400;
/// 2023-11-14T22:13:20Z, an arbitrary fixed point so nothing depends on today.
const BASE: i64 = 1_700_000_000;
const NOW: i64 = BASE + 100 * DAY;
const GRACE_DAYS: u32 = 14;

fn attempt(id: &str, email: &str, domain: &str, list_id: Option<&str>, at: i64) -> UnsubscribeAttempt {
    UnsubscribeAttempt {
        id: id.to_string(),
        account: ACCOUNT.to_string(),
        sender_email: email.to_string(),
        sender_domain: domain.to_string(),
        list_id: list_id.map(str::to_string),
        attempted_at: at,
        method: "one_click_post".to_string(),
        success: true,
        http_status: Some(200),
        url: "https://example.com/u".to_string(),
        final_url: None,
        list_unsubscribe_raw: None,
        follows_attempt_id: None,
        detail: "HTTP 200".to_string(),
    }
}

fn resumption(id: &str, email: &str, list_id: Option<&str>, attempt_id: &str, at: i64) -> Resumption {
    Resumption {
        id: id.to_string(),
        account: ACCOUNT.to_string(),
        sender_email: email.to_string(),
        list_id: list_id.map(str::to_string),
        attempt_id: attempt_id.to_string(),
        observed_at: at,
        last_seen: at - DAY,
        email_count: 3,
    }
}

/// Three senders: one that ignored its unsubscribe, one that honoured it, and
/// one whose only activity is long before the others.
fn histories() -> Vec<SenderHistoryView> {
    let attempts = vec![
        attempt(
            "a",
            "news@acme.example.com",
            "acme.example.com",
            Some("acme.list.example.com"),
            BASE,
        ),
        attempt("b", "promo@beta.example.com", "beta.example.com", None, BASE + 10 * DAY),
        attempt("c", "old@gamma.example.com", "gamma.example.com", None, BASE - 100 * DAY),
    ];
    let resumptions = vec![resumption(
        "r",
        "news@acme.example.com",
        Some("acme.list.example.com"),
        "a",
        BASE + 40 * DAY,
    )];
    sender_histories(&attempts, &resumptions, &[], NOW, GRACE_DAYS)
}

fn addresses(views: &[SenderHistoryView]) -> Vec<&str> {
    views.iter().map(|v| v.sender_email.as_str()).collect()
}

fn filtered(filter: HistoryFilter) -> Vec<SenderHistoryView> {
    filter_histories(histories(), &filter)
}

// ---------------------------------------------------------------------------
// No filter
// ---------------------------------------------------------------------------

#[test]
fn an_empty_filter_keeps_every_sender() {
    assert_eq!(filtered(HistoryFilter::default()).len(), 3);
}

#[test]
fn the_default_order_is_the_most_recently_attempted_first() {
    assert_eq!(
        addresses(&filtered(HistoryFilter::default())),
        [
            "promo@beta.example.com",
            "news@acme.example.com",
            "old@gamma.example.com",
        ]
    );
}

#[test]
fn senders_attempted_at_the_same_moment_are_ordered_by_address() {
    // Otherwise the listing would depend on how the rows came out of the
    // store, and two runs could disagree.
    let attempts = vec![
        attempt("z", "zoe@example.com", "example.com", None, BASE),
        attempt("a", "amy@example.com", "example.com", None, BASE),
    ];
    let views = sender_histories(&attempts, &[], &[], NOW, GRACE_DAYS);
    let ordered = filter_histories(views, &HistoryFilter::default());
    assert_eq!(addresses(&ordered), ["amy@example.com", "zoe@example.com"]);
}

// ---------------------------------------------------------------------------
// resumed_only
// ---------------------------------------------------------------------------

#[test]
fn resumed_only_keeps_the_senders_that_ignored_an_unsubscribe() {
    let views = filtered(HistoryFilter {
        resumed_only: true,
        ..HistoryFilter::default()
    });
    assert_eq!(addresses(&views), ["news@acme.example.com"]);
}

#[test]
fn a_violation_on_record_counts_even_though_nothing_is_arriving_now() {
    // The sender is absent from the current scan, so there is no live verdict;
    // what it did is still on the record.
    let views = filtered(HistoryFilter {
        resumed_only: true,
        ..HistoryFilter::default()
    });
    assert!(views[0].violation_count > 0);
    assert!(views[0].has_resumed());
    assert!(!views[0].is_resumed());
}

#[test]
fn a_sender_that_honoured_its_unsubscribe_is_excluded() {
    let views = filtered(HistoryFilter {
        resumed_only: true,
        ..HistoryFilter::default()
    });
    assert!(!addresses(&views).contains(&"promo@beta.example.com"));
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

#[test]
fn a_search_matches_part_of_an_address() {
    let views = filtered(HistoryFilter {
        search: "promo".to_string(),
        ..HistoryFilter::default()
    });
    assert_eq!(addresses(&views), ["promo@beta.example.com"]);
}

#[test]
fn a_search_matches_the_domain() {
    let views = filtered(HistoryFilter {
        search: "gamma.example.com".to_string(),
        ..HistoryFilter::default()
    });
    assert_eq!(addresses(&views), ["old@gamma.example.com"]);
}

#[test]
fn a_search_matches_the_list_id() {
    // Senders rotate addresses; the list is the stable identity, so it has to
    // be searchable on its own.
    let views = filtered(HistoryFilter {
        search: "acme.list".to_string(),
        ..HistoryFilter::default()
    });
    assert_eq!(addresses(&views), ["news@acme.example.com"]);
}

#[test]
fn a_search_ignores_case_and_surrounding_whitespace() {
    for needle in ["BETA", "  beta  ", "BeTa"] {
        let views = filtered(HistoryFilter {
            search: needle.to_string(),
            ..HistoryFilter::default()
        });
        assert_eq!(addresses(&views), ["promo@beta.example.com"], "needle {needle:?}");
    }
}

#[test]
fn a_search_that_matches_nothing_yields_nothing() {
    let views = filtered(HistoryFilter {
        search: "nobody".to_string(),
        ..HistoryFilter::default()
    });
    assert!(views.is_empty());
}

#[test]
fn an_empty_search_matches_everything() {
    // The screen filters as the user types, so a blank box is not a filter.
    let views = filtered(HistoryFilter {
        search: "   ".to_string(),
        ..HistoryFilter::default()
    });
    assert_eq!(views.len(), 3);
}

// ---------------------------------------------------------------------------
// since
// ---------------------------------------------------------------------------

#[test]
fn since_drops_senders_with_no_activity_on_or_after_the_date() {
    let views = filtered(HistoryFilter {
        since: Some(BASE + 5 * DAY),
        ..HistoryFilter::default()
    });
    assert_eq!(
        addresses(&views),
        ["promo@beta.example.com", "news@acme.example.com"]
    );
}

#[test]
fn since_looks_at_the_whole_timeline_not_just_the_last_attempt() {
    // The Acme sender was last *attempted* before the cutoff, but it resumed
    // after it -- which is exactly the activity someone is asking about.
    let views = filtered(HistoryFilter {
        since: Some(BASE + 20 * DAY),
        ..HistoryFilter::default()
    });
    assert_eq!(addresses(&views), ["news@acme.example.com"]);
    assert!(views[0].last_attempt_at < BASE + 20 * DAY);
}

#[test]
fn an_event_exactly_on_the_date_is_included() {
    let views = filtered(HistoryFilter {
        since: Some(BASE + 10 * DAY),
        ..HistoryFilter::default()
    });
    assert!(addresses(&views).contains(&"promo@beta.example.com"));
}

#[test]
fn a_sender_that_survives_the_filter_keeps_its_whole_timeline() {
    // Half a timeline is a misleading record, so filters select senders rather
    // than events.
    let views = filtered(HistoryFilter {
        since: Some(BASE + 20 * DAY),
        ..HistoryFilter::default()
    });
    let kinds: Vec<&str> = views[0].timeline.iter().map(TimelineEvent::kind).collect();
    assert_eq!(kinds, ["attempt", "resumption"]);
    assert_eq!(views[0].timeline[0].at(), BASE);
}

#[test]
fn a_date_after_everything_that_ever_happened_yields_nothing() {
    let views = filtered(HistoryFilter {
        since: Some(NOW),
        ..HistoryFilter::default()
    });
    assert!(views.is_empty());
}

// ---------------------------------------------------------------------------
// Filters combine
// ---------------------------------------------------------------------------

#[test]
fn the_filters_narrow_together_rather_than_widening() {
    let views = filtered(HistoryFilter {
        resumed_only: true,
        search: "beta".to_string(),
        ..HistoryFilter::default()
    });
    assert!(
        views.is_empty(),
        "the Beta sender matches the search but never resumed"
    );
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------

#[test]
fn sorting_by_sender_orders_by_address_regardless_of_case() {
    let views = filtered(HistoryFilter {
        sort: HistorySort::Sender,
        ..HistoryFilter::default()
    });
    assert_eq!(
        addresses(&views),
        [
            "news@acme.example.com",
            "old@gamma.example.com",
            "promo@beta.example.com",
        ]
    );
}

#[test]
fn sorting_by_violations_puts_the_worst_offender_first() {
    let views = filtered(HistoryFilter {
        sort: HistorySort::Violations,
        ..HistoryFilter::default()
    });
    assert_eq!(views[0].sender_email, "news@acme.example.com");
    assert!(views[0].violation_count > views[1].violation_count);
}

#[test]
fn the_sort_order_cycles_back_to_where_it_started() {
    let mut sort = HistorySort::default();
    let first = sort;
    for _ in 0..HistorySort::ALL.len() {
        sort = sort.next();
    }
    assert_eq!(sort, first);
}
