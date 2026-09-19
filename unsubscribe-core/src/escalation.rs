//! The escalation ladder: what to try next when a sender ignores an unsubscribe.
//!
//! Repeating the request that was already ignored is not a strategy. A sender's
//! ladder is every distinct way of asking it to stop, in order of how likely it
//! is to be honoured quietly, and a retry climbs to the next rung that has not
//! already been tried and ignored.
//!
//! Everything here is pure. The pipeline decides *when* to ask; this decides
//! *what* to ask, from the sender's headers and its own history.

use std::collections::{HashMap, HashSet};

use crate::history::{attempts_about, resumptions_about, Resumption, UnsubscribeAttempt};
use crate::types::{SenderInfo, UnsubscribeMethod};

/// A way of asking a sender to stop.
///
/// Coarser than [`UnsubscribeMethod`], which records what a single attempt
/// actually did: a GET that ends in a confirmation form and one that does not
/// are the same rung, because they are the same request to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RungMethod {
    /// RFC 8058 one-click POST.
    OneClickPost,
    /// GET the URL and follow through whatever confirmation page comes back.
    HttpFlow,
    /// Send an unsubscribe email.
    Mailto,
}

impl RungMethod {
    /// Human-readable label for CLI and TUI output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::OneClickPost => "one-click POST",
            Self::HttpFlow => "GET/form",
            Self::Mailto => "mailto",
        }
    }

    /// Stable identifier for machine-readable output.
    ///
    /// Separate from [`Self::label`] on purpose: the label is wording and may
    /// be reworded, while this is what a script matches on.
    #[must_use]
    pub fn as_id(self) -> &'static str {
        match self {
            Self::OneClickPost => "one_click_post",
            Self::HttpFlow => "http_flow",
            Self::Mailto => "mailto",
        }
    }

    /// Which rung a recorded attempt was climbing.
    ///
    /// `None` for the methods that describe an absence rather than a request:
    /// nothing to try, nothing tried, or -- for a skipped `mailto:` -- no way
    /// to send. A skip says nothing about the target, so it must not count
    /// towards writing that rung off; configuring SMTP makes it viable again.
    #[must_use]
    pub fn of_attempt(method: UnsubscribeMethod) -> Option<Self> {
        let rung = match method {
            UnsubscribeMethod::OneClickPost => Self::OneClickPost,
            UnsubscribeMethod::Get
            | UnsubscribeMethod::FormPost
            | UnsubscribeMethod::FormGet
            | UnsubscribeMethod::ConfirmLink => Self::HttpFlow,
            UnsubscribeMethod::MailtoSent | UnsubscribeMethod::MailtoFailed => Self::Mailto,
            UnsubscribeMethod::MailtoSkipped
            | UnsubscribeMethod::None
            | UnsubscribeMethod::DryRun => return None,
        };
        Some(rung)
    }
}

/// One rung: a method and the target it is aimed at.
///
/// The target is part of the identity on purpose. A sender that rotates its
/// unsubscribe URL offers a rung nobody has tried yet, which is exactly how a
/// rung that kept failing becomes worth trying again. A rung that was honoured
/// and then ignored gets no such second life -- see [`next_step`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rung {
    pub method: RungMethod,
    /// URL or `mailto:` URI this rung aims at.
    pub target: String,
}

impl Rung {
    #[must_use]
    pub fn new(method: RungMethod, target: impl Into<String>) -> Self {
        Self {
            method,
            target: target.into(),
        }
    }

    /// How this rung reads in output, e.g. `mailto`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.method.label()
    }
}

/// Every way of asking this sender to stop, best first.
///
/// One-click POST leads because it is the mechanism senders are obliged to
/// honour without a human in the loop; then each HTTP URL in the order the
/// header listed them; then each `mailto:` address, which costs the user an
/// outgoing email and so comes last.
#[must_use]
pub fn build_ladder(sender: &SenderInfo) -> Vec<Rung> {
    let one_click = sender
        .one_click
        .then(|| sender.unsubscribe_urls.first())
        .flatten()
        .map(|url| Rung::new(RungMethod::OneClickPost, url));

    one_click
        .into_iter()
        .chain(
            sender
                .unsubscribe_urls
                .iter()
                .map(|url| Rung::new(RungMethod::HttpFlow, url)),
        )
        .chain(
            sender
                .unsubscribe_mailto
                .iter()
                .map(|to| Rung::new(RungMethod::Mailto, to)),
        )
        .collect()
}

/// An escalation: the rung to climb to, and what prompted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escalation {
    /// The rung to try, and only this one.
    pub rung: Rung,
    /// The rung that was tried and ignored, when the history says which.
    pub from: Option<RungMethod>,
    /// Id of the ignored attempt this answers, recorded on the new attempt so
    /// the pair can be read back as one story.
    pub follows_attempt_id: Option<String>,
}

/// What a run should do about one sender's unsubscribe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextStep {
    /// Nothing has been tried and ignored yet, so run the whole flow with its
    /// within-attempt fallbacks, exactly as a first-ever attempt always has.
    FirstAttempt,
    /// Climb to one specific rung.
    Escalate(Escalation),
    /// Every rung is spent or broken. Nothing left to ask; archive and, one
    /// day, report.
    Exhausted,
}

impl NextStep {
    /// How the step reads next to a sender, e.g. `next: mailto`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::FirstAttempt => "next: full flow".to_string(),
            Self::Escalate(escalation) => format!("next: {}", escalation.rung.label()),
            Self::Exhausted => "exhausted \u{2014} no methods left".to_string(),
        }
    }

    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        matches!(self, Self::Exhausted)
    }
}

/// How many consecutive recent failures make a rung not worth trying.
const BROKEN_AFTER_FAILURES: usize = 2;

/// Decide what to try next for a sender.
///
/// Pure, and the whole of the escalation policy:
///
/// - a rung is **spent** once an attempt using it succeeded and a resumption
///   was later recorded against that attempt -- the sender said yes and kept
///   mailing, so asking the same way again is theatre;
/// - a spent rung stays spent when the sender rotates the target it was aimed
///   at. Unsubscribe URLs carry per-message tokens, so the very mail that
///   proves a request was ignored also offers a "new" URL for the same request;
///   a spent rung whose target is no longer offered therefore spends the next
///   otherwise-untried rung of its method instead;
/// - a rung is **broken** when its two most recent attempts both failed (a 404,
///   a timeout). Broken rungs are skipped, but a rung is identified by its
///   target, so a sender that changes its URL offers an untried rung again;
/// - a sender with no rungs at all has nothing to ask and is exhausted from the
///   start;
/// - otherwise, with nothing spent and nothing broken there is no reason to
///   narrow the attempt, so the sender gets the full flow it would have got
///   anyway.
#[must_use]
pub fn next_step(
    sender: &SenderInfo,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
) -> NextStep {
    let ladder = build_ladder(sender);
    if ladder.is_empty() {
        return NextStep::Exhausted;
    }

    let mine: Vec<&UnsubscribeAttempt> = attempts_about(sender, attempts).collect();
    let ignored: HashSet<&str> = resumptions_about(sender, resumptions)
        .map(|r| r.attempt_id.as_str())
        .collect();

    let spent = spent_rungs(&mine, &ignored);
    let broken = broken_rungs(&mine);
    if spent.is_empty() && broken.is_empty() {
        return NextStep::FirstAttempt;
    }

    // The most recent ignored attempt is the one this escalation answers.
    let ignored_attempt = mine
        .iter()
        .rev()
        .find(|a| a.success && ignored.contains(a.id.as_str()));

    first_untried_rung(ladder, &spent, &broken)
        .map_or(NextStep::Exhausted, |rung| {
            NextStep::Escalate(Escalation {
                rung,
                from: ignored_attempt
                    .and_then(|a| UnsubscribeMethod::from_id(&a.method))
                    .and_then(RungMethod::of_attempt),
                follows_attempt_id: ignored_attempt.map(|a| a.id.clone()),
            })
        })
}

/// The best rung that is neither spent nor broken.
///
/// Each spent rung whose target the sender no longer offers is carried over to
/// the first otherwise-eligible rung of the same method: that is where a
/// rotated target reappears in the ladder. Broken rungs carry nothing over -- a
/// changed target is exactly what makes a failing rung worth another try.
fn first_untried_rung(
    ladder: Vec<Rung>,
    spent: &HashSet<Rung>,
    broken: &HashSet<Rung>,
) -> Option<Rung> {
    let mut carried_over = spent.iter().filter(|rung| !ladder.contains(rung)).fold(
        HashMap::<RungMethod, usize>::new(),
        |mut per_method, rung| {
            *per_method.entry(rung.method).or_default() += 1;
            per_method
        },
    );

    ladder
        .into_iter()
        .filter(|rung| !spent.contains(rung) && !broken.contains(rung))
        .find(|rung| match carried_over.get_mut(&rung.method) {
            Some(left) if *left > 0 => {
                *left -= 1;
                false
            }
            _ => true,
        })
}

/// Rungs that were honoured and then ignored anyway.
fn spent_rungs(mine: &[&UnsubscribeAttempt], ignored: &HashSet<&str>) -> HashSet<Rung> {
    mine.iter()
        .filter(|a| a.success && ignored.contains(a.id.as_str()))
        .filter_map(|a| rung_of(a))
        .collect()
}

/// Rungs whose last two attempts both failed.
///
/// Attempts arrive oldest first, so the tail of each rung's list is its recent
/// history. A rung tried only once, however badly, is not written off.
fn broken_rungs(mine: &[&UnsubscribeAttempt]) -> HashSet<Rung> {
    mine.iter()
        .filter_map(|a| rung_of(a).map(|rung| (rung, a.success)))
        .fold(
            HashMap::<Rung, Vec<bool>>::new(),
            |mut per_rung, (rung, success)| {
                per_rung.entry(rung).or_default().push(success);
                per_rung
            },
        )
        .into_iter()
        .filter(|(_, outcomes)| {
            outcomes.len() >= BROKEN_AFTER_FAILURES
                && outcomes
                    .iter()
                    .rev()
                    .take(BROKEN_AFTER_FAILURES)
                    .all(|success| !success)
        })
        .map(|(rung, _)| rung)
        .collect()
}

/// Which rung a recorded attempt climbed, if it climbed one.
fn rung_of(attempt: &UnsubscribeAttempt) -> Option<Rung> {
    UnsubscribeMethod::from_id(&attempt.method)
        .and_then(RungMethod::of_attempt)
        .map(|method| Rung::new(method, &attempt.url))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: &str = "news@acme.example.com";
    const U1: &str = "https://acme.example.com/unsub?id=1";
    const U2: &str = "https://acme.example.com/other?id=2";
    const M1: &str = "mailto:unsub@acme.example.com";
    const M2: &str = "mailto:leave@acme.example.com";

    /// A sender carrying exactly the unsubscribe targets a test cares about.
    fn sender(one_click: bool, urls: &[&str], mailtos: &[&str]) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: SENDER.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: urls.iter().map(|u| (*u).to_string()).collect(),
            unsubscribe_mailto: mailtos.iter().map(|m| (*m).to_string()).collect(),
            one_click,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 3,
            messages: Vec::new(),
            last_seen: Some(1_700_000_000),
        }
    }

    /// One recorded attempt, identified so a resumption can point at it.
    fn attempt(
        id: &str,
        at: i64,
        method: UnsubscribeMethod,
        url: &str,
        success: bool,
    ) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: "user@example.com".to_string(),
            sender_email: SENDER.to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: None,
            attempted_at: at,
            method: method.as_id().to_string(),
            success,
            http_status: Some(200),
            url: url.to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: String::new(),
        }
    }

    /// An observation that the attempt with this id was ignored.
    fn ignored(attempt_id: &str) -> Resumption {
        Resumption {
            id: format!("res-{attempt_id}"),
            account: "user@example.com".to_string(),
            sender_email: SENDER.to_string(),
            list_id: None,
            attempt_id: attempt_id.to_string(),
            observed_at: 9_000,
            last_seen: 8_000,
            email_count: 2,
        }
    }

    /// The rung an `Escalate` step points at, or a readable panic.
    fn escalated(step: &NextStep) -> &Escalation {
        match step {
            NextStep::Escalate(escalation) => escalation,
            other => panic!("expected an escalation, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // build_ladder
    // -----------------------------------------------------------------------

    #[test]
    fn ladder_runs_one_click_then_urls_then_mailtos_in_header_order() {
        let ladder = build_ladder(&sender(true, &[U1, U2], &[M1, M2]));

        assert_eq!(
            ladder,
            vec![
                Rung::new(RungMethod::OneClickPost, U1),
                Rung::new(RungMethod::HttpFlow, U1),
                Rung::new(RungMethod::HttpFlow, U2),
                Rung::new(RungMethod::Mailto, M1),
                Rung::new(RungMethod::Mailto, M2),
            ]
        );
    }

    #[test]
    fn one_click_only_ever_aims_at_the_first_url() {
        let ladder = build_ladder(&sender(true, &[U1, U2], &[]));
        let posts: Vec<&Rung> = ladder
            .iter()
            .filter(|r| r.method == RungMethod::OneClickPost)
            .collect();

        assert_eq!(posts, vec![&Rung::new(RungMethod::OneClickPost, U1)]);
    }

    #[test]
    fn a_sender_without_one_click_gets_no_post_rung() {
        let ladder = build_ladder(&sender(false, &[U1, U2], &[M1]));

        assert_eq!(
            ladder,
            vec![
                Rung::new(RungMethod::HttpFlow, U1),
                Rung::new(RungMethod::HttpFlow, U2),
                Rung::new(RungMethod::Mailto, M1),
            ]
        );
    }

    #[test]
    fn a_mailto_only_sender_has_a_ladder_of_mailtos() {
        assert_eq!(
            build_ladder(&sender(false, &[], &[M1, M2])),
            vec![
                Rung::new(RungMethod::Mailto, M1),
                Rung::new(RungMethod::Mailto, M2),
            ]
        );
    }

    #[test]
    fn one_click_claimed_without_a_url_contributes_no_rung() {
        // `List-Unsubscribe-Post` can arrive on a header whose only target is a
        // mailto. There is nothing to POST to, so the ladder must not invent one.
        assert_eq!(
            build_ladder(&sender(true, &[], &[M1])),
            vec![Rung::new(RungMethod::Mailto, M1)]
        );
    }

    #[test]
    fn a_sender_with_no_targets_has_an_empty_ladder() {
        assert!(build_ladder(&sender(false, &[], &[])).is_empty());
    }

    // -----------------------------------------------------------------------
    // RungMethod::of_attempt
    // -----------------------------------------------------------------------

    #[test]
    fn every_request_shaped_method_maps_to_the_rung_it_climbed() {
        use UnsubscribeMethod as M;

        // Expected pairs written out rather than derived, so a rewiring of the
        // match has to disagree with this list to pass.
        let expected = [
            (M::OneClickPost, RungMethod::OneClickPost),
            (M::Get, RungMethod::HttpFlow),
            (M::FormPost, RungMethod::HttpFlow),
            (M::FormGet, RungMethod::HttpFlow),
            (M::ConfirmLink, RungMethod::HttpFlow),
            (M::MailtoSent, RungMethod::Mailto),
            (M::MailtoFailed, RungMethod::Mailto),
        ];

        for (method, rung) in expected {
            assert_eq!(
                RungMethod::of_attempt(method),
                Some(rung),
                "{} climbed the wrong rung",
                method.as_id()
            );
        }
    }

    #[test]
    fn methods_that_describe_an_absence_climb_no_rung() {
        use UnsubscribeMethod as M;

        for method in [M::MailtoSkipped, M::None, M::DryRun] {
            assert_eq!(
                RungMethod::of_attempt(method),
                None,
                "{} is not a request that was made",
                method.as_id()
            );
        }
    }

    // -----------------------------------------------------------------------
    // next_step: nothing tried and ignored yet
    // -----------------------------------------------------------------------

    #[test]
    fn no_history_means_the_full_flow() {
        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &[], &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn an_attempt_that_was_never_ignored_still_gets_the_full_flow() {
        // Succeeding and then staying quiet is the loop closing, not a reason
        // to narrow the next attempt.
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true)];

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &attempts, &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn another_senders_history_is_not_this_senders_history() {
        let mut theirs = attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true);
        theirs.sender_email = "deals@other.example.com".to_string();
        let mut their_resumption = ignored("a1");
        their_resumption.sender_email = "deals@other.example.com".to_string();

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &[theirs], &[their_resumption]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn a_resumption_against_a_failed_attempt_spends_nothing() {
        // Only a rung the sender said yes to can be spent; a failure never
        // promised anything, so there is nothing to have broken.
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, false)];

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &attempts, &[ignored("a1")]),
            NextStep::FirstAttempt
        );
    }

    // -----------------------------------------------------------------------
    // next_step: spent rungs
    // -----------------------------------------------------------------------

    #[test]
    fn an_ignored_one_click_escalates_to_the_get_flow() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true)];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &[ignored("a1")]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U1));
    }

    #[test]
    fn an_ignored_get_flow_escalates_to_mailto() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U1, true),
        ];
        let resumptions = vec![ignored("a1"), ignored("a2")];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &resumptions);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::Mailto, M1));
    }

    #[test]
    fn a_confirmation_form_and_a_plain_get_spend_the_same_rung() {
        // `form_post` and `get` are the same request to make, so honouring the
        // form and then ignoring it must not leave a plain GET looking untried.
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::FormPost, U1, true)];
        let step = next_step(&sender(false, &[U1], &[M1]), &attempts, &[ignored("a1")]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::Mailto, M1));
    }

    #[test]
    fn every_rung_ignored_leaves_nothing_to_try() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U1, true),
            attempt("a3", 3_000, UnsubscribeMethod::MailtoSent, M1, true),
        ];
        let resumptions = vec![ignored("a1"), ignored("a2"), ignored("a3")];

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &attempts, &resumptions),
            NextStep::Exhausted
        );
    }

    #[test]
    fn a_spent_rung_is_skipped_even_when_the_sender_offers_a_new_target() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::Get, U1, true)];
        let step = next_step(&sender(false, &[U1, U2], &[]), &attempts, &[ignored("a1")]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U2));
    }

    // -----------------------------------------------------------------------
    // next_step: a spent rung survives a rotated target (#113)
    // -----------------------------------------------------------------------

    /// The same endpoints as `U1` / `M1` with a fresh per-message token.
    const U1_ROTATED: &str = "https://acme.example.com/unsub?id=99";
    const U2_ROTATED: &str = "https://acme.example.com/other?id=98";
    const M1_ROTATED: &str = "mailto:unsub+tok99@acme.example.com";

    #[test]
    fn an_ignored_one_click_is_not_repeated_at_a_rotated_url() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true)];
        let step = next_step(&sender(true, &[U1_ROTATED], &[M1]), &attempts, &[ignored("a1")]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U1_ROTATED));
    }

    #[test]
    fn a_rotated_spent_url_spends_only_the_first_rung_of_its_method() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::Get, U1, true)];
        let step = next_step(
            &sender(false, &[U1_ROTATED, U2_ROTATED], &[M1]),
            &attempts,
            &[ignored("a1")],
        );

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U2_ROTATED));
    }

    #[test]
    fn every_rung_ignored_is_exhausted_even_after_every_target_rotates() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U1, true),
            attempt("a3", 3_000, UnsubscribeMethod::MailtoSent, M1, true),
        ];
        let resumptions = vec![ignored("a1"), ignored("a2"), ignored("a3")];

        assert_eq!(
            next_step(&sender(true, &[U1_ROTATED], &[M1_ROTATED]), &attempts, &resumptions),
            NextStep::Exhausted
        );
    }

    #[test]
    fn a_rotated_spent_rung_does_not_spend_a_rung_of_another_method() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::MailtoSent, M1, true)];
        let step = next_step(
            &sender(false, &[U1], &[M1_ROTATED, M2]),
            &attempts,
            &[ignored("a1")],
        );

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U1));
    }

    #[test]
    fn a_carried_over_rung_skips_past_a_broken_one() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::Get, U1, true),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U2, false),
            attempt("a3", 3_000, UnsubscribeMethod::Get, U2, false),
        ];
        let step = next_step(
            &sender(false, &[U2, U1_ROTATED], &[M1]),
            &attempts,
            &[ignored("a1")],
        );

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::Mailto, M1));
    }

    // -----------------------------------------------------------------------
    // next_step: what an escalation answers
    // -----------------------------------------------------------------------

    #[test]
    fn an_escalation_names_the_ignored_attempt_and_the_rung_it_used() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true)];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &[ignored("a1")]);
        let escalation = escalated(&step);

        assert_eq!(escalation.follows_attempt_id.as_deref(), Some("a1"));
        assert_eq!(escalation.from, Some(RungMethod::OneClickPost));
    }

    #[test]
    fn an_escalation_answers_the_most_recent_ignored_attempt() {
        let attempts = vec![
            attempt("older", 1_000, UnsubscribeMethod::OneClickPost, U1, true),
            attempt("newer", 2_000, UnsubscribeMethod::Get, U1, true),
        ];
        let resumptions = vec![ignored("older"), ignored("newer")];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &resumptions);

        assert_eq!(
            escalated(&step).follows_attempt_id.as_deref(),
            Some("newer")
        );
    }

    #[test]
    fn an_escalation_forced_by_breakage_alone_answers_nothing() {
        // Two dead requests are a reason to try elsewhere, but no attempt was
        // ignored, so there is no earlier attempt for this one to point at.
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::OneClickPost, U1, false),
        ];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &[]);
        let escalation = escalated(&step);

        assert_eq!(escalation.follows_attempt_id, None);
        assert_eq!(escalation.from, None);
    }

    // -----------------------------------------------------------------------
    // next_step: broken rungs
    // -----------------------------------------------------------------------

    #[test]
    fn one_failure_does_not_write_a_rung_off() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, false)];

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &attempts, &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn two_consecutive_failures_write_a_rung_off() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::OneClickPost, U1, false),
        ];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &[]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U1));
    }

    #[test]
    fn a_success_between_two_failures_keeps_the_rung_alive() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::OneClickPost, U1, true),
            attempt("a3", 3_000, UnsubscribeMethod::OneClickPost, U1, false),
        ];

        assert_eq!(
            next_step(&sender(true, &[U1], &[M1]), &attempts, &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn a_broken_rung_is_worth_trying_again_at_a_new_target() {
        // A rung is identified by its target, so a rotated URL is an untried
        // rung rather than the dead one written off earlier.
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::Get, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U1, false),
        ];
        let step = next_step(&sender(false, &[U2], &[M1]), &attempts, &[]);

        assert_eq!(escalated(&step).rung, Rung::new(RungMethod::HttpFlow, U2));
    }

    #[test]
    fn failures_at_two_different_targets_break_neither_rung() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::Get, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U2, false),
        ];

        assert_eq!(
            next_step(&sender(false, &[U1, U2], &[M1]), &attempts, &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn every_rung_broken_leaves_nothing_to_try() {
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::Get, U1, false),
            attempt("a2", 2_000, UnsubscribeMethod::Get, U1, false),
        ];

        assert_eq!(
            next_step(&sender(false, &[U1], &[]), &attempts, &[]),
            NextStep::Exhausted
        );
    }

    #[test]
    fn a_skipped_mailto_never_writes_the_mailto_rung_off() {
        // `MailtoSkipped` means no sender was configured, so nothing was asked.
        // Counting it would permanently deny the rung to anyone who later
        // configures SMTP.
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::MailtoSkipped, M1, false),
            attempt("a2", 2_000, UnsubscribeMethod::MailtoSkipped, M1, false),
        ];

        assert_eq!(
            next_step(&sender(false, &[], &[M1]), &attempts, &[]),
            NextStep::FirstAttempt
        );
    }

    #[test]
    fn a_failed_send_does_write_the_mailto_rung_off() {
        // Unlike a skip, `MailtoFailed` is a request that was made and did not
        // land, so two of them are evidence about the target.
        let attempts = vec![
            attempt("a1", 1_000, UnsubscribeMethod::MailtoFailed, M1, false),
            attempt("a2", 2_000, UnsubscribeMethod::MailtoFailed, M1, false),
        ];

        assert_eq!(
            next_step(&sender(false, &[], &[M1]), &attempts, &[]),
            NextStep::Exhausted
        );
    }

    #[test]
    fn a_sender_with_no_targets_at_all_has_nothing_to_try() {
        // Reachable: a message whose `List-Unsubscribe` header is present but
        // yields no usable URL or mailto still becomes a scanned sender. Its
        // ladder is empty, so there is nothing to ask, and attempting it would
        // only record a `none` failure on every run (#113).
        assert_eq!(
            next_step(&sender(false, &[], &[]), &[], &[]),
            NextStep::Exhausted
        );
    }

    // -----------------------------------------------------------------------
    // Labels
    // -----------------------------------------------------------------------

    #[test]
    fn a_step_reads_as_the_rung_it_points_at() {
        let attempts = vec![attempt("a1", 1_000, UnsubscribeMethod::OneClickPost, U1, true)];
        let step = next_step(&sender(true, &[U1], &[M1]), &attempts, &[ignored("a1")]);

        assert_eq!(step.label(), "next: GET/form");
        assert_eq!(NextStep::FirstAttempt.label(), "next: full flow");
        assert_eq!(NextStep::Exhausted.label(), "exhausted \u{2014} no methods left");
    }

    #[test]
    fn only_exhausted_reports_itself_as_exhausted() {
        assert!(NextStep::Exhausted.is_exhausted());
        assert!(!NextStep::FirstAttempt.is_exhausted());
        assert!(!NextStep::Escalate(Escalation {
            rung: Rung::new(RungMethod::Mailto, M1),
            from: None,
            follows_attempt_id: None,
        })
        .is_exhausted());
    }
}
