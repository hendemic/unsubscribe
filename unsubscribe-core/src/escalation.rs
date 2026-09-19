//! The escalation ladder: what to try next when a sender ignores an unsubscribe.
//!
//! Repeating the request that was already ignored is not a strategy. A sender's
//! ladder is every distinct way of asking it to stop, in order of how likely it
//! is to be honoured quietly, and a retry climbs to the next rung that has not
//! already been tried and ignored.
//!
//! Everything here is pure. The pipeline decides *when* to ask; this decides
//! *what* to ask, from the sender's headers and its own history.

use std::collections::HashSet;

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
/// rung that kept failing becomes worth trying again.
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
/// - a rung is **broken** when its two most recent attempts both failed (a 404,
///   a timeout). Broken rungs are skipped, but a rung is identified by its
///   target, so a sender that changes its URL offers an untried rung again;
/// - with nothing spent and nothing broken there is no reason to narrow the
///   attempt, so the sender gets the full flow it would have got anyway.
#[must_use]
pub fn next_step(
    sender: &SenderInfo,
    attempts: &[UnsubscribeAttempt],
    resumptions: &[Resumption],
) -> NextStep {
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

    build_ladder(sender)
        .into_iter()
        .find(|rung| !spent.contains(rung) && !broken.contains(rung))
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
            std::collections::HashMap::<Rung, Vec<bool>>::new(),
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
