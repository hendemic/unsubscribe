//! Choosing which senders a run acts on, without a person in the loop.
//!
//! The interactive front-ends let someone tick boxes; a cron job, a systemd
//! timer and the future scheduler state a policy instead. Both end up handing
//! the same `Vec<SenderInfo>` to [`crate::pipeline::plan_run`], so the rule for
//! turning a policy into a selection lives here, pure and UI-free, rather than
//! in whichever front-end happened to need it first.

use crate::pipeline::AnnotatedSenders;
use crate::types::SenderInfo;

/// Why a sender ended up in a headless run.
///
/// Reported back so a `--dry-run` (and `--json`) can say which flag put each
/// sender there, rather than presenting one undifferentiated list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// Picked by a person on a selection screen, where the choice is its own
    /// justification.
    Chosen,
    /// Named explicitly, by `--sender` or `--senders-file`.
    Named,
    /// Ignored an unsubscribe that succeeded earlier.
    Resumed,
    /// Seen recently and never successfully unsubscribed from.
    Active,
    /// Not seen for long enough to be archived without asking again.
    Stale,
}

impl SelectionReason {
    /// Stable identifier, for machine-readable output.
    #[must_use]
    pub fn as_id(self) -> &'static str {
        match self {
            Self::Chosen => "chosen",
            Self::Named => "named",
            Self::Resumed => "resumed",
            Self::Active => "active",
            Self::Stale => "stale",
        }
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Chosen => "chosen",
            Self::Named => "named",
            Self::Resumed => "resumed",
            Self::Active => "active",
            Self::Stale => "stale",
        }
    }
}

/// What a headless run was asked to act on.
///
/// The flags union rather than exclude: `--resumed --stale` means both. Plain
/// data, so the CLI parses argv and core decides nothing about how it was
/// spelled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectionPolicy {
    /// Senders that ignored a successful unsubscribe.
    pub resumed: bool,
    /// Every non-stale sender with no successful unsubscribe behind it.
    pub all_active: bool,
    /// Stale senders, which are archived without an attempt.
    pub stale: bool,
    /// Addresses named explicitly, in the order given.
    pub senders: Vec<String>,
    /// Refuse to act on more than this many senders in one run. Zero lifts the
    /// cap entirely, which is something the caller has to ask for.
    pub max_senders: u32,
}

impl SelectionPolicy {
    /// Whether the policy names nothing at all, i.e. no selection flag was
    /// given and the caller has not said what to act on.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.resumed && !self.all_active && !self.stale && self.senders.is_empty()
    }
}

/// How a `run` invocation decides what to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Ask a person, through whatever selection UI the consumer has.
    Interactive,
    /// Apply the policy and never prompt.
    Headless,
    /// Nothing to select by and nobody to ask: the caller has to say what it
    /// wants before anything can happen.
    SelectionRequired,
}

/// Decide how a run gets its senders.
///
/// A selection policy is itself the statement that no person is watching, so it
/// always wins over an attached terminal -- `unsubscribe run --resumed --yes`
/// must behave identically whether it was started by a timer or typed by hand.
#[must_use]
pub fn decide_run_mode(policy: &SelectionPolicy, interactive: bool) -> RunMode {
    if !policy.is_empty() {
        RunMode::Headless
    } else if interactive {
        RunMode::Interactive
    } else {
        RunMode::SelectionRequired
    }
}

/// One sender a policy picked out, and the flag that picked it.
#[derive(Debug, Clone)]
pub struct SelectedSender {
    pub sender: SenderInfo,
    pub reason: SelectionReason,
}

/// A selection that is larger than the policy allowed.
///
/// Reported rather than truncated: silently acting on the first 50 of 400
/// senders is a worse answer than refusing and letting the caller raise the
/// cap deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapExceeded {
    /// How many senders the policy matched.
    pub selected: usize,
    /// The cap that was in force.
    pub max_senders: u32,
}

/// What a policy matched.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    /// Matched senders, in the order a consumer should present them.
    pub selected: Vec<SelectedSender>,
    /// Addresses that were named but did not appear in this scan. Reported and
    /// skipped: a sender that stopped mailing is not an error.
    pub unknown: Vec<String>,
    /// Set when the match is larger than [`SelectionPolicy::max_senders`].
    pub over_cap: Option<CapExceeded>,
}

impl Selection {
    /// The senders themselves, ready for [`crate::pipeline::plan_run`].
    #[must_use]
    pub fn senders(&self) -> Vec<SenderInfo> {
        self.selected.iter().map(|s| s.sender.clone()).collect()
    }

    /// Whether the policy matched nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}

/// Apply a selection policy to the annotated senders of a scan.
///
/// Pure. Each sender is considered once, in the order the annotation produced
/// (previously unsubscribed, then active, then stale), and carries the first
/// reason that matches -- being named outranks everything, because naming a
/// sender is the most specific thing a caller can do. That single pass is what
/// makes overlapping flags a union rather than a source of duplicates.
///
/// A previously unsubscribed sender that has *not* resumed is reachable only by
/// name: `--all-active` deliberately excludes senders that were already asked
/// and have said nothing since.
#[must_use]
pub fn select_by_policy(annotated: &AnnotatedSenders, policy: &SelectionPolicy) -> Selection {
    let named: Vec<String> = policy.senders.iter().map(|s| s.to_lowercase()).collect();
    let is_named = |sender: &SenderInfo| named.iter().any(|n| *n == sender.email.to_lowercase());

    let previously = annotated.previously_unsubscribed.iter().filter_map(|p| {
        if is_named(&p.sender) {
            Some((p.sender.clone(), SelectionReason::Named))
        } else if policy.resumed && p.verdict.outcome.is_resumed() {
            Some((p.sender.clone(), SelectionReason::Resumed))
        } else {
            None
        }
    });

    let pick = |senders: &[SenderInfo], wanted: bool, reason: SelectionReason| {
        senders
            .iter()
            .filter_map(|sender| {
                if is_named(sender) {
                    Some((sender.clone(), SelectionReason::Named))
                } else if wanted {
                    Some((sender.clone(), reason))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };

    let selected: Vec<SelectedSender> = previously
        .chain(pick(&annotated.active, policy.all_active, SelectionReason::Active))
        .chain(pick(&annotated.stale, policy.stale, SelectionReason::Stale))
        .map(|(sender, reason)| SelectedSender { sender, reason })
        .collect();

    let unknown = policy
        .senders
        .iter()
        .filter(|wanted| {
            !selected
                .iter()
                .any(|s| s.sender.email.eq_ignore_ascii_case(wanted))
        })
        .cloned()
        .collect();

    let over_cap = (policy.max_senders > 0 && selected.len() > policy.max_senders as usize).then(
        || CapExceeded {
            selected: selected.len(),
            max_senders: policy.max_senders,
        },
    );

    Selection {
        selected,
        unknown,
        over_cap,
    }
}

/// Read a `--senders-file`: one address per line, `#` comments, blanks ignored.
///
/// Takes the file's contents rather than a path so it stays pure and the
/// consumer owns the I/O. A trailing comment on an address line is stripped
/// too, which is what anyone who has ever kept such a list expects.
#[must_use]
pub fn parse_senders_file(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}
