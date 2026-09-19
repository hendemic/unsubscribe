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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escalation::NextStep;
    use crate::history::{PreviouslyUnsubscribed, SenderVerdict, UnsubscribeOutcome};
    use crate::types::{Folder, FolderMessage, MessageId};

    fn sender(email: &str) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: email.split('@').nth(1).unwrap_or("example.com").to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/u".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 3,
            messages: vec![FolderMessage {
                folder: Folder::new("INBOX"),
                message_id: MessageId::new(format!("INBOX:{email}:1")),
            }],
            last_seen: Some(1_700_000_000),
        }
    }

    /// A previously unsubscribed sender carrying the given verdict.
    fn previously(email: &str, outcome: UnsubscribeOutcome) -> PreviouslyUnsubscribed {
        PreviouslyUnsubscribed {
            sender: sender(email),
            verdict: SenderVerdict {
                attempt_id: format!("attempt-for-{email}"),
                unsubscribed_at: 1_600_000_000,
                outcome,
                violation_count: u32::from(outcome.is_resumed()),
                next_step: NextStep::FirstAttempt,
            },
        }
    }

    /// One sender of each annotation group, so a policy's exclusions are
    /// visible rather than implied.
    fn annotated() -> AnnotatedSenders {
        AnnotatedSenders {
            previously_unsubscribed: vec![
                previously("resumed@acme.example.com", UnsubscribeOutcome::Resumed { days_after: 20 }),
                previously("grace@acme.example.com", UnsubscribeOutcome::WithinGrace { days_left: 4 }),
                previously("quiet@acme.example.com", UnsubscribeOutcome::NoNewMail),
            ],
            active: vec![
                sender("active-one@acme.example.com"),
                sender("active-two@acme.example.com"),
            ],
            stale: vec![sender("stale@acme.example.com")],
            new_resumptions: Vec::new(),
        }
    }

    /// The addresses a selection picked, in order.
    fn emails(selection: &Selection) -> Vec<String> {
        selection
            .selected
            .iter()
            .map(|s| s.sender.email.clone())
            .collect()
    }

    /// The reason recorded for one address.
    fn reason_for(selection: &Selection, email: &str) -> Option<SelectionReason> {
        selection
            .selected
            .iter()
            .find(|s| s.sender.email == email)
            .map(|s| s.reason)
    }

    fn policy() -> SelectionPolicy {
        SelectionPolicy::default()
    }

    // -----------------------------------------------------------------------
    // --resumed
    // -----------------------------------------------------------------------

    #[test]
    fn resumed_selects_only_senders_that_ignored_an_unsubscribe() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                ..policy()
            },
        );
        assert_eq!(emails(&selection), ["resumed@acme.example.com"]);
    }

    #[test]
    fn resumed_excludes_a_sender_still_inside_its_grace_period() {
        // Mail arriving four days after an unsubscribe is not yet a violation,
        // so acting on it would be acting early.
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                ..policy()
            },
        );
        assert!(!emails(&selection).contains(&"grace@acme.example.com".to_string()));
    }

    #[test]
    fn resumed_excludes_a_sender_that_has_stopped_mailing() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                ..policy()
            },
        );
        assert!(!emails(&selection).contains(&"quiet@acme.example.com".to_string()));
    }

    #[test]
    fn a_resumed_sender_is_reported_as_selected_for_that_reason() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                ..policy()
            },
        );
        assert_eq!(
            reason_for(&selection, "resumed@acme.example.com"),
            Some(SelectionReason::Resumed)
        );
    }

    // -----------------------------------------------------------------------
    // --all-active
    // -----------------------------------------------------------------------

    #[test]
    fn all_active_selects_every_active_sender() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                ..policy()
            },
        );
        assert_eq!(
            emails(&selection),
            ["active-one@acme.example.com", "active-two@acme.example.com"]
        );
    }

    #[test]
    fn all_active_excludes_stale_senders() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                ..policy()
            },
        );
        assert!(!emails(&selection).contains(&"stale@acme.example.com".to_string()));
    }

    #[test]
    fn all_active_excludes_senders_already_unsubscribed_from() {
        // Asking a sender again that has said nothing since is the one thing
        // `--all-active` must never do on its own.
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                ..policy()
            },
        );
        for already_asked in [
            "resumed@acme.example.com",
            "grace@acme.example.com",
            "quiet@acme.example.com",
        ] {
            assert!(
                !emails(&selection).contains(&already_asked.to_string()),
                "{already_asked} had already been unsubscribed from"
            );
        }
    }

    #[test]
    fn stale_selects_only_the_stale_group() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                stale: true,
                ..policy()
            },
        );
        assert_eq!(emails(&selection), ["stale@acme.example.com"]);
        assert_eq!(
            reason_for(&selection, "stale@acme.example.com"),
            Some(SelectionReason::Stale)
        );
    }

    // -----------------------------------------------------------------------
    // Flags combine as a union
    // -----------------------------------------------------------------------

    #[test]
    fn every_flag_together_selects_each_matching_sender_exactly_once() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                all_active: true,
                stale: true,
                senders: vec![
                    "active-one@acme.example.com".to_string(),
                    "stale@acme.example.com".to_string(),
                ],
                max_senders: 0,
            },
        );
        let picked = emails(&selection);
        let mut sorted = picked.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), picked.len(), "a sender was selected twice: {picked:?}");
        assert_eq!(picked.len(), 4);
    }

    #[test]
    fn naming_a_sender_outranks_the_flag_that_would_also_have_matched_it() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                senders: vec!["active-one@acme.example.com".to_string()],
                ..policy()
            },
        );
        assert_eq!(
            reason_for(&selection, "active-one@acme.example.com"),
            Some(SelectionReason::Named)
        );
        assert_eq!(
            reason_for(&selection, "active-two@acme.example.com"),
            Some(SelectionReason::Active)
        );
    }

    // -----------------------------------------------------------------------
    // Explicit sender list
    // -----------------------------------------------------------------------

    #[test]
    fn a_named_sender_matches_regardless_of_case() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec!["Active-One@Acme.Example.COM".to_string()],
                ..policy()
            },
        );
        assert_eq!(emails(&selection), ["active-one@acme.example.com"]);
        assert!(selection.unknown.is_empty());
    }

    #[test]
    fn naming_reaches_a_sender_no_flag_could_have_selected() {
        // A sender that was unsubscribed from and has gone quiet is reachable
        // only by name -- that is the whole point of the flag.
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec!["quiet@acme.example.com".to_string()],
                ..policy()
            },
        );
        assert_eq!(emails(&selection), ["quiet@acme.example.com"]);
    }

    #[test]
    fn an_address_that_is_not_in_this_scan_is_reported_rather_than_selected() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec!["gone@elsewhere.example.com".to_string()],
                ..policy()
            },
        );
        assert!(selection.is_empty());
        assert_eq!(selection.unknown, ["gone@elsewhere.example.com"]);
    }

    #[test]
    fn an_unknown_address_does_not_stop_the_known_ones_being_selected() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec![
                    "gone@elsewhere.example.com".to_string(),
                    "active-two@acme.example.com".to_string(),
                ],
                ..policy()
            },
        );
        assert_eq!(emails(&selection), ["active-two@acme.example.com"]);
        assert_eq!(selection.unknown, ["gone@elsewhere.example.com"]);
    }

    #[test]
    fn a_named_address_that_matched_is_never_also_reported_as_unknown() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec!["ACTIVE-TWO@acme.example.com".to_string()],
                ..policy()
            },
        );
        assert!(
            selection.unknown.is_empty(),
            "a case-different spelling was treated as a different sender: {:?}",
            selection.unknown
        );
    }

    // -----------------------------------------------------------------------
    // --max-senders
    // -----------------------------------------------------------------------

    #[test]
    fn a_selection_exactly_at_the_cap_is_allowed() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                max_senders: 2,
                ..policy()
            },
        );
        assert_eq!(selection.selected.len(), 2);
        assert_eq!(selection.over_cap, None);
    }

    #[test]
    fn one_sender_over_the_cap_is_refused_rather_than_truncated() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                max_senders: 1,
                ..policy()
            },
        );
        assert_eq!(
            selection.over_cap,
            Some(CapExceeded {
                selected: 2,
                max_senders: 1,
            })
        );
        // Nothing is dropped: the caller is told the real size so it can raise
        // the limit deliberately.
        assert_eq!(selection.selected.len(), 2);
    }

    #[test]
    fn a_zero_cap_lifts_the_limit_entirely() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                resumed: true,
                all_active: true,
                stale: true,
                max_senders: 0,
                ..policy()
            },
        );
        assert_eq!(selection.selected.len(), 4);
        assert_eq!(selection.over_cap, None);
    }

    #[test]
    fn an_empty_selection_is_never_over_the_cap() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                senders: vec!["gone@elsewhere.example.com".to_string()],
                max_senders: 1,
                ..policy()
            },
        );
        assert!(selection.is_empty());
        assert_eq!(selection.over_cap, None);
    }

    // -----------------------------------------------------------------------
    // Empty selections
    // -----------------------------------------------------------------------

    #[test]
    fn a_policy_that_matches_nothing_yields_an_empty_selection() {
        let empty = AnnotatedSenders::default();
        let selection = select_by_policy(
            &empty,
            &SelectionPolicy {
                resumed: true,
                all_active: true,
                stale: true,
                ..policy()
            },
        );
        assert!(selection.is_empty());
        assert!(selection.senders().is_empty());
    }

    #[test]
    fn senders_carries_the_selected_senders_in_selection_order() {
        let selection = select_by_policy(
            &annotated(),
            &SelectionPolicy {
                all_active: true,
                ..policy()
            },
        );
        let senders = selection.senders();
        assert_eq!(
            senders.iter().map(|s| s.email.as_str()).collect::<Vec<_>>(),
            ["active-one@acme.example.com", "active-two@acme.example.com"]
        );
    }

    // -----------------------------------------------------------------------
    // is_empty / decide_run_mode
    // -----------------------------------------------------------------------

    #[test]
    fn a_policy_with_no_selection_flag_names_nothing() {
        assert!(SelectionPolicy::default().is_empty());
    }

    #[test]
    fn a_cap_on_its_own_is_not_a_selection() {
        // `--max-senders` narrows a selection; it never makes one.
        assert!(SelectionPolicy {
            max_senders: 10,
            ..SelectionPolicy::default()
        }
        .is_empty());
    }

    #[test]
    fn each_selection_flag_on_its_own_makes_the_policy_non_empty() {
        let policies = [
            SelectionPolicy { resumed: true, ..SelectionPolicy::default() },
            SelectionPolicy { all_active: true, ..SelectionPolicy::default() },
            SelectionPolicy { stale: true, ..SelectionPolicy::default() },
            SelectionPolicy {
                senders: vec!["a@b.example.com".to_string()],
                ..SelectionPolicy::default()
            },
        ];
        for policy in policies {
            assert!(!policy.is_empty(), "{policy:?} names something");
        }
    }

    #[test]
    fn a_selection_flag_runs_headless_even_with_a_terminal_attached() {
        // Typing the flag by hand must do the same thing a timer's does.
        let policy = SelectionPolicy {
            resumed: true,
            ..SelectionPolicy::default()
        };
        assert_eq!(decide_run_mode(&policy, true), RunMode::Headless);
        assert_eq!(decide_run_mode(&policy, false), RunMode::Headless);
    }

    #[test]
    fn no_selection_flag_with_a_terminal_opens_the_selection_screen() {
        assert_eq!(
            decide_run_mode(&SelectionPolicy::default(), true),
            RunMode::Interactive
        );
    }

    #[test]
    fn no_selection_flag_and_no_terminal_demands_a_selection() {
        assert_eq!(
            decide_run_mode(&SelectionPolicy::default(), false),
            RunMode::SelectionRequired
        );
    }

    // -----------------------------------------------------------------------
    // parse_senders_file
    // -----------------------------------------------------------------------

    #[test]
    fn a_senders_file_reads_one_address_per_line() {
        assert_eq!(
            parse_senders_file("one@example.com\ntwo@example.com\n"),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn blank_lines_in_a_senders_file_are_ignored() {
        assert_eq!(
            parse_senders_file("\n\none@example.com\n\n\ntwo@example.com\n\n"),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn a_whole_line_comment_is_ignored() {
        assert_eq!(
            parse_senders_file("# senders to drop\none@example.com\n"),
            ["one@example.com"]
        );
    }

    #[test]
    fn a_trailing_comment_is_stripped_from_an_address() {
        assert_eq!(
            parse_senders_file("one@example.com  # keeps mailing\n"),
            ["one@example.com"]
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            parse_senders_file("   one@example.com\t\n\t two@example.com   \n"),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn crlf_line_endings_do_not_leave_a_carriage_return_on_the_address() {
        // A list edited on Windows must match the same senders as one edited
        // anywhere else.
        assert_eq!(
            parse_senders_file("one@example.com\r\ntwo@example.com\r\n"),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn an_empty_senders_file_names_nobody() {
        assert!(parse_senders_file("").is_empty());
        assert!(parse_senders_file("\n\n   \n# only a comment\n").is_empty());
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_yields_its_last_address() {
        assert_eq!(
            parse_senders_file("one@example.com\ntwo@example.com"),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn addresses_from_a_file_keep_the_case_they_were_written_in() {
        // Matching lowercases both sides; the file's own spelling is what is
        // reported back as unknown, so it must survive parsing.
        assert_eq!(
            parse_senders_file("One@Example.COM\n"),
            ["One@Example.COM"]
        );
    }

    #[test]
    fn selection_reasons_have_stable_identifiers() {
        // These are what a script matches on, so they are pinned here rather
        // than left to follow whatever the labels become.
        assert_eq!(SelectionReason::Chosen.as_id(), "chosen");
        assert_eq!(SelectionReason::Named.as_id(), "named");
        assert_eq!(SelectionReason::Resumed.as_id(), "resumed");
        assert_eq!(SelectionReason::Active.as_id(), "active");
        assert_eq!(SelectionReason::Stale.as_id(), "stale");
    }
}
