//! The Run panel: what the last scan found, and the two ways to act on it.
//!
//! The numbers are not computed here. [`RunStats::gather`] hands the cached
//! scan and the account's history to the same core functions a run uses, and
//! whether the cached scan can be reused at all is [`ScanAction`] from core --
//! the very decision the `run` command asks -- so the panel and a headless run
//! can never disagree.

use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    annotate_senders, ObtainedSenders, Resumption, RunPolicy, ScanAction, UnsubscribeAttempt,
};

use super::app::{Effect, Nav};
use super::keys::{self, Action};
use crate::time::{age_secs_since, format_relative_age, utc_to_local_display};

/// What the Run panel tells the user before they do anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStats {
    /// When the cached scan was taken (ISO 8601, UTC), if there is one.
    pub scanned_at: Option<String>,
    /// Senders the cached scan offers, after the `min_emails` filter.
    pub sender_count: usize,
    /// Of those, how many have been successfully unsubscribed from before.
    pub previously_unsubscribed: usize,
    /// Of those, how many kept mailing anyway.
    pub resumed: usize,
    /// Warnings the last scan recorded.
    pub warnings: usize,
    /// What core says about reusing the cached scan, asked as the "unsubscribe
    /// from the last scan" action asks it: demand the cache, and see whether
    /// there is one.
    pub cache: ScanAction,
}

impl Default for RunStats {
    fn default() -> Self {
        Self {
            scanned_at: None,
            sender_count: 0,
            previously_unsubscribed: 0,
            resumed: 0,
            warnings: 0,
            cache: ScanAction::CacheUnavailable,
        }
    }
}

impl RunStats {
    /// Judge the cached scan against the account's history.
    ///
    /// Pure: every input arrives as data. Nothing is recorded -- opening the
    /// panel is not an observation, and the resumptions it counts are written
    /// by the scan or run that actually looks at the mailbox.
    #[must_use]
    pub fn gather(
        account_id: &str,
        cached: Option<ObtainedSenders>,
        attempts: &[UnsubscribeAttempt],
        resumptions: &[Resumption],
        policy: &RunPolicy,
        now: i64,
        warnings: usize,
        cache: ScanAction,
    ) -> Self {
        let Some(cached) = cached else {
            return Self {
                warnings,
                cache,
                ..Self::default()
            };
        };
        let scanned_at = Some(cached.scanned_at);
        let annotated = annotate_senders(
            account_id,
            cached.senders,
            attempts,
            resumptions,
            policy,
            now,
        );
        Self {
            scanned_at,
            sender_count: annotated.total(),
            previously_unsubscribed: annotated.previously_unsubscribed.len(),
            resumed: annotated.resumed().count(),
            warnings,
            cache,
        }
    }

    /// Whether the cached scan can be worked from without scanning first.
    #[must_use]
    pub fn has_usable_cache(&self) -> bool {
        !matches!(self.cache, ScanAction::CacheUnavailable)
    }
}

/// One of the two things the Run panel offers to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunChoice {
    ScanAndUnsubscribe,
    FromLastScan,
}

impl RunChoice {
    pub const ALL: [RunChoice; 2] = [Self::ScanAndUnsubscribe, Self::FromLastScan];

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ScanAndUnsubscribe => "Scan and unsubscribe",
            Self::FromLastScan => "Unsubscribe from last scan",
        }
    }

    /// The one-line explanation under the highlighted action, which is also
    /// the reason an unavailable action gives for being unavailable.
    #[must_use]
    pub fn description(self, stats: &RunStats) -> String {
        match self {
            Self::ScanAndUnsubscribe => {
                "Read the mailbox again, then choose who to unsubscribe from.".to_string()
            }
            Self::FromLastScan if !stats.has_usable_cache() => {
                "No cached scan to work from \u{2014} scan the mailbox first.".to_string()
            }
            Self::FromLastScan => format!(
                "Choose from the {} senders the last scan found.",
                stats.sender_count
            ),
        }
    }

    /// Whether the action can be taken at all right now.
    #[must_use]
    pub fn is_available(self, stats: &RunStats) -> bool {
        match self {
            Self::ScanAndUnsubscribe => true,
            Self::FromLastScan => stats.has_usable_cache(),
        }
    }
}

/// The panel's cursor and the numbers it shows.
#[derive(Debug, Clone, Default)]
pub struct RunPanel {
    pub stats: RunStats,
    pub cursor: usize,
}

impl RunPanel {
    #[must_use]
    pub fn new(stats: RunStats) -> Self {
        Self { stats, cursor: 0 }
    }

    /// The action under the cursor.
    #[must_use]
    pub fn selected(&self) -> RunChoice {
        RunChoice::ALL[self.cursor.min(RunChoice::ALL.len() - 1)]
    }

    pub fn on_action(&mut self, action: Action) -> Nav {
        let last = RunChoice::ALL.len() - 1;
        if let Some(cursor) = keys::move_cursor(action, self.cursor, last) {
            self.cursor = cursor;
            return Nav::Stay;
        }
        match action {
            // An unavailable action says why on screen; pressing Enter on it
            // does nothing rather than starting something else.
            Action::Activate if self.selected().is_available(&self.stats) => {
                match self.selected() {
                    RunChoice::ScanAndUnsubscribe => Nav::Effect(Effect::Scan),
                    RunChoice::FromLastScan => Nav::Effect(Effect::Review),
                }
            }
            Action::Back => Nav::Pop,
            _ => Nav::Stay,
        }
    }

    /// The actions this panel answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        vec![
            Action::MoveUp,
            Action::MoveDown,
            Action::Activate,
            Action::Help,
            Action::Back,
        ]
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render(f: &mut Frame, area: Rect, panel: &RunPanel, focused: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // the last scan, in numbers
            Constraint::Min(4),    // the two actions
            Constraint::Length(2), // what the highlighted one does
        ])
        .split(area);

    f.render_widget(summary(&panel.stats), chunks[0]);

    let rows: Vec<Line> = RunChoice::ALL
        .iter()
        .enumerate()
        .map(|(index, choice)| {
            let available = choice.is_available(&panel.stats);
            let marker = if index == panel.cursor { ">" } else { " " };
            let style = match (index == panel.cursor, available, focused) {
                (true, true, true) => Style::default().bg(Color::DarkGray).fg(Color::White).bold(),
                (true, _, _) => Style::default().fg(Color::DarkGray).bold(),
                (false, true, _) => Style::default(),
                (false, false, _) => Style::default().fg(Color::DarkGray),
            };
            Line::styled(format!(" {marker} {}", choice.label()), style)
        })
        .collect();
    f.render_widget(Paragraph::new(rows), chunks[1]);

    f.render_widget(
        Paragraph::new(format!(" {}", panel.selected().description(&panel.stats)))
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true }),
        chunks[2],
    );
}

/// The counts, as a block of plain sentences rather than a dashboard.
fn summary(stats: &RunStats) -> Paragraph<'static> {
    let scan = match &stats.scanned_at {
        None => Line::styled(
            " No scan yet.",
            Style::default().fg(Color::DarkGray),
        ),
        Some(ts) => {
            let when = utc_to_local_display(ts).unwrap_or_else(|| ts.clone());
            let age = age_secs_since(ts)
                .map(format_relative_age)
                .map(|age| format!(" ({age})"))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(" Last scan ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{when}{age}"), Style::default().fg(Color::White)),
                Span::styled("  \u{00b7}  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    stats.sender_count.to_string(),
                    Style::default().fg(Color::Cyan).bold(),
                ),
                Span::raw(" senders with unsubscribe links"),
            ])
        }
    };

    let history = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            stats.previously_unsubscribed.to_string(),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::raw(" previously unsubscribed, "),
        Span::styled(
            stats.resumed.to_string(),
            if stats.resumed > 0 {
                Style::default().fg(Color::Red).bold()
            } else {
                Style::default().fg(Color::Cyan).bold()
            },
        ),
        Span::raw(" mailing again"),
    ]);

    Paragraph::new(vec![Line::raw(""), scan, history, Line::raw("")])
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::BOTTOM))
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::{Folder, FolderMessage, MessageId, SenderInfo, UnsubscribeMethod};

    const ACCOUNT: &str = "user@example.com";
    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_700_000_000;
    const SCANNED_AT: &str = "2026-06-01T09:00:00Z";

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Quit => "quit",
            Nav::Effect(Effect::Scan) => "scan",
            Nav::Effect(Effect::Review) => "review",
            Nav::Effect(_) => "other effect",
        }
    }

    fn policy() -> RunPolicy {
        RunPolicy {
            min_emails: 1,
            stale_after_months: 12,
            grace_period_days: 14,
            dry_run: false,
        }
    }

    fn sender(email: &str, last_seen: Option<i64>) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 4,
            messages: vec![FolderMessage {
                folder: Folder::new("INBOX"),
                message_id: MessageId::new("INBOX:1"),
            }],
            last_seen,
        }
    }

    fn cached(senders: Vec<SenderInfo>) -> ObtainedSenders {
        ObtainedSenders {
            senders,
            warnings: Vec::new(),
            scanned_at: SCANNED_AT.to_string(),
            from_cache: true,
        }
    }

    fn attempt(id: &str, email: &str, at: i64) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: ACCOUNT.to_string(),
            sender_email: email.to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: None,
            attempted_at: at,
            method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            success: true,
            http_status: Some(200),
            url: "https://acme.example.com/unsub".to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        }
    }

    fn gather(cache: Option<ObtainedSenders>, attempts: &[UnsubscribeAttempt]) -> RunStats {
        let action = if cache.is_some() {
            ScanAction::UseCache
        } else {
            ScanAction::CacheUnavailable
        };
        RunStats::gather(ACCOUNT, cache, attempts, &[], &policy(), NOW, 0, action)
    }

    // -----------------------------------------------------------------------
    // RunStats::gather
    // -----------------------------------------------------------------------

    #[test]
    fn with_no_cache_the_panel_shows_no_scan_and_no_counts() {
        let stats = gather(None, &[]);

        assert_eq!(stats.scanned_at, None);
        assert_eq!(stats.sender_count, 0);
        assert!(!stats.has_usable_cache());
    }

    #[test]
    fn warnings_are_shown_even_when_there_is_no_cache() {
        // The warnings file outlives the cache, and deleting the cache must
        // not hide headers the last scan could not parse.
        let stats = RunStats::gather(
            ACCOUNT,
            None,
            &[],
            &[],
            &policy(),
            NOW,
            5,
            ScanAction::CacheUnavailable,
        );

        assert_eq!(stats.warnings, 5);
        assert_eq!(stats.sender_count, 0);
    }

    #[test]
    fn an_empty_cache_still_reports_when_the_scan_was_taken() {
        let stats = gather(Some(cached(vec![])), &[]);

        assert_eq!(stats.scanned_at.as_deref(), Some(SCANNED_AT));
        assert_eq!(stats.sender_count, 0);
        assert_eq!(stats.previously_unsubscribed, 0);
        assert_eq!(stats.resumed, 0);
    }

    #[test]
    fn every_cached_sender_is_counted_whichever_group_it_lands_in() {
        let senders = vec![
            sender("fresh@acme.example.com", Some(NOW - DAY)),
            // Stale: last seen over a year ago.
            sender("old@acme.example.com", Some(NOW - 400 * DAY)),
            sender("quiet@acme.example.com", None),
        ];

        assert_eq!(gather(Some(cached(senders)), &[]).sender_count, 3);
    }

    #[test]
    fn a_sender_with_a_successful_unsubscribe_behind_it_is_counted_as_previously_unsubscribed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 60 * DAY)];
        // Nothing has arrived since the unsubscribe, so it was honoured.
        let senders = vec![sender("news@acme.example.com", Some(NOW - 90 * DAY))];

        let stats = gather(Some(cached(senders)), &attempts);

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 0, "it stopped mailing");
    }

    #[test]
    fn a_sender_mailing_again_after_the_grace_period_is_counted_as_resumed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 60 * DAY)];
        // Newest mail 20 days after the unsubscribe: past the 14-day grace.
        let senders = vec![sender("news@acme.example.com", Some(NOW - 40 * DAY))];

        let stats = gather(Some(cached(senders)), &attempts);

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 1);
    }

    #[test]
    fn a_sender_still_inside_its_grace_period_is_not_counted_as_resumed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 20 * DAY)];
        let senders = vec![sender("news@acme.example.com", Some(NOW - 10 * DAY))];

        let stats = gather(Some(cached(senders)), &attempts);

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 0, "the sender is still allowed time to act");
    }

    #[test]
    fn only_core_decides_whether_the_cached_scan_can_be_reused() {
        for (action, usable) in [
            (ScanAction::UseCache, true),
            (ScanAction::Ask { default_cached: false }, true),
            (ScanAction::Rescan, true),
            (ScanAction::CacheUnavailable, false),
        ] {
            let stats = RunStats {
                cache: action,
                ..RunStats::default()
            };
            assert_eq!(stats.has_usable_cache(), usable, "{action:?}");
        }
    }

    // -----------------------------------------------------------------------
    // The panel
    // -----------------------------------------------------------------------

    fn panel(stats: RunStats) -> RunPanel {
        RunPanel::new(stats)
    }

    fn with_cache() -> RunStats {
        RunStats {
            scanned_at: Some(SCANNED_AT.to_string()),
            sender_count: 42,
            cache: ScanAction::UseCache,
            ..RunStats::default()
        }
    }

    #[test]
    fn the_cursor_starts_on_scanning() {
        assert_eq!(panel(with_cache()).selected(), RunChoice::ScanAndUnsubscribe);
    }

    #[test]
    fn moving_walks_the_two_actions_and_stops_at_both_ends() {
        let mut panel = panel(with_cache());

        panel.on_action(Action::MoveDown);
        assert_eq!(panel.selected(), RunChoice::FromLastScan);
        panel.on_action(Action::MoveDown);
        assert_eq!(panel.selected(), RunChoice::FromLastScan);
        panel.on_action(Action::MoveUp);
        assert_eq!(panel.selected(), RunChoice::ScanAndUnsubscribe);
        panel.on_action(Action::MoveUp);
        assert_eq!(panel.selected(), RunChoice::ScanAndUnsubscribe);
    }

    #[test]
    fn each_action_asks_the_shell_for_its_own_pipeline() {
        let mut panel = panel(with_cache());

        assert_eq!(nav_name(&panel.on_action(Action::Activate)), "scan");
        panel.on_action(Action::MoveDown);
        assert_eq!(nav_name(&panel.on_action(Action::Activate)), "review");
    }

    #[test]
    fn the_cached_action_does_nothing_at_all_when_there_is_no_cache() {
        let mut panel = panel(RunStats::default());
        panel.on_action(Action::MoveDown);

        assert!(!panel.selected().is_available(&panel.stats));
        assert_eq!(nav_name(&panel.on_action(Action::Activate)), "stay");
    }

    #[test]
    fn an_unavailable_action_says_why_rather_than_only_dimming() {
        let description = RunChoice::FromLastScan.description(&RunStats::default());

        assert!(description.contains("scan the mailbox first"), "{description}");
    }

    #[test]
    fn the_cached_action_names_how_many_senders_the_last_scan_found() {
        assert!(RunChoice::FromLastScan
            .description(&with_cache())
            .contains("42"));
    }

    #[test]
    fn esc_leaves_the_panel_rather_than_quitting() {
        let mut panel = panel(with_cache());

        assert_eq!(nav_name(&panel.on_action(Action::Back)), "pop");
    }

    #[test]
    fn q_inside_the_panel_does_nothing() {
        let mut panel = panel(with_cache());

        assert_eq!(nav_name(&panel.on_action(Action::Quit)), "stay");
    }

    #[test]
    fn a_cursor_past_the_end_still_resolves_to_an_action() {
        let mut panel = panel(with_cache());
        panel.cursor = 99;

        assert_eq!(panel.selected(), RunChoice::FromLastScan);
    }
}
