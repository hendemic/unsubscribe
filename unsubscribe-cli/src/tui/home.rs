//! The Home screen: where the app opens, and what it knows about the account.
//!
//! The numbers on it are not computed here. [`HomeStats::gather`] hands the
//! cached scan and the account's history to the same core functions a run
//! uses, so Home and a headless `run` can never disagree about how many
//! senders resumed.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    annotate_senders, ObtainedSenders, Resumption, RunPolicy, UnsubscribeAttempt,
};

use super::app::{Effect, Nav};

/// What Home tells the user about the account before they do anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HomeStats {
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
}

impl HomeStats {
    /// Judge the cached scan against the account's history.
    ///
    /// Pure: every input arrives as data. Nothing is recorded -- opening Home
    /// is not an observation, and the resumptions it counts are written by the
    /// scan or run that actually looks at the mailbox.
    #[must_use]
    pub fn gather(
        account_id: &str,
        cached: Option<ObtainedSenders>,
        attempts: &[UnsubscribeAttempt],
        resumptions: &[Resumption],
        policy: &RunPolicy,
        now: i64,
        warnings: usize,
    ) -> Self {
        let Some(cached) = cached else {
            return Self {
                warnings,
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
        }
    }
}

/// One thing Home offers to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeAction {
    Scan,
    Review,
    History,
    Settings,
    Warnings,
    Reauthenticate,
    Quit,
}

impl HomeAction {
    pub const ALL: [HomeAction; 7] = [
        Self::Scan,
        Self::Review,
        Self::History,
        Self::Settings,
        Self::Warnings,
        Self::Reauthenticate,
        Self::Quit,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Scan => "Scan mailbox",
            Self::Review => "Review senders",
            Self::History => "History",
            Self::Settings => "Settings",
            Self::Warnings => "Scan warnings",
            Self::Reauthenticate => "Re-authenticate",
            Self::Quit => "Quit",
        }
    }

    /// The one-line explanation under the highlighted action.
    fn description(self, stats: &HomeStats) -> String {
        match self {
            Self::Scan => "Fetch headers from the mailbox and look for unsubscribe links.".into(),
            Self::Review if stats.sender_count == 0 => {
                "Nothing cached yet \u{2014} this will scan first.".into()
            }
            Self::Review => format!(
                "Choose from the {} senders the last scan found.",
                stats.sender_count
            ),
            Self::History => "Everything unsubscribed, and whether it worked.".into(),
            Self::Settings => "Account, folders, and behaviour preferences.".into(),
            Self::Warnings => match stats.warnings {
                0 => "No unparseable headers from the last scan.".into(),
                n => format!("{n} email(s) had unparseable List-Unsubscribe headers."),
            },
            Self::Reauthenticate => "Replace the stored credentials for this account.".into(),
            Self::Quit => "Leave the app.".into(),
        }
    }

    /// What choosing this action asks the shell to do.
    fn activate(self) -> Nav {
        match self {
            Self::Scan => Nav::Effect(Effect::Scan),
            Self::Review => Nav::Effect(Effect::Review),
            Self::History => Nav::Effect(Effect::OpenHistory),
            Self::Settings => Nav::Effect(Effect::OpenSettings),
            Self::Warnings => Nav::Effect(Effect::OpenWarnings),
            Self::Reauthenticate => Nav::Effect(Effect::Reauthenticate),
            Self::Quit => Nav::Quit,
        }
    }
}

/// Home's cursor and the numbers it shows.
#[derive(Debug, Clone)]
pub struct HomeScreen {
    pub stats: HomeStats,
    pub cursor: usize,
}

impl HomeScreen {
    #[must_use]
    pub fn new(stats: HomeStats) -> Self {
        Self { stats, cursor: 0 }
    }

    /// The action under the cursor.
    #[must_use]
    pub fn selected(&self) -> HomeAction {
        HomeAction::ALL[self.cursor.min(HomeAction::ALL.len() - 1)]
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1).min(HomeAction::ALL.len() - 1);
                Nav::Stay
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.cursor = 0;
                Nav::Stay
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.cursor = HomeAction::ALL.len() - 1;
                Nav::Stay
            }
            KeyCode::Enter => self.selected().activate(),
            // Home is the bottom of the stack, so quitting is the only way out.
            KeyCode::Char('q') | KeyCode::Esc => Nav::Quit,
            _ => Nav::Stay,
        }
    }

    pub fn hints(&self) -> &'static str {
        " j/k: move | Enter: choose | ?: keys | q: quit"
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("j / k / \u{2191}\u{2193}", "move between actions"),
            ("Enter", "run the highlighted action"),
            ("g / G", "first / last action"),
            ("?", "show this help"),
            ("q / Esc", "quit the app"),
        ]
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render(f: &mut Frame, area: Rect, screen: &HomeScreen) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // summary
            Constraint::Min(5),    // actions
            Constraint::Length(2), // description of the highlighted action
        ])
        .split(area);

    f.render_widget(summary(&screen.stats), chunks[0]);

    let items: Vec<Line> = HomeAction::ALL
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let style = if index == screen.cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White).bold()
            } else {
                Style::default()
            };
            Line::styled(format!("  {}", action.label()), style)
        })
        .collect();
    f.render_widget(
        Paragraph::new(items).block(Block::default().borders(Borders::ALL).title(" Actions ")),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(format!(" {}", screen.selected().description(&screen.stats)))
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true }),
        chunks[2],
    );
}

/// The counts, as a block of plain sentences rather than a dashboard.
fn summary(stats: &HomeStats) -> Paragraph<'static> {
    let senders = match stats.scanned_at {
        None => Line::styled(
            "  No scan yet \u{2014} start with Scan mailbox.",
            Style::default().fg(Color::DarkGray),
        ),
        Some(_) => Line::from(vec![
            Span::raw("  "),
            Span::styled(
                stats.sender_count.to_string(),
                Style::default().fg(Color::Cyan).bold(),
            ),
            Span::raw(" senders with unsubscribe links in the last scan"),
        ]),
    };

    let history = Line::from(vec![
        Span::raw("  "),
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

    Paragraph::new(vec![Line::raw(""), senders, history])
        .block(Block::default().borders(Borders::BOTTOM))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use unsubscribe_core::{Folder, FolderMessage, MessageId, SenderInfo, UnsubscribeMethod};

    const ACCOUNT: &str = "user@example.com";
    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_700_000_000;
    const SCANNED_AT: &str = "2026-06-01T09:00:00Z";

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Quit => "quit",
            Nav::Effect(effect) => match effect {
                Effect::Scan => "scan",
                Effect::Review => "review",
                Effect::OpenHistory => "history",
                Effect::OpenSettings => "settings",
                Effect::OpenWarnings => "warnings",
                Effect::Reauthenticate => "reauth",
                _ => "other effect",
            },
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

    // -----------------------------------------------------------------------
    // HomeStats::gather
    // -----------------------------------------------------------------------

    #[test]
    fn with_no_cache_home_shows_no_scan_and_no_counts() {
        let stats = HomeStats::gather(ACCOUNT, None, &[], &[], &policy(), NOW, 0);

        assert_eq!(stats, HomeStats::default());
        assert_eq!(stats.scanned_at, None);
    }

    #[test]
    fn warnings_are_shown_even_when_there_is_no_cache() {
        // The warnings file outlives the cache, and deleting the cache must
        // not hide headers the last scan could not parse.
        let stats = HomeStats::gather(ACCOUNT, None, &[], &[], &policy(), NOW, 5);

        assert_eq!(stats.warnings, 5);
        assert_eq!(stats.sender_count, 0);
    }

    #[test]
    fn an_empty_cache_still_reports_when_the_scan_was_taken() {
        let stats = HomeStats::gather(ACCOUNT, Some(cached(vec![])), &[], &[], &policy(), NOW, 0);

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

        let stats = HomeStats::gather(ACCOUNT, Some(cached(senders)), &[], &[], &policy(), NOW, 0);

        assert_eq!(stats.sender_count, 3);
    }

    #[test]
    fn a_sender_with_a_successful_unsubscribe_behind_it_is_counted_as_previously_unsubscribed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 60 * DAY)];
        // Nothing has arrived since the unsubscribe, so it was honoured.
        let senders = vec![sender("news@acme.example.com", Some(NOW - 90 * DAY))];

        let stats = HomeStats::gather(
            ACCOUNT,
            Some(cached(senders)),
            &attempts,
            &[],
            &policy(),
            NOW,
            0,
        );

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 0, "it stopped mailing");
    }

    #[test]
    fn a_sender_mailing_again_after_the_grace_period_is_counted_as_resumed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 60 * DAY)];
        // Newest mail 20 days after the unsubscribe: past the 14-day grace.
        let senders = vec![sender("news@acme.example.com", Some(NOW - 40 * DAY))];

        let stats = HomeStats::gather(
            ACCOUNT,
            Some(cached(senders)),
            &attempts,
            &[],
            &policy(),
            NOW,
            0,
        );

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 1);
    }

    #[test]
    fn a_sender_still_inside_its_grace_period_is_not_counted_as_resumed() {
        let attempts = [attempt("a1", "news@acme.example.com", NOW - 20 * DAY)];
        let senders = vec![sender("news@acme.example.com", Some(NOW - 10 * DAY))];

        let stats = HomeStats::gather(
            ACCOUNT,
            Some(cached(senders)),
            &attempts,
            &[],
            &policy(),
            NOW,
            0,
        );

        assert_eq!(stats.previously_unsubscribed, 1);
        assert_eq!(stats.resumed, 0, "the sender is still allowed time to act");
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    fn home() -> HomeScreen {
        HomeScreen::new(HomeStats::default())
    }

    #[test]
    fn the_cursor_starts_on_the_first_action() {
        assert_eq!(home().selected(), HomeAction::Scan);
    }

    #[test]
    fn moving_down_and_up_walks_the_actions_one_at_a_time() {
        let mut screen = home();

        screen.on_key(key(KeyCode::Down));
        assert_eq!(screen.selected(), HomeAction::Review);
        screen.on_key(key(KeyCode::Char('j')));
        assert_eq!(screen.selected(), HomeAction::History);
        screen.on_key(key(KeyCode::Char('k')));
        assert_eq!(screen.selected(), HomeAction::Review);
        screen.on_key(key(KeyCode::Up));
        assert_eq!(screen.selected(), HomeAction::Scan);
    }

    #[test]
    fn the_cursor_stops_at_both_ends_rather_than_wrapping() {
        let mut screen = home();

        for _ in 0..3 {
            screen.on_key(key(KeyCode::Up));
        }
        assert_eq!(screen.selected(), HomeAction::Scan);

        for _ in 0..HomeAction::ALL.len() + 3 {
            screen.on_key(key(KeyCode::Down));
        }
        assert_eq!(screen.selected(), HomeAction::Quit);
    }

    #[test]
    fn g_and_shift_g_jump_to_the_first_and_last_action() {
        let mut screen = home();

        screen.on_key(key(KeyCode::Char('G')));
        assert_eq!(screen.selected(), HomeAction::Quit);
        screen.on_key(key(KeyCode::Char('g')));
        assert_eq!(screen.selected(), HomeAction::Scan);
        screen.on_key(key(KeyCode::End));
        assert_eq!(screen.selected(), HomeAction::Quit);
        screen.on_key(key(KeyCode::Home));
        assert_eq!(screen.selected(), HomeAction::Scan);
    }

    #[test]
    fn moving_the_cursor_asks_the_shell_for_nothing() {
        let mut screen = home();

        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Down))), "stay");
        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Char('x')))), "stay");
    }

    #[test]
    fn each_action_leads_to_its_own_screen() {
        let expected = [
            (HomeAction::Scan, "scan"),
            (HomeAction::Review, "review"),
            (HomeAction::History, "history"),
            (HomeAction::Settings, "settings"),
            (HomeAction::Warnings, "warnings"),
            (HomeAction::Reauthenticate, "reauth"),
            (HomeAction::Quit, "quit"),
        ];

        for (index, (action, wanted)) in expected.into_iter().enumerate() {
            let mut screen = home();
            screen.cursor = index;
            assert_eq!(screen.selected(), action, "the list order changed");
            assert_eq!(nav_name(&screen.on_key(key(KeyCode::Enter))), wanted);
        }
    }

    #[test]
    fn home_is_the_floor_so_esc_and_q_leave_the_app_rather_than_going_back() {
        assert_eq!(nav_name(&home().on_key(key(KeyCode::Esc))), "quit");
        assert_eq!(nav_name(&home().on_key(key(KeyCode::Char('q')))), "quit");
    }

    #[test]
    fn review_is_offered_with_an_empty_cache_and_says_it_will_scan_first() {
        // It is never disabled: with nothing cached the shell falls through to
        // a scan, so the description has to say so.
        let mut screen = home();
        screen.cursor = 1;

        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Enter))), "review");
        assert!(HomeAction::Review
            .description(&HomeStats::default())
            .contains("scan first"));
    }

    #[test]
    fn review_names_how_many_senders_the_last_scan_found() {
        let stats = HomeStats {
            sender_count: 42,
            ..HomeStats::default()
        };

        assert!(HomeAction::Review.description(&stats).contains("42"));
    }

    #[test]
    fn the_warnings_action_says_how_many_headers_could_not_be_parsed() {
        let none = HomeAction::Warnings.description(&HomeStats::default());
        let some = HomeAction::Warnings.description(&HomeStats {
            warnings: 7,
            ..HomeStats::default()
        });

        assert!(none.contains("No unparseable"));
        assert!(some.contains('7'));
    }

    #[test]
    fn a_cursor_past_the_end_still_resolves_to_an_action() {
        let mut screen = home();
        screen.cursor = 99;

        assert_eq!(screen.selected(), HomeAction::Quit);
    }
}
