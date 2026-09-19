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
