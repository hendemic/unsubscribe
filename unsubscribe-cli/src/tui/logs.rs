//! The Logs panel: every recorded event, newest first.
//!
//! Read-only, and it aggregates nothing of its own. The rows are
//! [`LogEntry`]s from `unsubscribe_core::history_view` -- the same feed the
//! headless side will read -- and the filter and search are that module's pure
//! functions. This file only decides how a row is worded and which rows are on
//! screen.

use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{LogEntry, LogFilter, LogKind, TimelineEvent};

use super::app::Nav;
use super::history::method_label;
use super::keys::{self, Action};
use crate::time::format_unix_date;

/// The feed, the filter over it, and where the viewport sits.
pub struct LogsPanel {
    /// Built once when the panel is loaded: the store is never touched again
    /// while the user scrolls or types.
    entries: Vec<LogEntry>,
    filter: LogFilter,
    visible: Vec<usize>,
    cursor: usize,
    scroll_offset: usize,
    /// True while the user is typing a search.
    searching: bool,
}

impl LogsPanel {
    #[must_use]
    pub fn new(entries: Vec<LogEntry>) -> Self {
        let filter = LogFilter::default();
        let visible = unsubscribe_core::visible_log(&entries, &filter);
        Self {
            entries,
            filter,
            visible,
            cursor: 0,
            scroll_offset: 0,
            searching: false,
        }
    }

    /// Whether a text field has focus, so the shell leaves the keystroke alone.
    #[must_use]
    pub fn captures_text(&self) -> bool {
        self.searching
    }

    fn refilter(&mut self) {
        self.visible = unsubscribe_core::visible_log(&self.entries, &self.filter);
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    fn last(&self) -> usize {
        self.visible.len().saturating_sub(1)
    }

    pub fn on_action(&mut self, action: Action) -> Nav {
        if self.searching {
            match action {
                Action::Type(c) => {
                    self.filter.search.push(c);
                    self.refilter();
                }
                Action::Erase => {
                    self.filter.search.pop();
                    self.refilter();
                }
                // Enter keeps the needle and leaves the field; Esc clears it.
                Action::Activate => self.searching = false,
                Action::Back => {
                    self.searching = false;
                    self.filter.search.clear();
                    self.refilter();
                }
                _ => {}
            }
            return Nav::Stay;
        }

        if let Some(cursor) = keys::move_cursor(action, self.cursor, self.last()) {
            self.cursor = cursor;
            return Nav::Stay;
        }
        match action {
            Action::Search => self.searching = true,
            Action::Mnemonic('f') => {
                self.filter.kind = self.filter.kind.next();
                self.refilter();
            }
            Action::Back => return Nav::Pop,
            _ => {}
        }
        Nav::Stay
    }

    /// The actions this panel answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        if self.searching {
            return vec![Action::Activate, Action::Back];
        }
        keys::list_actions(&[Action::Mnemonic('f'), Action::Search])
    }

    fn scroll_into_view(&mut self, height: usize) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if height > 0 && self.cursor >= self.scroll_offset + height {
            self.scroll_offset = self.cursor - height + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render(f: &mut Frame, area: Rect, panel: &mut LogsPanel, focused: bool) {
    if panel.entries.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(" Nothing recorded yet.", Style::default().fg(Color::Cyan)),
                Line::styled(
                    " Every unsubscribe attempt and every sender that starts up again",
                    Style::default().fg(Color::DarkGray),
                ),
                Line::styled(
                    " lands here, in the order it happened.",
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let height = chunks[0].height as usize;
    panel.scroll_into_view(height);

    // Only the visible slice is ever formatted: the feed holds every event the
    // account has ever recorded.
    let rows: Vec<Line> = panel
        .visible
        .iter()
        .enumerate()
        .skip(panel.scroll_offset)
        .take(height)
        .map(|(position, index)| {
            log_row(&panel.entries[*index], position == panel.cursor && focused)
        })
        .collect();

    f.render_widget(
        Paragraph::new(if rows.is_empty() {
            vec![Line::styled(
                " Nothing matches.",
                Style::default().fg(Color::DarkGray),
            )]
        } else {
            rows
        }),
        chunks[0],
    );

    f.render_widget(controls(panel), chunks[1]);
}

/// One event: when, who, what was tried, and how it went.
fn log_row(entry: &LogEntry, is_cursor: bool) -> Line<'static> {
    let (text, color) = match &entry.event {
        TimelineEvent::Attempt(attempt) => {
            let status = attempt
                .http_status
                .map(|status| status.to_string())
                .unwrap_or_default();
            // The escalation names the attempt it answers, so the pair reads
            // as one exchange rather than two unrelated rows.
            let follows = entry
                .follows
                .as_ref()
                .map(|earlier| {
                    format!(
                        "  \u{21b3} after the {} of {}",
                        method_label(&earlier.method),
                        format_unix_date(earlier.at)
                    )
                })
                .unwrap_or_default();
            (
                format!(
                    " {}  {:<30} {:<14} {:<4} {:<4} {}{follows}",
                    format_unix_date(entry.at),
                    truncate(&entry.sender_email, 30),
                    truncate(method_label(&attempt.method), 14),
                    if attempt.success { "ok" } else { "fail" },
                    status,
                    truncate(&attempt.detail, 40),
                ),
                if attempt.success {
                    Color::Green
                } else {
                    Color::Red
                },
            )
        }
        TimelineEvent::Resumption(resumption) => (
            format!(
                " {}  {:<30} {:<14} kept mailing \u{2014} {} emails, newest {}",
                format_unix_date(entry.at),
                truncate(&entry.sender_email, 30),
                "resumed",
                resumption.email_count,
                format_unix_date(resumption.last_seen),
            ),
            Color::Yellow,
        ),
    };

    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else {
        Style::default().fg(color)
    };
    Line::styled(text, style)
}

/// The filter and search line under the feed.
fn controls(panel: &LogsPanel) -> Paragraph<'static> {
    let kind = match panel.filter.kind {
        LogKind::All => "everything",
        LogKind::Failures => "failures only",
        LogKind::Resumptions => "resumptions only",
    };
    let search = if panel.searching {
        format!("/{}\u{2588}", panel.filter.search)
    } else if panel.filter.search.is_empty() {
        "none".to_string()
    } else {
        format!("/{}", panel.filter.search)
    };
    Paragraph::new(Line::from(vec![
        Span::styled(" showing ", Style::default().fg(Color::DarkGray)),
        Span::styled(kind, Style::default().fg(Color::Cyan)),
        Span::styled("   search ", Style::default().fg(Color::DarkGray)),
        Span::styled(search, Style::default().fg(Color::Yellow)),
        Span::styled(
            format!(
                "   {} of {} event(s)",
                panel.visible.len(),
                panel.entries.len()
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::{event_log, Resumption, UnsubscribeAttempt, UnsubscribeMethod};

    const DAY: i64 = 24 * 60 * 60;
    const T0: i64 = 1_700_000_000;

    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Park => "park",
            Nav::Quit => "quit",
            Nav::Effect(_) => "effect",
        }
    }

    fn attempt(id: &str, email: &str, at: i64, success: bool) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: "user@example.com".to_string(),
            sender_email: email.to_string(),
            sender_domain: email.split('@').nth(1).unwrap_or_default().to_string(),
            list_id: None,
            attempted_at: at,
            method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            success,
            http_status: Some(if success { 200 } else { 500 }),
            url: "https://acme.example.com/unsub".to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: "HTTP".to_string(),
        }
    }

    fn resumption(email: &str, at: i64) -> Resumption {
        Resumption {
            id: format!("r-{email}"),
            account: "user@example.com".to_string(),
            sender_email: email.to_string(),
            list_id: None,
            attempt_id: "a1".to_string(),
            observed_at: at,
            last_seen: at - DAY,
            email_count: 3,
        }
    }

    fn panel() -> LogsPanel {
        let attempts = [
            attempt("a1", "one@acme.example.com", T0 - 30 * DAY, true),
            attempt("a2", "two@beta.example.org", T0 - 20 * DAY, false),
        ];
        let resumptions = [resumption("one@acme.example.com", T0 - 5 * DAY)];
        LogsPanel::new(event_log(&attempts, &resumptions))
    }

    fn visible_addresses(panel: &LogsPanel) -> Vec<&str> {
        panel
            .visible
            .iter()
            .map(|index| panel.entries[*index].sender_email.as_str())
            .collect()
    }

    #[test]
    fn every_event_is_listed_newest_first() {
        let panel = panel();

        assert_eq!(panel.visible.len(), 3);
        assert_eq!(
            visible_addresses(&panel),
            [
                "one@acme.example.com",
                "two@beta.example.org",
                "one@acme.example.com"
            ]
        );
    }

    #[test]
    fn the_cursor_stops_at_both_ends() {
        let mut panel = panel();

        for _ in 0..10 {
            panel.on_action(Action::MoveDown);
        }
        assert_eq!(panel.cursor, 2);

        for _ in 0..10 {
            panel.on_action(Action::MoveUp);
        }
        assert_eq!(panel.cursor, 0);
    }

    #[test]
    fn f_cycles_through_everything_failures_and_resumptions() {
        let mut panel = panel();

        panel.on_action(Action::Mnemonic('f'));
        assert_eq!(panel.filter.kind, LogKind::Failures);
        assert_eq!(panel.visible.len(), 2, "one failed attempt, one resumption");

        panel.on_action(Action::Mnemonic('f'));
        assert_eq!(panel.filter.kind, LogKind::Resumptions);
        assert_eq!(panel.visible.len(), 1);

        panel.on_action(Action::Mnemonic('f'));
        assert_eq!(panel.filter.kind, LogKind::All);
        assert_eq!(panel.visible.len(), 3);
    }

    #[test]
    fn searching_narrows_the_feed_as_the_needle_is_typed() {
        let mut panel = panel();

        panel.on_action(Action::Search);
        assert!(panel.captures_text());
        for c in "beta".chars() {
            panel.on_action(Action::Type(c));
        }

        assert_eq!(visible_addresses(&panel), ["two@beta.example.org"]);
    }

    #[test]
    fn enter_keeps_the_needle_and_esc_clears_it() {
        let mut panel = panel();
        panel.on_action(Action::Search);
        panel.on_action(Action::Type('b'));
        panel.on_action(Action::Activate);

        assert!(!panel.captures_text());
        assert_eq!(panel.filter.search, "b");

        panel.on_action(Action::Search);
        panel.on_action(Action::Back);

        assert!(panel.filter.search.is_empty());
        assert_eq!(panel.visible.len(), 3);
    }

    #[test]
    fn esc_outside_a_search_backs_out_of_the_panel() {
        assert_eq!(nav_name(&panel().on_action(Action::Back)), "pop");
    }

    #[test]
    fn q_inside_the_panel_does_nothing() {
        assert_eq!(nav_name(&panel().on_action(Action::Quit)), "stay");
    }

    #[test]
    fn the_cursor_never_points_past_a_narrowed_feed() {
        let mut panel = panel();
        panel.on_action(Action::Last);
        panel.on_action(Action::Mnemonic('f'));
        panel.on_action(Action::Mnemonic('f'));

        assert_eq!(panel.cursor, 0, "one row left");
    }

    #[test]
    fn the_panel_is_read_only_so_nothing_it_answers_asks_for_an_effect() {
        let mut panel = panel();

        for action in [
            Action::MoveDown,
            Action::Activate,
            Action::Toggle,
            Action::Mnemonic('f'),
        ] {
            assert_eq!(nav_name(&panel.on_action(action)), "stay", "{action:?}");
        }
    }

    #[test]
    fn an_account_with_no_recorded_history_opens_an_empty_but_working_panel() {
        let mut panel = LogsPanel::new(Vec::new());

        assert!(panel.entries.is_empty());
        assert!(panel.visible.is_empty());
        // The movement keys must not index past the end of an empty feed.
        for action in keys::LIST_MOVEMENT {
            assert_eq!(nav_name(&panel.on_action(action)), "stay", "{action:?}");
            assert_eq!(panel.cursor, 0);
        }
        assert_eq!(nav_name(&panel.on_action(Action::Back)), "pop");
    }

    #[test]
    fn a_filter_that_empties_an_account_with_history_leaves_the_cursor_at_the_top() {
        let attempts = [attempt("a1", "one@acme.example.com", T0, true)];
        let mut panel = LogsPanel::new(event_log(&attempts, &[]));

        // Resumptions only: nothing here is one.
        panel.on_action(Action::Mnemonic('f'));
        panel.on_action(Action::Mnemonic('f'));

        assert!(panel.visible.is_empty());
        assert_eq!(panel.cursor, 0);
        panel.on_action(Action::Last);
        assert_eq!(panel.cursor, 0, "Last on an empty listing is still the top");
    }

    #[test]
    fn a_search_is_matched_without_regard_to_case() {
        let mut panel = panel();
        panel.on_action(Action::Search);
        for c in "BETA".chars() {
            panel.on_action(Action::Type(c));
        }

        assert_eq!(visible_addresses(&panel), ["two@beta.example.org"]);
    }

    #[test]
    fn backspace_widens_the_feed_again_one_character_at_a_time() {
        let mut panel = panel();
        panel.on_action(Action::Search);
        for c in "beta".chars() {
            panel.on_action(Action::Type(c));
        }
        assert_eq!(panel.visible.len(), 1);

        panel.on_action(Action::Erase);
        panel.on_action(Action::Erase);
        panel.on_action(Action::Erase);
        panel.on_action(Action::Erase);

        assert_eq!(panel.filter.search, "");
        assert_eq!(panel.visible.len(), 3, "an empty needle matches everything");
    }

    #[test]
    fn backspace_on_an_empty_needle_does_nothing() {
        let mut panel = panel();
        panel.on_action(Action::Search);

        panel.on_action(Action::Erase);

        assert_eq!(panel.filter.search, "");
        assert_eq!(panel.visible.len(), 3);
    }

    #[test]
    fn the_filter_and_the_needle_narrow_together() {
        let mut panel = panel();
        panel.on_action(Action::Mnemonic('f')); // failures only
        panel.on_action(Action::Search);
        for c in "acme".chars() {
            panel.on_action(Action::Type(c));
        }

        assert_eq!(
            visible_addresses(&panel),
            ["one@acme.example.com"],
            "the resumption, not the failed attempt at beta"
        );
    }

    #[test]
    fn the_feed_is_held_as_indices_so_a_few_thousand_events_still_scroll_and_filter() {
        const N: i64 = 2_000;
        let attempts: Vec<UnsubscribeAttempt> = (0..N)
            .map(|i| {
                attempt(
                    &format!("a{i}"),
                    &format!("s{i:04}@acme.example.com"),
                    T0 + i,
                    i % 2 == 0,
                )
            })
            .collect();
        let mut panel = LogsPanel::new(event_log(&attempts, &[]));

        panel.on_action(Action::Last);
        assert_eq!(panel.cursor, (N - 1) as usize);

        panel.on_action(Action::Mnemonic('f'));
        assert_eq!(panel.visible.len(), (N / 2) as usize);
        assert_eq!(panel.cursor, panel.visible.len() - 1, "pulled into range");

        // Every visible index still points at a row the filter selected.
        assert!(panel
            .visible
            .iter()
            .all(|index| panel.entries[*index].is_failure()));
    }
}
