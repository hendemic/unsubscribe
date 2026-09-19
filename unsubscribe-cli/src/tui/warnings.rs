//! The Warnings screen: the `List-Unsubscribe` headers the last scan could not
//! make sense of.
//!
//! Read-only, and deliberately the same list the `warnings` command prints --
//! both read it from the `DataStore`.

use ratatui::prelude::*;
use ratatui::widgets::*;

use super::app::Nav;
use super::keys::{self, Action};

/// The warning list and where the viewport sits in it.
#[derive(Debug, Clone, Default)]
pub struct WarningsScreen {
    pub warnings: Vec<String>,
    pub cursor: usize,
    scroll_offset: usize,
}

impl WarningsScreen {
    #[must_use]
    pub fn new(warnings: Vec<String>) -> Self {
        Self {
            warnings,
            cursor: 0,
            scroll_offset: 0,
        }
    }

    fn last(&self) -> usize {
        self.warnings.len().saturating_sub(1)
    }

    pub fn on_action(&mut self, action: Action) -> Nav {
        if let Some(cursor) = keys::move_cursor(action, self.cursor, self.last()) {
            self.cursor = cursor;
            return Nav::Stay;
        }
        match action {
            Action::Back => Nav::Pop,
            _ => Nav::Stay,
        }
    }

    /// The actions this panel answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        keys::list_actions(&[])
    }

    /// Keep the cursor inside the viewport. Called at draw time, when the
    /// height is finally known.
    fn scroll_into_view(&mut self, height: usize) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if height > 0 && self.cursor >= self.scroll_offset + height {
            self.scroll_offset = self.cursor - height + 1;
        }
    }
}

pub(crate) fn render(f: &mut Frame, area: Rect, screen: &mut WarningsScreen) {
    if screen.warnings.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(
                    " No warnings from the last scan.",
                    Style::default().fg(Color::Green),
                ),
                Line::styled(
                    " Every List-Unsubscribe header parsed cleanly.",
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            area,
        );
        return;
    }

    // The working area already draws the border and the title, so the rows
    // fill it edge to edge and the count goes on a line of its own.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);
    f.render_widget(
        Paragraph::new(Line::styled(
            format!(" {} unparseable header(s)", screen.warnings.len()),
            Style::default().fg(Color::DarkGray),
        )),
        chunks[0],
    );

    let area = chunks[1];
    let height = area.height as usize;
    screen.scroll_into_view(height);

    let rows: Vec<Line> = screen
        .warnings
        .iter()
        .enumerate()
        .skip(screen.scroll_offset)
        .take(height)
        .map(|(index, warning)| {
            let style = if index == screen.cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::Yellow)
            };
            Line::styled(format!(" {warning}"), style)
        })
        .collect();

    f.render_widget(Paragraph::new(rows), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_pop(nav: &Nav) -> bool {
        matches!(nav, Nav::Pop)
    }

    fn screen(count: usize) -> WarningsScreen {
        WarningsScreen::new((0..count).map(|i| format!("warning {i}")).collect())
    }

    #[test]
    fn the_cursor_starts_at_the_top() {
        assert_eq!(screen(30).cursor, 0);
    }

    #[test]
    fn moving_down_stops_on_the_last_warning() {
        let mut s = screen(3);

        for _ in 0..10 {
            s.on_action(Action::MoveDown);
        }

        assert_eq!(s.cursor, 2);
    }

    #[test]
    fn moving_up_stops_at_the_top() {
        let mut s = screen(3);
        s.on_action(Action::Last);

        for _ in 0..10 {
            s.on_action(Action::MoveUp);
        }

        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn a_page_moves_ten_rows_and_clamps_at_the_ends() {
        let mut s = screen(30);

        s.on_action(Action::PageDown);
        assert_eq!(s.cursor, 10);
        s.on_action(Action::PageDown);
        assert_eq!(s.cursor, 20);
        s.on_action(Action::PageDown);
        assert_eq!(s.cursor, 29, "the last row, not row 30");
        s.on_action(Action::PageUp);
        assert_eq!(s.cursor, 19);
    }

    #[test]
    fn g_and_shift_g_jump_to_the_first_and_last_warning() {
        let mut s = screen(30);

        s.on_action(Action::Last);
        assert_eq!(s.cursor, 29);
        s.on_action(Action::First);
        assert_eq!(s.cursor, 0);
        s.on_action(Action::Last);
        assert_eq!(s.cursor, 29);
        s.on_action(Action::First);
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn esc_goes_back_one_level_and_q_is_never_back() {
        assert!(is_pop(&screen(3).on_action(Action::Back)));
        assert!(!is_pop(&screen(3).on_action(Action::Quit)));
    }

    #[test]
    fn navigating_an_empty_list_does_not_panic_or_move() {
        let mut s = screen(0);

        for action in [
            Action::MoveDown,
            Action::MoveUp,
            Action::PageDown,
            Action::PageUp,
            Action::Last,
            Action::First,
        ] {
            s.on_action(action);
            assert_eq!(s.cursor, 0);
        }
    }

    #[test]
    fn an_action_this_panel_does_not_answer_changes_nothing() {
        let mut s = screen(3);
        s.on_action(Action::MoveDown);

        s.on_action(Action::Toggle);

        assert_eq!(s.cursor, 1);
    }
}
