//! The Warnings screen: the `List-Unsubscribe` headers the last scan could not
//! make sense of.
//!
//! Read-only, and deliberately the same list the `warnings` command prints --
//! both read it from the `DataStore`.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;

use super::app::Nav;

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

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.cursor = (self.cursor + 1).min(self.last()),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::PageDown => self.cursor = (self.cursor + 10).min(self.last()),
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = self.last(),
            KeyCode::Esc | KeyCode::Char('q') => return Nav::Pop,
            _ => {}
        }
        Nav::Stay
    }

    pub fn hints(&self) -> &'static str {
        " j/k: move | ?: keys | Esc: back"
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("j / k / \u{2191}\u{2193}", "scroll"),
            ("PgUp / PgDn", "scroll a page"),
            ("g / G", "first / last"),
            ("Esc / q", "back"),
        ]
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
                    "  No warnings from the last scan.",
                    Style::default().fg(Color::Green),
                ),
                Line::styled(
                    "  Every List-Unsubscribe header parsed cleanly.",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .block(Block::default().borders(Borders::ALL).title(" Warnings ")),
            area,
        );
        return;
    }

    let height = (area.height as usize).saturating_sub(2);
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

    f.render_widget(
        Paragraph::new(rows).block(
            Block::default().borders(Borders::ALL).title(format!(
                " Warnings \u{2014} {} unparseable header(s) ",
                screen.warnings.len()
            )),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

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
            s.on_key(key(KeyCode::Down));
        }

        assert_eq!(s.cursor, 2);
    }

    #[test]
    fn moving_up_stops_at_the_top() {
        let mut s = screen(3);
        s.on_key(key(KeyCode::Char('G')));

        for _ in 0..10 {
            s.on_key(key(KeyCode::Char('k')));
        }

        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn a_page_moves_ten_rows_and_clamps_at_the_ends() {
        let mut s = screen(30);

        s.on_key(key(KeyCode::PageDown));
        assert_eq!(s.cursor, 10);
        s.on_key(key(KeyCode::PageDown));
        assert_eq!(s.cursor, 20);
        s.on_key(key(KeyCode::PageDown));
        assert_eq!(s.cursor, 29, "the last row, not row 30");
        s.on_key(key(KeyCode::PageUp));
        assert_eq!(s.cursor, 19);
    }

    #[test]
    fn g_and_shift_g_jump_to_the_first_and_last_warning() {
        let mut s = screen(30);

        s.on_key(key(KeyCode::End));
        assert_eq!(s.cursor, 29);
        s.on_key(key(KeyCode::Home));
        assert_eq!(s.cursor, 0);
        s.on_key(key(KeyCode::Char('G')));
        assert_eq!(s.cursor, 29);
        s.on_key(key(KeyCode::Char('g')));
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn esc_and_q_go_back_to_the_screen_underneath() {
        assert!(is_pop(&screen(3).on_key(key(KeyCode::Esc))));
        assert!(is_pop(&screen(3).on_key(key(KeyCode::Char('q')))));
    }

    #[test]
    fn navigating_an_empty_list_does_not_panic_or_move() {
        let mut s = screen(0);

        for code in [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::PageDown,
            KeyCode::PageUp,
            KeyCode::Char('G'),
            KeyCode::Char('g'),
        ] {
            s.on_key(key(code));
            assert_eq!(s.cursor, 0);
        }
    }

    #[test]
    fn an_unrecognised_key_changes_nothing() {
        let mut s = screen(3);
        s.on_key(key(KeyCode::Down));

        s.on_key(key(KeyCode::Char('z')));

        assert_eq!(s.cursor, 1);
    }
}
