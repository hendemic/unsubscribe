use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io;

use unsubscribe_core::SenderInfo;

/// Guard that restores the terminal on drop, even if we panic or return early
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// State for the TUI selection screen
struct App {
    senders: Vec<SenderInfo>,
    /// true = will unsubscribe, false = keep
    selected: Vec<bool>,
    cursor: usize,
    scroll_offset: usize,
    confirmed: bool,
    cancelled: bool,
}

impl App {
    fn new(senders: Vec<SenderInfo>) -> Self {
        let len = senders.len();
        Self {
            senders,
            selected: vec![false; len],
            cursor: 0,
            scroll_offset: 0,
            confirmed: false,
            cancelled: false,
        }
    }

    fn toggle(&mut self) {
        if self.cursor == 0 {
            // "Select All" row: if any are unselected, select all; otherwise deselect all
            if self.selected.iter().all(|&s| s) {
                self.selected.fill(false);
            } else {
                self.selected.fill(true);
            }
        } else if !self.senders.is_empty() {
            let idx = self.cursor - 1;
            self.selected[idx] = !self.selected[idx];
        }
    }

    fn select_all(&mut self) {
        self.selected.fill(true);
    }

    fn deselect_all(&mut self) {
        self.selected.fill(false);
    }

    fn move_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    fn move_down(&mut self) {
        // total rows = senders.len() + 1 (for "Select All" row)
        if self.cursor + 1 < self.senders.len() + 1 {
            self.cursor += 1;
        }
    }

    fn count_selected(&self) -> usize {
        self.selected.iter().filter(|&&s| s).count()
    }

    fn total_emails_selected(&self) -> u32 {
        self.senders
            .iter()
            .zip(self.selected.iter())
            .filter(|(_, sel)| **sel)
            .map(|(s, _)| s.email_count)
            .sum()
    }
}

/// Run the TUI selection screen. Returns the senders with their selection state.
/// Selected = true means the user wants to unsubscribe from that sender.
pub fn select_senders(senders: Vec<SenderInfo>) -> anyhow::Result<Option<Vec<(SenderInfo, bool)>>> {
    enable_raw_mode()?;
    let _guard = TerminalGuard; // restores terminal on drop, even on error/panic
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(senders);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.cancelled = true;
                    break;
                }
                KeyCode::Enter => {
                    app.confirmed = true;
                    break;
                }
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') => app.toggle(),
                KeyCode::Char('a') => app.select_all(),
                KeyCode::Char('n') => app.deselect_all(),
                KeyCode::Home | KeyCode::Char('g') => app.cursor = 0,
                KeyCode::End | KeyCode::Char('G') => {
                    // last row index = senders.len() (row 0 is Select All)
                    app.cursor = app.senders.len();
                }
                _ => {}
            }
        }
    }

    // Guard handles cleanup, but we explicitly drop here so terminal
    // is restored before we return results to the caller
    drop(_guard);

    if app.cancelled {
        return Ok(None);
    }

    let result: Vec<(SenderInfo, bool)> = app
        .senders
        .into_iter()
        .zip(app.selected)
        .collect();

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsubscribe_core::SenderInfo;

    /// Builds a minimal SenderInfo for TUI state tests.
    fn make_sender(email: &str, email_count: u32) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: vec![],
            unsubscribe_mailto: vec![],
            one_click: false,
            email_count,
            messages: vec![],
        }
    }

    fn three_senders() -> Vec<SenderInfo> {
        vec![
            make_sender("a@test.com", 10),
            make_sender("b@test.com", 20),
            make_sender("c@test.com", 5),
        ]
    }

    // -------------------------------------------------------------------
    // Cursor movement
    // -------------------------------------------------------------------

    #[test]
    fn move_up_stops_at_zero() {
        let mut app = App::new(three_senders());
        assert_eq!(app.cursor, 0);
        app.move_up();
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn move_down_stops_at_last_row() {
        let mut app = App::new(three_senders());
        // Total rows = 3 senders + 1 Select All = 4 rows (indices 0..3)
        app.move_down(); // 1
        app.move_down(); // 2
        app.move_down(); // 3
        assert_eq!(app.cursor, 3);
        app.move_down(); // should stay at 3
        assert_eq!(app.cursor, 3);
    }

    #[test]
    fn move_up_and_down_traverse_all_rows() {
        let mut app = App::new(three_senders());
        for i in 0..3 {
            assert_eq!(app.cursor, i);
            app.move_down();
        }
        assert_eq!(app.cursor, 3);
        for i in (0..3).rev() {
            app.move_up();
            assert_eq!(app.cursor, i);
        }
    }

    // -------------------------------------------------------------------
    // Toggle
    // -------------------------------------------------------------------

    #[test]
    fn toggle_on_row_zero_selects_all_when_any_unselected() {
        let mut app = App::new(three_senders());
        assert_eq!(app.cursor, 0);
        // All start unselected, toggling row 0 should select all
        app.toggle();
        assert!(app.selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_row_zero_deselects_all_when_all_selected() {
        let mut app = App::new(three_senders());
        app.select_all();
        assert_eq!(app.cursor, 0);
        app.toggle();
        assert!(app.selected.iter().all(|&s| !s));
    }

    #[test]
    fn toggle_on_row_zero_selects_all_when_partially_selected() {
        let mut app = App::new(three_senders());
        app.selected[0] = true; // only first selected
        assert_eq!(app.cursor, 0);
        app.toggle();
        assert!(app.selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_sender_row_toggles_individual() {
        let mut app = App::new(three_senders());
        app.cursor = 1; // first sender
        assert!(!app.selected[0]);
        app.toggle();
        assert!(app.selected[0]);
        assert!(!app.selected[1]);
        assert!(!app.selected[2]);
        app.toggle();
        assert!(!app.selected[0]);
    }

    // -------------------------------------------------------------------
    // Select all / deselect all
    // -------------------------------------------------------------------

    #[test]
    fn select_all_sets_all_flags() {
        let mut app = App::new(three_senders());
        app.select_all();
        assert!(app.selected.iter().all(|&s| s));
    }

    #[test]
    fn deselect_all_clears_all_flags() {
        let mut app = App::new(three_senders());
        app.select_all();
        app.deselect_all();
        assert!(app.selected.iter().all(|&s| !s));
    }

    // -------------------------------------------------------------------
    // Counting
    // -------------------------------------------------------------------

    #[test]
    fn count_selected_correct() {
        let mut app = App::new(three_senders());
        assert_eq!(app.count_selected(), 0);
        app.selected[0] = true;
        app.selected[2] = true;
        assert_eq!(app.count_selected(), 2);
    }

    #[test]
    fn total_emails_selected_sums_only_selected() {
        let mut app = App::new(three_senders());
        // a=10, b=20, c=5
        app.selected[1] = true; // b=20
        app.selected[2] = true; // c=5
        assert_eq!(app.total_emails_selected(), 25);
    }

    #[test]
    fn total_emails_selected_none_selected_is_zero() {
        let app = App::new(three_senders());
        assert_eq!(app.total_emails_selected(), 0);
    }

    // -------------------------------------------------------------------
    // Empty senders list
    // -------------------------------------------------------------------

    #[test]
    fn empty_senders_no_panic() {
        let mut app = App::new(vec![]);
        assert_eq!(app.cursor, 0);
        assert_eq!(app.count_selected(), 0);
        assert_eq!(app.total_emails_selected(), 0);

        // Movement should not panic
        app.move_up();
        app.move_down();
        assert_eq!(app.cursor, 0);

        // Toggle on row 0 with empty selected vec should not panic
        app.toggle();
        app.select_all();
        app.deselect_all();
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(5),   // list
            Constraint::Length(3), // status bar
            Constraint::Length(2), // help
        ])
        .split(area);

    // Title
    let title = Paragraph::new("Email Unsubscriber")
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Scrollable list
    let visible_height = chunks[1].height as usize;
    let total_rows = app.senders.len() + 1; // +1 for "Select All" row

    // Adjust scroll to keep cursor visible
    if app.cursor < app.scroll_offset {
        app.scroll_offset = app.cursor;
    } else if app.cursor >= app.scroll_offset + visible_height {
        app.scroll_offset = app.cursor - visible_height + 1;
    }

    // Build visible rows: row 0 = "Select All", rows 1..=senders.len() = actual senders
    let mut items: Vec<Line> = Vec::new();
    for row in app.scroll_offset..total_rows.min(app.scroll_offset + visible_height) {
        if row == 0 {
            // "Select All" row
            let all_selected = !app.selected.is_empty() && app.selected.iter().all(|&s| s);
            let checkbox = if all_selected { "[x]" } else { "[ ]" };
            let text = format!(" {checkbox} Select All");
            let is_cursor = app.cursor == 0;
            let style = if is_cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::Cyan)
            };
            items.push(Line::styled(text, style));
        } else {
            // Sender row: sender index = row - 1
            let idx = row - 1;
            let sender = &app.senders[idx];
            let selected = app.selected[idx];
            let checkbox = if selected { "[x]" } else { "[ ]" };
            let is_cursor = row == app.cursor;
            let name = if sender.display_name.is_empty() {
                &sender.email
            } else {
                &sender.display_name
            };

            let method = if sender.one_click {
                "1-click"
            } else if !sender.unsubscribe_urls.is_empty() {
                "http"
            } else {
                "mailto"
            };

            let text = format!(
                " {checkbox} {name:<40} ({:<30}) [{method:>7}] ({} emails)",
                sender.email, sender.email_count
            );

            let style = if is_cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if selected {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };

            items.push(Line::styled(text, style));
        }
    }

    let list = Paragraph::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Senders (checked = unsubscribe) "),
    );
    f.render_widget(list, chunks[1]);

    // Status bar
    let status = Paragraph::new(format!(
        " {} of {} senders selected for unsubscribe ({} emails)",
        app.count_selected(),
        app.senders.len(),
        app.total_emails_selected(),
    ))
    .style(Style::default().fg(Color::Yellow))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[2]);

    // Help line
    let help = Paragraph::new(
        " Space: toggle | a: select all | n: deselect all | j/k: move | Enter: confirm | q: quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, chunks[3]);
}
