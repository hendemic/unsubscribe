use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use unsubscribe_core::SenderInfo;

/// A sender is considered stale if their last message is older than 12 months.
const STALE_THRESHOLD_SECS: i64 = 365 * 24 * 60 * 60;

fn is_stale(sender: &SenderInfo) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match sender.last_seen {
        Some(ts) => now - ts > STALE_THRESHOLD_SECS,
        None => false,
    }
}

/// Guard that restores the terminal on drop, even if we panic or return early
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// State for the TUI selection screen.
///
/// Senders are split into two sections: active senders (any) followed by stale
/// senders (last message >12 months ago). A section header row separates them
/// when both sections are non-empty.
///
/// Row layout (0-indexed):
///   0              — "Select All" row
///   1..=n_active   — active sender rows
///   n_active+1     — stale section header (only when n_stale > 0)
///   n_active+2..   — stale sender rows
struct App {
    /// Active senders (last_seen within 12 months, or unknown).
    active: Vec<SenderInfo>,
    /// Stale senders (last_seen older than 12 months).
    stale: Vec<SenderInfo>,
    /// Selection state for active senders (parallel to `active`).
    active_selected: Vec<bool>,
    /// Selection state for stale senders (parallel to `stale`). Defaults to false.
    stale_selected: Vec<bool>,
    cursor: usize,
    scroll_offset: usize,
    cancelled: bool,
}

impl App {
    fn new(senders: Vec<SenderInfo>) -> Self {
        let mut active = Vec::new();
        let mut stale = Vec::new();
        for s in senders {
            if is_stale(&s) {
                stale.push(s);
            } else {
                active.push(s);
            }
        }
        let n_active = active.len();
        let n_stale = stale.len();
        Self {
            active,
            stale,
            active_selected: vec![false; n_active],
            stale_selected: vec![false; n_stale],
            cursor: 0,
            scroll_offset: 0,
            cancelled: false,
        }
    }

    /// Total number of senders across both sections.
    fn total_senders(&self) -> usize {
        self.active.len() + self.stale.len()
    }

    /// Total navigable rows: "Select All" + active senders + stale header (if any) + stale senders.
    fn total_rows(&self) -> usize {
        let header = if self.stale.is_empty() { 0 } else { 1 };
        1 + self.active.len() + header + self.stale.len()
    }

    /// Resolve a visible row index into what it represents.
    fn row_kind(&self, row: usize) -> RowKind {
        if row == 0 {
            return RowKind::SelectAll;
        }
        let idx = row - 1;
        if idx < self.active.len() {
            return RowKind::Active(idx);
        }
        let after_active = idx - self.active.len();
        if !self.stale.is_empty() {
            if after_active == 0 {
                return RowKind::StaleHeader;
            }
            let stale_idx = after_active - 1;
            if stale_idx < self.stale.len() {
                return RowKind::Stale(stale_idx);
            }
        }
        RowKind::SelectAll // fallback, shouldn't happen
    }

    fn toggle(&mut self) {
        match self.row_kind(self.cursor) {
            RowKind::SelectAll => {
                // Toggle all: if everything is selected, deselect; otherwise select all
                let all_sel = self.active_selected.iter().all(|&s| s)
                    && self.stale_selected.iter().all(|&s| s);
                self.active_selected.fill(!all_sel);
                self.stale_selected.fill(!all_sel);
            }
            RowKind::Active(idx) => self.active_selected[idx] = !self.active_selected[idx],
            RowKind::Stale(idx) => self.stale_selected[idx] = !self.stale_selected[idx],
            RowKind::StaleHeader => {} // section header is not selectable
        }
    }

    fn select_all(&mut self) {
        self.active_selected.fill(true);
        self.stale_selected.fill(true);
    }

    fn deselect_all(&mut self) {
        self.active_selected.fill(false);
        self.stale_selected.fill(false);
    }

    fn move_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            // Skip over the stale section header (not selectable)
            if matches!(self.row_kind(self.cursor), RowKind::StaleHeader) && self.cursor > 0 {
                self.cursor -= 1;
            }
        }
    }

    fn move_down(&mut self) {
        let max = self.total_rows().saturating_sub(1);
        if self.cursor < max {
            self.cursor += 1;
            // Skip over the stale section header (not selectable)
            if matches!(self.row_kind(self.cursor), RowKind::StaleHeader) {
                if self.cursor < max {
                    self.cursor += 1;
                } else {
                    self.cursor -= 1;
                }
            }
        }
    }

    fn count_selected(&self) -> usize {
        self.active_selected.iter().filter(|&&s| s).count()
            + self.stale_selected.iter().filter(|&&s| s).count()
    }

    fn total_emails_selected(&self) -> u32 {
        let active: u32 = self.active.iter()
            .zip(self.active_selected.iter())
            .filter(|(_, sel)| **sel)
            .map(|(s, _)| s.email_count)
            .sum();
        let stale: u32 = self.stale.iter()
            .zip(self.stale_selected.iter())
            .filter(|(_, sel)| **sel)
            .map(|(s, _)| s.email_count)
            .sum();
        active + stale
    }

    /// Consume the app and produce `(sender, selected, is_stale)` for each sender.
    fn into_results(self) -> Vec<(SenderInfo, bool)> {
        let active = self.active.into_iter().zip(self.active_selected);
        let stale = self.stale.into_iter().zip(self.stale_selected);
        active.chain(stale).collect()
    }
}

#[derive(Debug, PartialEq)]
enum RowKind {
    SelectAll,
    Active(usize),
    StaleHeader,
    Stale(usize),
}

/// Run the TUI selection screen. Returns the senders with their selection state.
/// Selected = true means the user wants to unsubscribe (or archive-only for stale senders).
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
                    break;
                }
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') => app.toggle(),
                KeyCode::Char('a') => app.select_all(),
                KeyCode::Char('n') => app.deselect_all(),
                KeyCode::Home | KeyCode::Char('g') => app.cursor = 0,
                KeyCode::End | KeyCode::Char('G') => {
                    app.cursor = app.total_rows().saturating_sub(1);
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

    Ok(Some(app.into_results()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use unsubscribe_core::SenderInfo;

    /// Builds a minimal active (non-stale) SenderInfo.
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
            last_seen: None,
        }
    }

    /// Builds a stale SenderInfo (last_seen = 2 years ago).
    fn make_stale_sender(email: &str, email_count: u32) -> SenderInfo {
        let two_years_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 - 2 * 365 * 24 * 3600)
            .unwrap_or(0);
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: vec![],
            unsubscribe_mailto: vec![],
            one_click: false,
            email_count,
            messages: vec![],
            last_seen: Some(two_years_ago),
        }
    }

    fn three_active_senders() -> Vec<SenderInfo> {
        vec![
            make_sender("a@test.com", 10),
            make_sender("b@test.com", 20),
            make_sender("c@test.com", 5),
        ]
    }

    // -------------------------------------------------------------------
    // Cursor movement (active-only list)
    // -------------------------------------------------------------------

    #[test]
    fn move_up_stops_at_zero() {
        let mut app = App::new(three_active_senders());
        assert_eq!(app.cursor, 0);
        app.move_up();
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn move_down_stops_at_last_row() {
        let mut app = App::new(three_active_senders());
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
        let mut app = App::new(three_active_senders());
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
    // Toggle (active-only list)
    // -------------------------------------------------------------------

    #[test]
    fn toggle_on_row_zero_selects_all_when_any_unselected() {
        let mut app = App::new(three_active_senders());
        assert_eq!(app.cursor, 0);
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_row_zero_deselects_all_when_all_selected() {
        let mut app = App::new(three_active_senders());
        app.select_all();
        assert_eq!(app.cursor, 0);
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    #[test]
    fn toggle_on_row_zero_selects_all_when_partially_selected() {
        let mut app = App::new(three_active_senders());
        app.active_selected[0] = true;
        assert_eq!(app.cursor, 0);
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_sender_row_toggles_individual() {
        let mut app = App::new(three_active_senders());
        app.cursor = 1; // first active sender
        assert!(!app.active_selected[0]);
        app.toggle();
        assert!(app.active_selected[0]);
        assert!(!app.active_selected[1]);
        assert!(!app.active_selected[2]);
        app.toggle();
        assert!(!app.active_selected[0]);
    }

    // -------------------------------------------------------------------
    // Select all / deselect all
    // -------------------------------------------------------------------

    #[test]
    fn select_all_sets_all_flags() {
        let mut app = App::new(three_active_senders());
        app.select_all();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn deselect_all_clears_all_flags() {
        let mut app = App::new(three_active_senders());
        app.select_all();
        app.deselect_all();
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    // -------------------------------------------------------------------
    // Counting
    // -------------------------------------------------------------------

    #[test]
    fn count_selected_correct() {
        let mut app = App::new(three_active_senders());
        assert_eq!(app.count_selected(), 0);
        app.active_selected[0] = true;
        app.active_selected[2] = true;
        assert_eq!(app.count_selected(), 2);
    }

    #[test]
    fn total_emails_selected_sums_only_selected() {
        let mut app = App::new(three_active_senders());
        // a=10, b=20, c=5
        app.active_selected[1] = true; // b=20
        app.active_selected[2] = true; // c=5
        assert_eq!(app.total_emails_selected(), 25);
    }

    #[test]
    fn total_emails_selected_none_selected_is_zero() {
        let app = App::new(three_active_senders());
        assert_eq!(app.total_emails_selected(), 0);
    }

    // -------------------------------------------------------------------
    // Stale sender handling
    // -------------------------------------------------------------------

    #[test]
    fn stale_senders_start_deselected() {
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let app = App::new(senders);
        assert_eq!(app.active.len(), 1);
        assert_eq!(app.stale.len(), 1);
        assert!(!app.stale_selected[0]);
    }

    #[test]
    fn stale_senders_go_to_stale_section() {
        let senders = vec![
            make_stale_sender("old@test.com", 2),
            make_sender("new@test.com", 5),
        ];
        let app = App::new(senders);
        assert_eq!(app.active.len(), 1);
        assert_eq!(app.stale.len(), 1);
        assert_eq!(app.active[0].email, "new@test.com");
        assert_eq!(app.stale[0].email, "old@test.com");
    }

    #[test]
    fn stale_header_row_is_skipped_by_navigation() {
        // With 1 active + 1 stale, rows are: SelectAll(0), Active(1), StaleHeader(2), Stale(3)
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        // Navigate down past SelectAll, Active, then past StaleHeader (should skip it)
        app.move_down(); // cursor=1 (active)
        app.move_down(); // cursor should skip header to 3 (stale)
        assert_eq!(app.cursor, 3, "stale header at row 2 should be skipped");
        assert!(matches!(app.row_kind(app.cursor), RowKind::Stale(0)));
    }

    #[test]
    fn stale_header_row_is_skipped_when_navigating_up() {
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        // Get to stale row
        app.move_down(); // 1
        app.move_down(); // 3 (skipped header at 2)
        assert_eq!(app.cursor, 3);
        // Navigate up — should skip the header again
        app.move_up(); // should skip header to 1 (active)
        assert_eq!(app.cursor, 1, "stale header should be skipped when moving up");
    }

    #[test]
    fn into_results_preserves_all_senders() {
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        app.active_selected[0] = true;
        let results = app.into_results();
        assert_eq!(results.len(), 2);
        let (active_sender, active_sel) = &results[0];
        assert_eq!(active_sender.email, "active@test.com");
        assert!(active_sel);
        let (stale_sender, stale_sel) = &results[1];
        assert_eq!(stale_sender.email, "stale@test.com");
        assert!(!stale_sel);
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

        // Toggle on row 0 with empty active/stale vecs should not panic
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
    let total_rows = app.total_rows();

    // Adjust scroll to keep cursor visible
    if app.cursor < app.scroll_offset {
        app.scroll_offset = app.cursor;
    } else if app.cursor >= app.scroll_offset + visible_height {
        app.scroll_offset = app.cursor - visible_height + 1;
    }

    let mut items: Vec<Line> = Vec::new();
    for row in app.scroll_offset..total_rows.min(app.scroll_offset + visible_height) {
        let is_cursor = row == app.cursor;

        match app.row_kind(row) {
            RowKind::SelectAll => {
                let all_selected = app.active_selected.iter().all(|&s| s)
                    && app.stale_selected.iter().all(|&s| s)
                    && !app.active_selected.is_empty();
                let checkbox = if all_selected { "[x]" } else { "[ ]" };
                let text = format!(" {checkbox} Select All");
                let style = if is_cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                items.push(Line::styled(text, style));
            }
            RowKind::Active(idx) => {
                let sender = &app.active[idx];
                let selected = app.active_selected[idx];
                items.push(sender_row(sender, selected, is_cursor));
            }
            RowKind::StaleHeader => {
                let text = " ── Stale senders (archive only — unsubscribe URLs may be expired) ──";
                items.push(Line::styled(text, Style::default().fg(Color::DarkGray)));
            }
            RowKind::Stale(idx) => {
                let sender = &app.stale[idx];
                let selected = app.stale_selected[idx];
                items.push(stale_sender_row(sender, selected, is_cursor));
            }
        }
    }

    let title_str = if app.stale.is_empty() {
        " Senders (checked = unsubscribe) "
    } else {
        " Senders (checked = unsubscribe / archive-only for stale) "
    };

    let list = Paragraph::new(items).block(
        Block::default().borders(Borders::ALL).title(title_str),
    );
    f.render_widget(list, chunks[1]);

    // Status bar
    let status = Paragraph::new(format!(
        " {} of {} senders selected ({} emails)",
        app.count_selected(),
        app.total_senders(),
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

fn sender_row(sender: &SenderInfo, selected: bool, is_cursor: bool) -> Line<'static> {
    let checkbox = if selected { "[x]" } else { "[ ]" };
    let name = if sender.display_name.is_empty() {
        sender.email.clone()
    } else {
        sender.display_name.clone()
    };
    let method = if sender.one_click {
        "1-click"
    } else if !sender.unsubscribe_urls.is_empty() {
        "http"
    } else {
        "mailto"
    };
    let name_trunc = truncate_str(&name, 40);
    let email_trunc = truncate_str(&sender.email, 30);
    let text = format!(
        " {checkbox} {name_trunc:<40} ({email_trunc:<30}) [{method:>7}] ({} emails)",
        sender.email_count,
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if selected {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };
    Line::styled(text, style)
}

fn stale_sender_row(sender: &SenderInfo, selected: bool, is_cursor: bool) -> Line<'static> {
    let checkbox = if selected { "[x]" } else { "[ ]" };
    let name = if sender.display_name.is_empty() {
        sender.email.clone()
    } else {
        sender.display_name.clone()
    };
    let name_trunc = truncate_str(&name, 40);
    let email_trunc = truncate_str(&sender.email, 30);
    let text = format!(
        " {checkbox} {name_trunc:<40} ({email_trunc:<30}) [archive ] ({} emails)",
        sender.email_count,
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if selected {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Line::styled(text, style)
}

fn truncate_str(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}
