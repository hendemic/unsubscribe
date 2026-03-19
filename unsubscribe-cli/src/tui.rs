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
/// Senders are split into two sections: active senders followed by stale
/// senders (last message >12 months ago). Each section has its own select-all
/// toggle row.
///
/// Row layout (0-indexed):
///   0              — "Select All Active" row
///   1..=n_active   — active sender rows
///   n_active+1     — "Select All Stale" row (only when n_stale > 0)
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
    /// Optional scan timestamp (ISO 8601) for display.
    scan_timestamp: Option<String>,
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
            cursor: 1, // start on SelectAllActive, skip the header
            scroll_offset: 0,
            cancelled: false,
            scan_timestamp: None,
        }
    }

    /// Total number of senders across both sections.
    fn total_senders(&self) -> usize {
        self.active.len() + self.stale.len()
    }

    /// Total rows including section headers and spacer:
    ///   ActiveHeader + SelectAllActive + active senders
    ///   + Spacer + StaleHeader + SelectAllStale + stale senders (if any)
    fn total_rows(&self) -> usize {
        let active_section = 2 + self.active.len(); // header + select-all + senders
        // spacer + header + select-all + senders
        let stale_section = if self.stale.is_empty() { 0 } else { 3 + self.stale.len() };
        active_section + stale_section
    }

    /// Resolve a visible row index into what it represents.
    fn row_kind(&self, row: usize) -> RowKind {
        if row == 0 {
            return RowKind::ActiveHeader;
        }
        if row == 1 {
            return RowKind::SelectAllActive;
        }
        let idx = row - 2;
        if idx < self.active.len() {
            return RowKind::Active(idx);
        }
        let after_active = idx - self.active.len();
        if !self.stale.is_empty() {
            if after_active == 0 {
                return RowKind::Spacer;
            }
            if after_active == 1 {
                return RowKind::StaleHeader;
            }
            if after_active == 2 {
                return RowKind::SelectAllStale;
            }
            let stale_idx = after_active - 3;
            if stale_idx < self.stale.len() {
                return RowKind::Stale(stale_idx);
            }
        }
        RowKind::ActiveHeader // fallback
    }

    fn toggle(&mut self) {
        match self.row_kind(self.cursor) {
            RowKind::SelectAllActive => {
                let all_sel = self.active_selected.iter().all(|&s| s)
                    && !self.active_selected.is_empty();
                self.active_selected.fill(!all_sel);
            }
            RowKind::SelectAllStale => {
                let all_sel = self.stale_selected.iter().all(|&s| s)
                    && !self.stale_selected.is_empty();
                self.stale_selected.fill(!all_sel);
            }
            RowKind::Active(idx) => self.active_selected[idx] = !self.active_selected[idx],
            RowKind::Stale(idx) => self.stale_selected[idx] = !self.stale_selected[idx],
            RowKind::ActiveHeader | RowKind::StaleHeader | RowKind::Spacer => {}
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

    fn is_non_selectable(&self, row: usize) -> bool {
        matches!(self.row_kind(row), RowKind::ActiveHeader | RowKind::StaleHeader | RowKind::Spacer)
    }

    fn move_up(&mut self) {
        if self.cursor > 1 {
            self.cursor -= 1;
            while self.is_non_selectable(self.cursor) && self.cursor > 1 {
                self.cursor -= 1;
            }
        }
    }

    fn move_down(&mut self) {
        let max = self.total_rows().saturating_sub(1);
        if self.cursor < max {
            self.cursor += 1;
            while self.is_non_selectable(self.cursor) && self.cursor < max {
                self.cursor += 1;
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
    ActiveHeader,
    SelectAllActive,
    Active(usize),
    Spacer,
    StaleHeader,
    SelectAllStale,
    Stale(usize),
}

/// Run the TUI selection screen. Returns the senders with their selection state.
/// Selected = true means the user wants to unsubscribe (or archive-only for stale senders).
pub fn select_senders(
    senders: Vec<SenderInfo>,
    scan_timestamp: Option<&str>,
) -> anyhow::Result<Option<Vec<(SenderInfo, bool)>>> {
    enable_raw_mode()?;
    let _guard = TerminalGuard; // restores terminal on drop, even on error/panic
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(senders);
    app.scan_timestamp = scan_timestamp.map(String::from);

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
                KeyCode::Home | KeyCode::Char('g') => app.cursor = 1, // SelectAllActive
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
    fn cursor_starts_on_select_all_active() {
        let app = App::new(three_active_senders());
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(1), RowKind::SelectAllActive));
    }

    #[test]
    fn move_up_stops_at_select_all_active() {
        let mut app = App::new(three_active_senders());
        app.move_up();
        assert_eq!(app.cursor, 1, "should not move above SelectAllActive");
    }

    #[test]
    fn move_down_stops_at_last_row() {
        let mut app = App::new(three_active_senders());
        // Rows: ActiveHeader(0), SelectAllActive(1), Active(2,3,4) = 5 rows
        for _ in 0..10 {
            app.move_down();
        }
        assert_eq!(app.cursor, 4);
    }

    #[test]
    fn move_up_and_down_traverse_selectable_rows() {
        let mut app = App::new(three_active_senders());
        // Start at 1 (SelectAllActive), down to 2, 3, 4
        let mut visited = vec![app.cursor];
        for _ in 0..3 {
            app.move_down();
            visited.push(app.cursor);
        }
        assert_eq!(visited, vec![1, 2, 3, 4]);
    }

    // -------------------------------------------------------------------
    // Toggle (active-only list)
    // -------------------------------------------------------------------

    #[test]
    fn toggle_select_all_active_selects_when_any_unselected() {
        let mut app = App::new(three_active_senders());
        // cursor starts at 1 (SelectAllActive)
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_select_all_active_deselects_when_all_selected() {
        let mut app = App::new(three_active_senders());
        app.active_selected.fill(true);
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    #[test]
    fn toggle_select_all_active_selects_when_partially_selected() {
        let mut app = App::new(three_active_senders());
        app.active_selected[0] = true;
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_sender_row_toggles_individual() {
        let mut app = App::new(three_active_senders());
        app.cursor = 2; // first active sender (row 2)
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
    fn select_all_stale_row_is_navigable() {
        // With 1 active + 1 stale, rows are:
        //   ActiveHeader(0), SelectAllActive(1), Active(2),
        //   Spacer(3), StaleHeader(4), SelectAllStale(5), Stale(6)
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        app.move_down(); // 2 (active sender)
        app.move_down(); // 5 (select all stale — skips Spacer+StaleHeader)
        assert_eq!(app.cursor, 5);
        assert!(matches!(app.row_kind(app.cursor), RowKind::SelectAllStale));
        app.move_down(); // 6 (stale sender)
        assert_eq!(app.cursor, 6);
        assert!(matches!(app.row_kind(app.cursor), RowKind::Stale(0)));
    }

    #[test]
    fn toggle_select_all_stale_toggles_only_stale() {
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        app.cursor = 5; // SelectAllStale
        app.toggle();
        assert!(app.stale_selected[0], "stale sender should be selected");
        assert!(!app.active_selected[0], "active sender should remain unselected");
    }

    #[test]
    fn toggle_select_all_active_toggles_only_active() {
        let senders = vec![
            make_sender("active@test.com", 5),
            make_stale_sender("stale@test.com", 3),
        ];
        let mut app = App::new(senders);
        // cursor starts at 1 (SelectAllActive)
        app.toggle();
        assert!(app.active_selected[0], "active sender should be selected");
        assert!(!app.stale_selected[0], "stale sender should remain unselected");
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
        assert_eq!(app.cursor, 1);
        assert_eq!(app.count_selected(), 0);
        assert_eq!(app.total_emails_selected(), 0);

        // Movement should not panic
        app.move_up();
        app.move_down();

        // Toggle with empty active/stale vecs should not panic
        app.toggle();
        app.select_all();
        app.deselect_all();
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let has_timestamp = app.scan_timestamp.is_some();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                                  // title
            Constraint::Length(if has_timestamp { 1 } else { 0 }), // scan timestamp
            Constraint::Min(5),                                    // list
            Constraint::Length(3),                                  // status bar
            Constraint::Length(2),                                  // help
        ])
        .split(area);

    // Title
    let title = Paragraph::new("Email Unsubscriber")
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Scan timestamp
    if let Some(ts) = &app.scan_timestamp {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Parse ISO 8601 timestamp to check age
        let is_stale_scan = parse_iso8601_age_secs(ts)
            .map(|scan_secs| now_secs.saturating_sub(scan_secs) > 7 * 24 * 3600)
            .unwrap_or(false);
        let color = if is_stale_scan { Color::Red } else { Color::DarkGray };
        let label = format!(" Last scanned: {ts}");
        f.render_widget(
            Paragraph::new(label).style(Style::default().fg(color)),
            chunks[1],
        );
    }

    // Scrollable list
    let visible_height = chunks[2].height as usize;
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
            RowKind::ActiveHeader => {
                let label = if app.stale.is_empty() {
                    " ── Senders ──"
                } else {
                    " ── Active Senders ──"
                };
                items.push(Line::styled(label, Style::default().fg(Color::Cyan).bold()));
            }
            RowKind::SelectAllActive => {
                let all_selected = app.active_selected.iter().all(|&s| s)
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
            RowKind::Spacer => {
                items.push(Line::raw(""));
            }
            RowKind::StaleHeader => {
                items.push(Line::styled(
                    " ── Stale Senders (archive only — URLs may be expired) ──",
                    Style::default().fg(Color::Yellow).bold(),
                ));
            }
            RowKind::SelectAllStale => {
                let all_selected = app.stale_selected.iter().all(|&s| s)
                    && !app.stale_selected.is_empty();
                let checkbox = if all_selected { "[x]" } else { "[ ]" };
                let text = format!(" {checkbox} Select All");
                let style = if is_cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                items.push(Line::styled(text, style));
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
    f.render_widget(list, chunks[2]);

    // Status bar
    let status = Paragraph::new(format!(
        " {} of {} senders selected ({} emails)",
        app.count_selected(),
        app.total_senders(),
        app.total_emails_selected(),
    ))
    .style(Style::default().fg(Color::Cyan))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[3]);

    // Help line
    let help = Paragraph::new(
        " Space: toggle | a: select all | n: deselect all | j/k: move | Enter: confirm | q: quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, chunks[4]);
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
    let last_email = format_last_seen(sender.last_seen);
    let name_trunc = truncate_str(&name, 35);
    let email_trunc = truncate_str(&sender.email, 28);
    let text = format!(
        " {checkbox} {name_trunc:<35} ({email_trunc:<28}) {last_email:>8}  [{method:>7}] ({} emails)",
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
    let last_email = format_last_seen(sender.last_seen);
    let name_trunc = truncate_str(&name, 35);
    let email_trunc = truncate_str(&sender.email, 28);
    let text = format!(
        " {checkbox} {name_trunc:<35} ({email_trunc:<28}) {last_email:>8}  [archive ] ({} emails)",
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

/// Parse an ISO 8601 timestamp (e.g., "2026-03-18T19:30:00Z") into Unix seconds.
fn parse_iso8601_age_secs(ts: &str) -> Option<u64> {
    // Minimal parser for the format produced by now_iso8601(): YYYY-MM-DDThh:mm:ssZ
    let b = ts.as_bytes();
    if b.len() < 19 { return None; }
    let year: i64 = ts.get(0..4)?.parse().ok()?;
    let month: u32 = ts.get(5..7)?.parse().ok()?;
    let day: u32 = ts.get(8..10)?.parse().ok()?;
    let hour: u64 = ts.get(11..13)?.parse().ok()?;
    let min: u64 = ts.get(14..16)?.parse().ok()?;
    let sec: u64 = ts.get(17..19)?.parse().ok()?;

    // Convert civil date to days since epoch (inverse of days_to_civil)
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let day_count = era * 146097 + doe as i64 - 719468;

    Some(day_count as u64 * 86400 + hour * 3600 + min * 60 + sec)
}

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format a Unix timestamp as "Mon YYYY" (e.g., "Mar 2025"), or "-" if None.
fn format_last_seen(last_seen: Option<i64>) -> String {
    let ts = match last_seen {
        Some(ts) => ts,
        None => return "-".to_string(),
    };

    // Convert Unix timestamp to civil date (Howard Hinnant's algorithm).
    // The +719468 converts from Unix epoch (1970-01-01) to the algorithm's epoch.
    let day_count = ts / 86400 + 719468;
    let era = if day_count >= 0 { day_count } else { day_count - 146096 } / 146097;
    let doe = (day_count - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let month_name = MONTH_NAMES.get((m - 1) as usize).unwrap_or(&"???");
    format!("{month_name} {y}")
}
