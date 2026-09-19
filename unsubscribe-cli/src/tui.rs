use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use unsubscribe_core::{split_previously_unsubscribed, SenderInfo, UnsubscribeAttempt};

use crate::time::{
    is_stale, parse_iso8601_age_secs, utc_to_local_display, MONTH_NAMES, SCAN_MAX_AGE_SECS,
};

/// Number of selectable rows Ctrl+Up/Ctrl+Down jumps at a time.
const JUMP_ROWS: usize = 5;

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
/// Senders are split into up to three sections, in the order they matter:
/// previously unsubscribed (a prior unsubscribe succeeded and they are mailing
/// again), active, then stale (last message >12 months ago). Each section has
/// its own header and select-all toggle row, and an empty section contributes
/// no rows at all.
///
/// The row layout is fixed once the app is built -- only selection changes
/// afterwards -- so it is computed once into `rows` and indexed from there.
struct App {
    /// Senders with a prior successful unsubscribe, newest attempt date alongside.
    previous: Vec<SenderInfo>,
    /// When each previously unsubscribed sender was last unsubscribed (Unix seconds).
    previous_unsubscribed_at: Vec<i64>,
    /// Active senders (last_seen within 12 months, or unknown).
    active: Vec<SenderInfo>,
    /// Stale senders (last_seen older than 12 months).
    stale: Vec<SenderInfo>,
    /// Selection state for previously unsubscribed senders. Defaults to false.
    previous_selected: Vec<bool>,
    /// Selection state for active senders (parallel to `active`).
    active_selected: Vec<bool>,
    /// Selection state for stale senders (parallel to `stale`). Defaults to false.
    stale_selected: Vec<bool>,
    /// What each visible row represents, in display order.
    rows: Vec<RowKind>,
    cursor: usize,
    scroll_offset: usize,
    cancelled: bool,
    /// Optional scan timestamp (ISO 8601) for display.
    scan_timestamp: Option<String>,
}

impl App {
    /// Build the selection screen, promoting senders with a prior successful
    /// unsubscribe into their own section.
    fn with_history(senders: Vec<SenderInfo>, history: &[UnsubscribeAttempt]) -> Self {
        let sections = split_previously_unsubscribed(senders, history);

        let (previous, previous_unsubscribed_at): (Vec<_>, Vec<_>) = sections
            .previously_unsubscribed
            .into_iter()
            .map(|p| (p.sender, p.unsubscribed_at))
            .unzip();

        // A previously unsubscribed sender stays in that section even when it
        // is also stale: that it came back at all is the interesting part.
        let (stale, active): (Vec<_>, Vec<_>) =
            sections.remaining.into_iter().partition(is_stale);

        let rows = build_rows(previous.len(), active.len(), stale.len());
        let cursor = first_selectable_row(&rows);

        Self {
            previous_selected: vec![false; previous.len()],
            active_selected: vec![false; active.len()],
            stale_selected: vec![false; stale.len()],
            previous,
            previous_unsubscribed_at,
            active,
            stale,
            rows,
            cursor,
            scroll_offset: 0,
            cancelled: false,
            scan_timestamp: None,
        }
    }

    /// Total number of senders across all sections.
    fn total_senders(&self) -> usize {
        self.previous.len() + self.active.len() + self.stale.len()
    }

    /// Total rows including section headers and spacers.
    fn total_rows(&self) -> usize {
        self.rows.len()
    }

    /// Resolve a visible row index into what it represents.
    fn row_kind(&self, row: usize) -> RowKind {
        self.rows.get(row).copied().unwrap_or(RowKind::ActiveHeader)
    }

    /// Flip a whole section, selecting it unless it is already fully selected.
    fn toggle_section(selected: &mut [bool]) {
        let all_sel = !selected.is_empty() && selected.iter().all(|&s| s);
        selected.fill(!all_sel);
    }

    fn toggle(&mut self) {
        match self.row_kind(self.cursor) {
            RowKind::SelectAllPrevious => Self::toggle_section(&mut self.previous_selected),
            RowKind::SelectAllActive => Self::toggle_section(&mut self.active_selected),
            RowKind::SelectAllStale => Self::toggle_section(&mut self.stale_selected),
            RowKind::Previous(idx) => self.previous_selected[idx] = !self.previous_selected[idx],
            RowKind::Active(idx) => self.active_selected[idx] = !self.active_selected[idx],
            RowKind::Stale(idx) => self.stale_selected[idx] = !self.stale_selected[idx],
            RowKind::PreviousHeader
            | RowKind::ActiveHeader
            | RowKind::StaleHeader
            | RowKind::Spacer => {}
        }
    }

    fn select_all(&mut self) {
        self.previous_selected.fill(true);
        self.active_selected.fill(true);
        self.stale_selected.fill(true);
    }

    fn deselect_all(&mut self) {
        self.previous_selected.fill(false);
        self.active_selected.fill(false);
        self.stale_selected.fill(false);
    }

    fn is_non_selectable(&self, row: usize) -> bool {
        self.row_kind(row).is_non_selectable()
    }

    /// The first row the cursor is allowed to rest on (the top select-all row).
    fn first_selectable(&self) -> usize {
        first_selectable_row(&self.rows)
    }

    fn move_up(&mut self) {
        let min = self.first_selectable();
        if self.cursor > min {
            self.cursor -= 1;
            while self.is_non_selectable(self.cursor) && self.cursor > min {
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

    /// Move up by `n` selectable rows, stopping early at the top.
    fn move_up_by(&mut self, n: usize) {
        for _ in 0..n {
            self.move_up();
        }
    }

    /// Move down by `n` selectable rows, stopping early at the bottom.
    fn move_down_by(&mut self, n: usize) {
        for _ in 0..n {
            self.move_down();
        }
    }

    fn count_selected(&self) -> usize {
        [
            &self.previous_selected,
            &self.active_selected,
            &self.stale_selected,
        ]
        .iter()
        .flat_map(|section| section.iter())
        .filter(|&&s| s)
        .count()
    }

    fn total_emails_selected(&self) -> u32 {
        let sections = [
            (&self.previous, &self.previous_selected),
            (&self.active, &self.active_selected),
            (&self.stale, &self.stale_selected),
        ];
        sections
            .iter()
            .flat_map(|(senders, selected)| senders.iter().zip(selected.iter()))
            .filter(|(_, sel)| **sel)
            .map(|(s, _)| s.email_count)
            .sum()
    }

    /// Consume the app and produce `(sender, selected)` for each sender.
    fn into_results(self) -> Vec<(SenderInfo, bool)> {
        let previous = self.previous.into_iter().zip(self.previous_selected);
        let active = self.active.into_iter().zip(self.active_selected);
        let stale = self.stale.into_iter().zip(self.stale_selected);
        previous.chain(active).chain(stale).collect()
    }
}

/// The first row a cursor may rest on: headers and spacers are skipped.
fn first_selectable_row(rows: &[RowKind]) -> usize {
    rows.iter()
        .position(|row| !row.is_non_selectable())
        .unwrap_or(0)
}

/// Lay out the visible rows for the given section sizes.
///
/// Empty sections contribute nothing -- no header, no select-all, no spacer --
/// so a run with no history looks exactly as it did before.
fn build_rows(previous: usize, active: usize, stale: usize) -> Vec<RowKind> {
    let mut rows = Vec::new();

    if previous > 0 {
        rows.push(RowKind::PreviousHeader);
        rows.push(RowKind::SelectAllPrevious);
        rows.extend((0..previous).map(RowKind::Previous));
        rows.push(RowKind::Spacer);
    }

    rows.push(RowKind::ActiveHeader);
    rows.push(RowKind::SelectAllActive);
    rows.extend((0..active).map(RowKind::Active));

    if stale > 0 {
        rows.push(RowKind::Spacer);
        rows.push(RowKind::StaleHeader);
        rows.push(RowKind::SelectAllStale);
        rows.extend((0..stale).map(RowKind::Stale));
    }

    rows
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RowKind {
    PreviousHeader,
    SelectAllPrevious,
    Previous(usize),
    ActiveHeader,
    SelectAllActive,
    Active(usize),
    Spacer,
    StaleHeader,
    SelectAllStale,
    Stale(usize),
}

impl RowKind {
    /// Headers and spacers are display only -- the cursor skips over them.
    fn is_non_selectable(&self) -> bool {
        matches!(
            self,
            Self::PreviousHeader | Self::ActiveHeader | Self::StaleHeader | Self::Spacer
        )
    }
}

/// Run the TUI selection screen. Returns the senders with their selection state.
/// Selected = true means the user wants to unsubscribe (or archive-only for stale senders).
pub fn select_senders(
    senders: Vec<SenderInfo>,
    history: &[UnsubscribeAttempt],
    scan_timestamp: Option<&str>,
) -> anyhow::Result<Option<Vec<(SenderInfo, bool)>>> {
    enable_raw_mode()?;
    let _guard = TerminalGuard; // restores terminal on drop, even on error/panic
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::with_history(senders, history);
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
                KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.move_up_by(JUMP_ROWS)
                }
                KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.move_down_by(JUMP_ROWS)
                }
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') => app.toggle(),
                KeyCode::Char('a') => app.select_all(),
                KeyCode::Char('n') => app.deselect_all(),
                KeyCode::Home | KeyCode::Char('g') => app.cursor = app.first_selectable(),
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
            list_id: None,
            list_unsubscribe_raw: None,
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
            list_id: None,
            list_unsubscribe_raw: None,
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
        let app = App::with_history(three_active_senders(), &[]);
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(1), RowKind::SelectAllActive));
    }

    #[test]
    fn move_up_stops_at_select_all_active() {
        let mut app = App::with_history(three_active_senders(), &[]);
        app.move_up();
        assert_eq!(app.cursor, 1, "should not move above SelectAllActive");
    }

    #[test]
    fn move_down_stops_at_last_row() {
        let mut app = App::with_history(three_active_senders(), &[]);
        // Rows: ActiveHeader(0), SelectAllActive(1), Active(2,3,4) = 5 rows
        for _ in 0..10 {
            app.move_down();
        }
        assert_eq!(app.cursor, 4);
    }

    #[test]
    fn move_up_and_down_traverse_selectable_rows() {
        let mut app = App::with_history(three_active_senders(), &[]);
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
        let mut app = App::with_history(three_active_senders(), &[]);
        // cursor starts at 1 (SelectAllActive)
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_select_all_active_deselects_when_all_selected() {
        let mut app = App::with_history(three_active_senders(), &[]);
        app.active_selected.fill(true);
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    #[test]
    fn toggle_select_all_active_selects_when_partially_selected() {
        let mut app = App::with_history(three_active_senders(), &[]);
        app.active_selected[0] = true;
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_sender_row_toggles_individual() {
        let mut app = App::with_history(three_active_senders(), &[]);
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
        let mut app = App::with_history(three_active_senders(), &[]);
        app.select_all();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn deselect_all_clears_all_flags() {
        let mut app = App::with_history(three_active_senders(), &[]);
        app.select_all();
        app.deselect_all();
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    // -------------------------------------------------------------------
    // Counting
    // -------------------------------------------------------------------

    #[test]
    fn count_selected_correct() {
        let mut app = App::with_history(three_active_senders(), &[]);
        assert_eq!(app.count_selected(), 0);
        app.active_selected[0] = true;
        app.active_selected[2] = true;
        assert_eq!(app.count_selected(), 2);
    }

    #[test]
    fn total_emails_selected_sums_only_selected() {
        let mut app = App::with_history(three_active_senders(), &[]);
        // a=10, b=20, c=5
        app.active_selected[1] = true; // b=20
        app.active_selected[2] = true; // c=5
        assert_eq!(app.total_emails_selected(), 25);
    }

    #[test]
    fn total_emails_selected_none_selected_is_zero() {
        let app = App::with_history(three_active_senders(), &[]);
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
        let app = App::with_history(senders, &[]);
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
        let app = App::with_history(senders, &[]);
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
        let mut app = App::with_history(senders, &[]);
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
        let mut app = App::with_history(senders, &[]);
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
        let mut app = App::with_history(senders, &[]);
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
        let mut app = App::with_history(senders, &[]);
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
        let mut app = App::with_history(vec![], &[]);
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
            Constraint::Length(if has_timestamp { 2 } else { 0 }), // scan timestamp + spacer
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
        let is_stale_scan = parse_iso8601_age_secs(ts)
            .map(|scan_secs| now_secs.saturating_sub(scan_secs) > SCAN_MAX_AGE_SECS)
            .unwrap_or(false);
        let color = if is_stale_scan { Color::Red } else { Color::DarkGray };
        let display_ts = utc_to_local_display(ts).unwrap_or_else(|| ts.clone());
        let label = format!(" Last scanned: {display_ts}");
        f.render_widget(
            Paragraph::new(label).style(Style::default().fg(color)),
            chunks[1],
        );
    }

    // Scrollable list — subtract 2 for the top/bottom borders of the Block
    let visible_height = (chunks[2].height as usize).saturating_sub(2);
    let total_rows = app.total_rows();

    // Adjust scroll to keep cursor visible.
    // When the cursor is on a row immediately after a non-selectable header,
    // include the header in the visible area so it doesn't disappear.
    let scroll_target = if app.cursor > 0 && app.is_non_selectable(app.cursor - 1) {
        app.cursor - 1
    } else {
        app.cursor
    };
    if scroll_target < app.scroll_offset {
        app.scroll_offset = scroll_target;
    } else if app.cursor >= app.scroll_offset + visible_height {
        app.scroll_offset = app.cursor - visible_height + 1;
    }

    let mut items: Vec<Line> = Vec::new();
    for row in app.scroll_offset..total_rows.min(app.scroll_offset + visible_height) {
        let is_cursor = row == app.cursor;

        match app.row_kind(row) {
            RowKind::PreviousHeader => {
                items.push(Line::styled(
                    " \u{2500}\u{2500} Previously Unsubscribed \u{2500}\u{2500}",
                    Style::default().fg(Color::Yellow).bold(),
                ));
            }
            RowKind::SelectAllPrevious => {
                items.push(select_all_row(&app.previous_selected, is_cursor));
            }
            RowKind::Previous(idx) => {
                items.push(previous_sender_row(
                    &app.previous[idx],
                    app.previous_unsubscribed_at[idx],
                    app.previous_selected[idx],
                    is_cursor,
                ));
            }
            RowKind::ActiveHeader => {
                let label = if app.stale.is_empty() {
                    " ── Senders ──"
                } else {
                    " ── Active Senders ──"
                };
                items.push(Line::styled(label, Style::default().fg(Color::Yellow).bold()));
            }
            RowKind::SelectAllActive => {
                items.push(select_all_row(&app.active_selected, is_cursor));
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
                    " ── Stale Senders ──",
                    Style::default().fg(Color::Yellow).bold(),
                ));
            }
            RowKind::SelectAllStale => {
                items.push(select_all_row(&app.stale_selected, is_cursor));
            }
            RowKind::Stale(idx) => {
                let sender = &app.stale[idx];
                let selected = app.stale_selected[idx];
                items.push(stale_sender_row(sender, selected, is_cursor));
            }
        }
    }

    let title_str = if app.stale.is_empty() {
        " Senders (checked = unsubscribe and archive) "
    } else {
        " Senders (checked = unsubscribe and archive / archive-only for stale) "
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
        " Space: toggle | a: select all | n: deselect all | j/k: move | Ctrl+↑/↓: jump 5 | Enter: confirm | q: quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, chunks[4]);
}

/// The "Select All" row for a section, checked when the whole section is selected.
fn select_all_row(selected: &[bool], is_cursor: bool) -> Line<'static> {
    let all_selected = !selected.is_empty() && selected.iter().all(|&s| s);
    let checkbox = if all_selected { "[x]" } else { "[ ]" };
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else {
        Style::default().fg(Color::Yellow)
    };
    Line::styled(format!(" {checkbox} Select All"), style)
}

/// A sender we already unsubscribed from, annotated with when that happened.
///
/// Selecting one retries the unsubscribe and archives, exactly like an active
/// sender -- the section is about drawing attention, not about behaving
/// differently.
fn previous_sender_row(
    sender: &SenderInfo,
    unsubscribed_at: i64,
    selected: bool,
    is_cursor: bool,
) -> Line<'static> {
    let text = format!(
        "{}  unsubscribed {}",
        sender_row_text(sender, selected),
        format_date(unsubscribed_at),
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if selected {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Yellow)
    };
    Line::styled(text, style)
}

/// The text of a sender row, shared by the active and previously unsubscribed
/// sections so the columns line up between them.
fn sender_row_text(sender: &SenderInfo, selected: bool) -> String {
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
    format!(
        " {checkbox} {name_trunc:<35} ({email_trunc:<28}) {last_email:>8}  [{method:>7}] ({} emails)",
        sender.email_count,
    )
}

fn sender_row(sender: &SenderInfo, selected: bool, is_cursor: bool) -> Line<'static> {
    let text = sender_row_text(sender, selected);
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
        Style::default().fg(Color::Red)
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

/// Format a Unix timestamp as "Mon YYYY" (e.g., "Mar 2025"), or "-" if None.
fn format_last_seen(last_seen: Option<i64>) -> String {
    let Some(ts) = last_seen else {
        return "-".to_string();
    };
    let (year, month, _) = civil_from_unix(ts);
    let month_name = MONTH_NAMES.get((month - 1) as usize).unwrap_or(&"???");
    format!("{month_name} {year}")
}

/// Format a Unix timestamp as "Mon DD, YYYY" (e.g., "Sep 12, 2026").
fn format_date(ts: i64) -> String {
    let (year, month, day) = civil_from_unix(ts);
    let month_name = MONTH_NAMES.get((month - 1) as usize).unwrap_or(&"???");
    format!("{month_name} {day}, {year}")
}

/// Convert a Unix timestamp to a civil `(year, month, day)` (Howard Hinnant's
/// algorithm). The +719468 shifts from the Unix epoch to the algorithm's epoch.
fn civil_from_unix(ts: i64) -> (i64, u32, u32) {
    let day_count = ts.div_euclid(86400) + 719468;
    let era = if day_count >= 0 { day_count } else { day_count - 146096 } / 146097;
    let doe = (day_count - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
