//! The sender selection screen: the checkbox list a run confirms against.
//!
//! [`App`] holds the rows, the cursor and the selection and never touches a
//! terminal, so the whole screen can be driven from a test. Rendering lives at
//! the bottom of the file, and [`select_senders`] is the standalone entry point
//! the `run` command still uses.

use crossterm::event::KeyEvent;
use ratatui::prelude::*;
use ratatui::widgets::*;

use unsubscribe_core::{
    AnnotatedSenders, NextStep, Preferences, SenderInfo, SenderVerdict, UnsubscribeOutcome,
};

use super::keys::{self, Action};
use crate::time::{is_scan_stale, utc_to_local_display, MONTH_NAMES};

/// Number of selectable rows Ctrl+Up/Ctrl+Down jumps at a time.
/// Rows `Ctrl` with an arrow moves here, which is the app-wide jump.
const JUMP_ROWS: usize = keys::JUMP;


/// State for the TUI selection screen.
///
/// Senders are split into up to three sections, in the order they matter:
/// previously unsubscribed (a prior unsubscribe succeeded and they are mailing
/// again), active, then stale (no message within the `stale_after_months`
/// preference). Each section has its own header and select-all toggle row, and
/// an empty section contributes no rows at all.
///
/// The row layout is fixed once the app is built -- only selection changes
/// afterwards -- so it is computed once into `rows` and indexed from there.
pub(crate) struct App {
    /// Senders with a prior successful unsubscribe, newest attempt date alongside.
    previous: Vec<SenderInfo>,
    /// What the history says about each previously unsubscribed sender: when
    /// it was unsubscribed, whether it honoured that, and how often it has not.
    previous_verdicts: Vec<SenderVerdict>,
    /// Active senders (seen within the staleness threshold, or date unknown).
    active: Vec<SenderInfo>,
    /// Stale senders (last seen before the staleness threshold).
    stale: Vec<SenderInfo>,
    /// Selection state for previously unsubscribed senders. Senders that
    /// ignored an unsubscribe start selected; the rest do not.
    previous_selected: Vec<bool>,
    /// Selection state for active senders (parallel to `active`).
    active_selected: Vec<bool>,
    /// Selection state for stale senders (parallel to `stale`). Defaults to false.
    stale_selected: Vec<bool>,
    /// What each visible row represents, in display order.
    rows: Vec<RowKind>,
    cursor: usize,
    scroll_offset: usize,
    pub(crate) cancelled: bool,
    /// Optional scan timestamp (ISO 8601) for display. `None` inside the app,
    /// whose header already carries the scan age.
    pub(crate) scan_timestamp: Option<String>,
    /// User preferences driving the stale split and the scan-age warning.
    preferences: Preferences,
    /// The ticks the screen opened with, so discarding a selection the user
    /// never touched needs no confirmation.
    defaults: Vec<bool>,
}

impl App {
    /// Build the selection screen from the sections core already worked out.
    ///
    /// The grouping is [`unsubscribe_core::annotate_senders`]'s job, so the
    /// screen and a headless run always agree about which sender is where.
    pub(crate) fn new(annotated: AnnotatedSenders, preferences: Preferences) -> Self {
        // The observations have already been recorded by the time the screen
        // opens, so the screen only needs the three groups.
        let AnnotatedSenders {
            previously_unsubscribed,
            active,
            stale,
            ..
        } = annotated;

        let (previous, previous_verdicts): (Vec<_>, Vec<_>) = previously_unsubscribed
            .into_iter()
            .map(|p| (p.sender, p.verdict))
            .unzip();

        let rows = build_rows(previous.len(), active.len(), stale.len());
        let cursor = first_selectable_row(&rows);

        // A sender that kept mailing after a successful unsubscribe is the
        // reason this section exists, so it arrives already ticked; one still
        // inside its grace period has not done anything wrong yet.
        let previous_selected: Vec<bool> = previous_verdicts
            .iter()
            .map(|verdict| verdict.outcome.is_resumed())
            .collect();

        let defaults: Vec<bool> = previous_selected
            .iter()
            .copied()
            .chain(std::iter::repeat_n(false, active.len() + stale.len()))
            .collect();

        Self {
            previous_selected,
            active_selected: vec![false; active.len()],
            stale_selected: vec![false; stale.len()],
            previous,
            previous_verdicts,
            active,
            stale,
            rows,
            cursor,
            scroll_offset: 0,
            cancelled: false,
            scan_timestamp: None,
            preferences,
            defaults,
        }
    }

    /// Whether any tick differs from the ones the screen opened with.
    #[must_use]
    pub(crate) fn is_dirty(&self) -> bool {
        !self
            .previous_selected
            .iter()
            .chain(&self.active_selected)
            .chain(&self.stale_selected)
            .eq(self.defaults.iter())
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

    /// The senders currently ticked, without consuming the screen.
    ///
    /// The confirmation is asked over the top of the screen, so backing out of
    /// it has to leave the selection exactly as it was.
    pub(crate) fn selected_senders(&self) -> Vec<SenderInfo> {
        let sections = [
            (&self.previous, &self.previous_selected),
            (&self.active, &self.active_selected),
            (&self.stale, &self.stale_selected),
        ];
        sections
            .iter()
            .flat_map(|(senders, selected)| senders.iter().zip(selected.iter()))
            .filter(|(_, selected)| **selected)
            .map(|(sender, _)| sender.clone())
            .collect()
    }

    /// Consume the app and produce `(sender, selected)` for each sender.
    pub(crate) fn into_results(self) -> Vec<(SenderInfo, bool)> {
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

/// What the selection screen wants to happen next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectAction {
    /// Stay on the screen.
    None,
    /// The user accepted the current selection.
    Confirm,
    /// The user backed out without choosing.
    Cancel,
    /// Leave the screen standing and hand focus to the nav.
    Park,
    /// Discard the selection, but ask first: ticks have been changed.
    ConfirmCancel,
}

impl App {
    /// Apply one keypress. Pure: no terminal, no I/O, so the whole screen can
    /// be driven from a test.
    pub(crate) fn on_action(&mut self, action: Action) -> SelectAction {
        match action {
            // Esc parks the selection: every tick is kept and the nav becomes
            // reachable. Discarding it is `c`, which is never an accident.
            Action::Back => return SelectAction::Park,
            Action::Mnemonic('c') => {
                return if self.is_dirty() {
                    SelectAction::ConfirmCancel
                } else {
                    SelectAction::Cancel
                }
            }
            Action::Activate => return SelectAction::Confirm,
            Action::JumpUp => self.move_up_by(JUMP_ROWS),
            Action::JumpDown => self.move_down_by(JUMP_ROWS),
            Action::MoveUp => self.move_up(),
            Action::MoveDown => self.move_down(),
            // The headers and spacers between the sections are not rows the
            // page helper can land on, so paging steps rather than jumps.
            Action::PageUp => self.move_up_by(keys::PAGE),
            Action::PageDown => self.move_down_by(keys::PAGE),
            Action::Toggle => self.toggle(),
            Action::Mnemonic('a') => self.select_all(),
            Action::Mnemonic('n') => self.deselect_all(),
            Action::First => self.cursor = self.first_selectable(),
            Action::Last => self.cursor = self.total_rows().saturating_sub(1),
            _ => {}
        }
        SelectAction::None
    }

    /// Apply one raw keypress, for the standalone entry point that owns its
    /// own event loop.
    pub(crate) fn on_key(&mut self, key: KeyEvent) -> SelectAction {
        keys::action(key, false)
            .map(|action| self.on_action(action))
            .unwrap_or(SelectAction::None)
    }

    /// The actions this screen answers, for the footer and the `?` overlay.
    #[must_use]
    pub(crate) fn actions(&self) -> Vec<Action> {
        keys::list_actions(&[
            Action::Toggle,
            Action::Mnemonic('a'),
            Action::Mnemonic('n'),
            Action::Mnemonic('c'),
            Action::Activate,
        ])
    }
}

/// Run the TUI selection screen on its own. Returns the senders with their
/// selection state; selected = true means unsubscribe and archive (or
/// archive-only for stale senders).
///
/// The standalone entry point `run` uses. Inside the app the same [`App`] is
/// pushed onto the screen stack instead, so both paths share every key.
pub fn select_senders(
    annotated: AnnotatedSenders,
    scan_timestamp: Option<&str>,
    preferences: &Preferences,
) -> anyhow::Result<Option<Vec<(SenderInfo, bool)>>> {
    let (_guard, mut terminal) = super::TerminalGuard::enter()?;

    let mut app = App::new(annotated, *preferences);
    app.scan_timestamp = scan_timestamp.map(String::from);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        let crossterm::event::Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind != crossterm::event::KeyEventKind::Press {
            continue;
        }
        match app.on_key(key) {
            SelectAction::None => {}
            SelectAction::Confirm => break,
            // Standalone there is no nav to park at, so backing out is what
            // it has always been: leaving without choosing.
            SelectAction::Cancel | SelectAction::Park | SelectAction::ConfirmCancel => {
                app.cancelled = true;
                break;
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
    use unsubscribe_core::{
        annotate_senders, now_unix_secs, Preferences, RunPolicy, SenderInfo, UnsubscribeAttempt,
    };

    /// Build the screen the way `run` does: annotate the scanned senders
    /// against history in core, then hand the sections to the app.
    fn app_with_history(
        senders: Vec<SenderInfo>,
        history: &[UnsubscribeAttempt],
        preferences: Preferences,
    ) -> App {
        let policy = RunPolicy {
            min_emails: preferences.min_emails,
            stale_after_months: preferences.stale_after_months,
            grace_period_days: preferences.grace_period_days,
            dry_run: false,
        };
        App::new(
            annotate_senders(
                "user@example.com",
                senders,
                history,
                &[],
                &policy,
                now_unix_secs(),
            ),
            preferences,
        )
    }

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
        let app = app_with_history(three_active_senders(), &[], Preferences::default());
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(1), RowKind::SelectAllActive));
    }

    #[test]
    fn move_up_stops_at_select_all_active() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        app.move_up();
        assert_eq!(app.cursor, 1, "should not move above SelectAllActive");
    }

    #[test]
    fn move_down_stops_at_last_row() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        // Rows: ActiveHeader(0), SelectAllActive(1), Active(2,3,4) = 5 rows
        for _ in 0..10 {
            app.move_down();
        }
        assert_eq!(app.cursor, 4);
    }

    #[test]
    fn move_up_and_down_traverse_selectable_rows() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
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
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        // cursor starts at 1 (SelectAllActive)
        app.toggle();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_select_all_active_deselects_when_all_selected() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        app.active_selected.fill(true);
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    #[test]
    fn toggle_select_all_active_selects_when_partially_selected() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        app.active_selected[0] = true;
        app.toggle(); // cursor is at 1 (SelectAllActive)
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn toggle_on_sender_row_toggles_individual() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
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
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        app.select_all();
        assert!(app.active_selected.iter().all(|&s| s));
    }

    #[test]
    fn deselect_all_clears_all_flags() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        app.select_all();
        app.deselect_all();
        assert!(app.active_selected.iter().all(|&s| !s));
    }

    // -------------------------------------------------------------------
    // Counting
    // -------------------------------------------------------------------

    #[test]
    fn count_selected_correct() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        assert_eq!(app.count_selected(), 0);
        app.active_selected[0] = true;
        app.active_selected[2] = true;
        assert_eq!(app.count_selected(), 2);
    }

    #[test]
    fn total_emails_selected_sums_only_selected() {
        let mut app = app_with_history(three_active_senders(), &[], Preferences::default());
        // a=10, b=20, c=5
        app.active_selected[1] = true; // b=20
        app.active_selected[2] = true; // c=5
        assert_eq!(app.total_emails_selected(), 25);
    }

    #[test]
    fn total_emails_selected_none_selected_is_zero() {
        let app = app_with_history(three_active_senders(), &[], Preferences::default());
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
        let app = app_with_history(senders, &[], Preferences::default());
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
        let app = app_with_history(senders, &[], Preferences::default());
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
        let mut app = app_with_history(senders, &[], Preferences::default());
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
        let mut app = app_with_history(senders, &[], Preferences::default());
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
        let mut app = app_with_history(senders, &[], Preferences::default());
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
        let mut app = app_with_history(senders, &[], Preferences::default());
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
        let mut app = app_with_history(vec![], &[], Preferences::default());
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

    // -------------------------------------------------------------------
    // Three-section model: previously unsubscribed / active / stale
    // -------------------------------------------------------------------

    /// A successful unsubscribe of `email`, which is what promotes a scanned
    /// sender into the Previously Unsubscribed section.
    fn unsubscribed(email: &str) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: format!("attempt-{email}"),
            account: "user@example.com".to_string(),
            sender_email: email.to_string(),
            sender_domain: "test.com".to_string(),
            list_id: None,
            attempted_at: 1_700_000_000,
            method: "one_click_post".to_string(),
            success: true,
            http_status: Some(200),
            url: "https://test.com/unsub".to_string(),
            final_url: None,
            list_unsubscribe_raw: None,
            follows_attempt_id: None,
            detail: "HTTP 200".to_string(),
        }
    }

    /// Two senders per section, interleaved in scan order so that routing is
    /// visible rather than an artefact of the input order.
    fn all_three_sections() -> App {
        let senders = vec![
            make_sender("p1@test.com", 1),
            make_sender("a1@test.com", 2),
            make_stale_sender("s1@test.com", 3),
            make_sender("p2@test.com", 4),
            make_sender("a2@test.com", 5),
            make_stale_sender("s2@test.com", 6),
        ];
        let history = vec![unsubscribed("p1@test.com"), unsubscribed("p2@test.com")];
        app_with_history(senders, &history, Preferences::default())
    }

    fn emails(senders: &[SenderInfo]) -> Vec<&str> {
        senders.iter().map(|s| s.email.as_str()).collect()
    }

    #[test]
    fn all_three_sections_lay_out_header_select_all_senders_and_spacers() {
        let app = all_three_sections();
        assert_eq!(
            app.rows,
            vec![
                RowKind::PreviousHeader,
                RowKind::SelectAllPrevious,
                RowKind::Previous(0),
                RowKind::Previous(1),
                RowKind::Spacer,
                RowKind::ActiveHeader,
                RowKind::SelectAllActive,
                RowKind::Active(0),
                RowKind::Active(1),
                RowKind::Spacer,
                RowKind::StaleHeader,
                RowKind::SelectAllStale,
                RowKind::Stale(0),
                RowKind::Stale(1),
            ]
        );
    }

    #[test]
    fn senders_are_routed_to_the_right_section() {
        let app = all_three_sections();
        assert_eq!(emails(&app.previous), ["p1@test.com", "p2@test.com"]);
        assert_eq!(emails(&app.active), ["a1@test.com", "a2@test.com"]);
        assert_eq!(emails(&app.stale), ["s1@test.com", "s2@test.com"]);
    }

    #[test]
    fn previously_unsubscribed_section_is_omitted_when_empty() {
        let app = app_with_history(three_active_senders(), &[], Preferences::default());
        assert!(!app.rows.contains(&RowKind::PreviousHeader));
        assert!(!app.rows.contains(&RowKind::SelectAllPrevious));
        assert_eq!(app.rows[0], RowKind::ActiveHeader);
    }

    #[test]
    fn stale_section_is_omitted_when_empty() {
        let app = app_with_history(three_active_senders(), &[], Preferences::default());
        assert!(!app.rows.contains(&RowKind::StaleHeader));
        assert!(!app.rows.contains(&RowKind::Spacer));
    }

    #[test]
    fn only_previously_unsubscribed_senders_still_shows_the_active_section() {
        // The active header is the screen's anchor, so it is drawn even with
        // nothing under it.
        let app = app_with_history(
            vec![make_sender("p1@test.com", 1)],
            &[unsubscribed("p1@test.com")],
            Preferences::default(),
        );
        assert_eq!(
            app.rows,
            vec![
                RowKind::PreviousHeader,
                RowKind::SelectAllPrevious,
                RowKind::Previous(0),
                RowKind::Spacer,
                RowKind::ActiveHeader,
                RowKind::SelectAllActive,
            ]
        );
    }

    #[test]
    fn only_stale_senders_still_shows_the_active_section() {
        let app = app_with_history(
            vec![make_stale_sender("s1@test.com", 1)],
            &[],
            Preferences::default(),
        );
        assert_eq!(
            app.rows,
            vec![
                RowKind::ActiveHeader,
                RowKind::SelectAllActive,
                RowKind::Spacer,
                RowKind::StaleHeader,
                RowKind::SelectAllStale,
                RowKind::Stale(0),
            ]
        );
    }

    #[test]
    fn previously_unsubscribed_and_stale_with_no_active_senders() {
        let app = app_with_history(
            vec![
                make_sender("p1@test.com", 1),
                make_stale_sender("s1@test.com", 2),
            ],
            &[unsubscribed("p1@test.com")],
            Preferences::default(),
        );
        assert_eq!(
            app.rows,
            vec![
                RowKind::PreviousHeader,
                RowKind::SelectAllPrevious,
                RowKind::Previous(0),
                RowKind::Spacer,
                RowKind::ActiveHeader,
                RowKind::SelectAllActive,
                RowKind::Spacer,
                RowKind::StaleHeader,
                RowKind::SelectAllStale,
                RowKind::Stale(0),
            ]
        );
    }

    #[test]
    fn no_senders_at_all_leaves_only_the_active_header_and_select_all() {
        let app = app_with_history(vec![], &[], Preferences::default());
        assert_eq!(app.rows, vec![RowKind::ActiveHeader, RowKind::SelectAllActive]);
        assert_eq!(app.total_senders(), 0);
    }

    #[test]
    fn a_sender_that_is_both_stale_and_previously_unsubscribed_lands_in_previous() {
        let app = app_with_history(
            vec![make_stale_sender("ghost@test.com", 1)],
            &[unsubscribed("ghost@test.com")],
            Preferences::default(),
        );
        assert_eq!(emails(&app.previous), ["ghost@test.com"]);
        assert!(app.stale.is_empty());
    }

    #[test]
    fn history_matches_the_scanned_sender_case_insensitively() {
        let app = app_with_history(
            vec![make_sender("News@Test.com", 1)],
            &[unsubscribed("NEWS@TEST.COM")],
            Preferences::default(),
        );
        assert_eq!(app.previous.len(), 1);
        assert!(app.active.is_empty());
    }

    #[test]
    fn a_failed_prior_attempt_does_not_promote_a_sender() {
        let mut attempt = unsubscribed("a1@test.com");
        attempt.success = false;
        let app = app_with_history(
            vec![make_sender("a1@test.com", 1)],
            &[attempt],
            Preferences::default(),
        );
        assert!(app.previous.is_empty());
        assert_eq!(app.active.len(), 1);
    }

    #[test]
    fn the_date_of_the_last_successful_unsubscribe_is_kept_for_display() {
        let mut older = unsubscribed("p1@test.com");
        older.id = "older".to_string();
        older.attempted_at = 1_600_000_000;
        let app = app_with_history(
            vec![make_sender("p1@test.com", 1)],
            &[older, unsubscribed("p1@test.com")],
            Preferences::default(),
        );
        assert_eq!(
            app.previous_verdicts
                .iter()
                .map(|v| v.unsubscribed_at)
                .collect::<Vec<_>>(),
            [1_700_000_000]
        );
    }

    // -------------------------------------------------------------------
    // Selection defaults and per-section select-all
    // -------------------------------------------------------------------

    #[test]
    fn previously_unsubscribed_senders_that_stopped_mailing_start_deselected() {
        // These fixtures carry no `last_seen`, so nothing arrived after the
        // unsubscribe as far as the app can tell. Senders caught mailing again
        // start selected instead -- that is what the section is for.
        let app = all_three_sections();
        assert_eq!(app.previous_selected, [false, false]);
    }

    #[test]
    fn active_senders_keep_their_deselected_default() {
        let app = all_three_sections();
        assert_eq!(app.active_selected, [false, false]);
        assert_eq!(app.stale_selected, [false, false]);
        assert_eq!(app.count_selected(), 0);
    }

    #[test]
    fn toggle_select_all_previous_toggles_only_previous() {
        let mut app = all_three_sections();
        app.cursor = 1;
        assert!(matches!(app.row_kind(1), RowKind::SelectAllPrevious));
        app.toggle();

        assert_eq!(app.previous_selected, [true, true]);
        assert_eq!(app.active_selected, [false, false]);
        assert_eq!(app.stale_selected, [false, false]);
    }

    #[test]
    fn toggle_select_all_active_leaves_previous_and_stale_alone() {
        let mut app = all_three_sections();
        app.cursor = 6;
        assert!(matches!(app.row_kind(6), RowKind::SelectAllActive));
        app.toggle();

        assert_eq!(app.previous_selected, [false, false]);
        assert_eq!(app.active_selected, [true, true]);
        assert_eq!(app.stale_selected, [false, false]);
    }

    #[test]
    fn toggle_select_all_stale_leaves_previous_and_active_alone() {
        let mut app = all_three_sections();
        app.cursor = 11;
        assert!(matches!(app.row_kind(11), RowKind::SelectAllStale));
        app.toggle();

        assert_eq!(app.previous_selected, [false, false]);
        assert_eq!(app.active_selected, [false, false]);
        assert_eq!(app.stale_selected, [true, true]);
    }

    #[test]
    fn select_all_previous_twice_returns_to_deselected() {
        let mut app = all_three_sections();
        app.cursor = 1;
        app.toggle();
        app.toggle();
        assert_eq!(app.previous_selected, [false, false]);
    }

    #[test]
    fn toggling_a_previous_sender_row_touches_only_that_sender() {
        let mut app = all_three_sections();
        app.cursor = 3;
        assert!(matches!(app.row_kind(3), RowKind::Previous(1)));
        app.toggle();

        assert_eq!(app.previous_selected, [false, true]);
        assert_eq!(app.count_selected(), 1);
    }

    #[test]
    fn toggling_a_header_or_spacer_changes_nothing() {
        let mut app = all_three_sections();
        for row in [0, 4, 5, 9, 10] {
            app.cursor = row;
            app.toggle();
        }
        assert_eq!(app.count_selected(), 0);
    }

    #[test]
    fn select_all_and_deselect_all_span_every_section() {
        let mut app = all_three_sections();
        app.select_all();
        assert_eq!(app.count_selected(), 6);
        assert_eq!(app.total_emails_selected(), 1 + 2 + 3 + 4 + 5 + 6);

        app.deselect_all();
        assert_eq!(app.count_selected(), 0);
        assert_eq!(app.total_emails_selected(), 0);
    }

    // -------------------------------------------------------------------
    // Cursor navigation across three sections
    // -------------------------------------------------------------------

    #[test]
    fn cursor_starts_on_select_all_previous_when_that_section_exists() {
        let app = all_three_sections();
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(1), RowKind::SelectAllPrevious));
    }

    #[test]
    fn moving_down_visits_every_selectable_row_and_no_other() {
        let mut app = all_three_sections();
        let mut visited = vec![app.cursor];
        for _ in 0..20 {
            app.move_down();
            visited.push(app.cursor);
        }
        visited.dedup();
        assert_eq!(visited, vec![1, 2, 3, 6, 7, 8, 11, 12, 13]);
        assert!(!visited.iter().any(|&row| app.is_non_selectable(row)));
    }

    #[test]
    fn moving_up_from_the_bottom_retraces_the_same_selectable_rows() {
        let mut app = all_three_sections();
        app.cursor = 13;
        let mut visited = vec![app.cursor];
        for _ in 0..20 {
            app.move_up();
            visited.push(app.cursor);
        }
        visited.dedup();
        assert_eq!(visited, vec![13, 12, 11, 8, 7, 6, 3, 2, 1]);
    }

    #[test]
    fn moving_up_stops_at_select_all_previous() {
        let mut app = all_three_sections();
        for _ in 0..10 {
            app.move_up();
        }
        assert_eq!(app.cursor, 1);
    }

    #[test]
    fn jump_movement_skips_headers_and_spacers_too() {
        let mut app = all_three_sections();
        app.move_down_by(JUMP_ROWS);
        // Five selectable steps from row 1: 2, 3, 6, 7, 8.
        assert_eq!(app.cursor, 8);
        assert!(!app.is_non_selectable(app.cursor));
    }

    #[test]
    fn first_selectable_is_the_active_select_all_when_there_is_no_previous_section() {
        let app = app_with_history(
            vec![make_stale_sender("s1@test.com", 1)],
            &[],
            Preferences::default(),
        );
        assert_eq!(app.first_selectable(), 1);
        assert!(matches!(app.row_kind(1), RowKind::SelectAllActive));
    }

    // -------------------------------------------------------------------
    // into_results
    // -------------------------------------------------------------------

    #[test]
    fn into_results_returns_every_sender_exactly_once_across_three_sections() {
        let results = all_three_sections().into_results();

        let mut found: Vec<&str> = results.iter().map(|(s, _)| s.email.as_str()).collect();
        found.sort_unstable();
        assert_eq!(
            found,
            [
                "a1@test.com",
                "a2@test.com",
                "p1@test.com",
                "p2@test.com",
                "s1@test.com",
                "s2@test.com"
            ]
        );
    }

    #[test]
    fn into_results_pairs_each_sender_with_its_own_selection() {
        let mut app = all_three_sections();
        // One sender selected per section, at a different index each time, so
        // a mis-zipped section would pair the wrong sender.
        app.previous_selected[0] = true;
        app.active_selected[1] = true;
        app.stale_selected[0] = true;

        let results = app.into_results();
        let selected: Vec<&str> = results
            .iter()
            .filter(|(_, sel)| *sel)
            .map(|(s, _)| s.email.as_str())
            .collect();
        assert_eq!(selected, ["p1@test.com", "a2@test.com", "s1@test.com"]);
    }

    // -------------------------------------------------------------------
    // Ctrl+Up / Ctrl+Down jump (Issue #79 / #111)
    // -------------------------------------------------------------------

    /// The rows the cursor is allowed to rest on, in display order. Derived
    /// from the layout rather than from the movement code, so it is an
    /// independent yardstick for how far a jump travelled.
    fn selectable_rows(app: &App) -> Vec<usize> {
        (0..app.total_rows())
            .filter(|&row| !app.is_non_selectable(row))
            .collect()
    }

    /// Position of the cursor within `selectable_rows`.
    fn selectable_position(app: &App) -> usize {
        selectable_rows(app)
            .iter()
            .position(|&row| row == app.cursor)
            .expect("cursor must rest on a selectable row")
    }

    #[test]
    fn jumping_down_advances_five_selectable_rows_across_sections() {
        let mut app = all_three_sections();
        let start = selectable_position(&app);

        app.move_down_by(JUMP_ROWS);

        assert_eq!(
            selectable_position(&app) - start,
            5,
            "a jump should cover five selectable rows, whatever sits between them"
        );
        // Rows 1,2,3 are the previous section and 6,7,8 the active one, so this
        // jump crosses a spacer and a header on the way.
        assert_eq!(app.cursor, 8);
        assert!(matches!(app.row_kind(app.cursor), RowKind::Active(1)));
    }

    #[test]
    fn jumping_up_retreats_five_selectable_rows_across_sections() {
        let mut app = all_three_sections();
        app.cursor = 13;
        let start = selectable_position(&app);

        app.move_up_by(JUMP_ROWS);

        assert_eq!(start - selectable_position(&app), 5);
        assert_eq!(app.cursor, 6);
        assert!(matches!(app.row_kind(app.cursor), RowKind::SelectAllActive));
    }

    #[test]
    fn a_jump_down_and_back_up_returns_to_the_starting_row() {
        // Started far enough from both ends that neither jump is clamped.
        let mut app = all_three_sections();
        app.cursor = 3;

        app.move_down_by(JUMP_ROWS);
        assert_eq!(app.cursor, 12);
        app.move_up_by(JUMP_ROWS);

        assert_eq!(app.cursor, 3);
    }

    #[test]
    fn a_jump_down_near_the_bottom_stops_on_the_last_selectable_row() {
        let mut app = all_three_sections();
        app.cursor = 12; // one selectable row above the end

        app.move_down_by(JUMP_ROWS);

        let last_selectable = *selectable_rows(&app).last().expect("rows exist");
        assert_eq!(app.cursor, last_selectable);
        assert_eq!(app.cursor, 13);
        assert!(matches!(app.row_kind(app.cursor), RowKind::Stale(1)));
    }

    #[test]
    fn a_jump_up_near_the_top_stops_on_the_first_selectable_row() {
        let mut app = all_three_sections();
        app.cursor = 2; // one selectable row below the top

        app.move_up_by(JUMP_ROWS);

        assert_eq!(app.cursor, app.first_selectable());
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(app.cursor), RowKind::SelectAllPrevious));
    }

    #[test]
    fn repeated_jumps_settle_on_the_ends_without_overshooting() {
        let mut app = all_three_sections();
        for _ in 0..5 {
            app.move_down_by(JUMP_ROWS);
        }
        assert_eq!(app.cursor, 13, "should rest on the last row, not past it");

        for _ in 0..5 {
            app.move_up_by(JUMP_ROWS);
        }
        assert_eq!(app.cursor, 1, "should rest on the first selectable row");
    }

    /// Build a screen with the given number of senders per section. Section
    /// sizes shift where the headers and spacers fall, which is what decides
    /// whether a jump can strand the cursor on one.
    fn sections_of(previous: usize, active: usize, stale: usize) -> App {
        let mut senders = Vec::new();
        let mut history = Vec::new();
        for i in 0..previous {
            let email = format!("p{i}@test.com");
            history.push(unsubscribed(&email));
            senders.push(make_sender(&email, 1));
        }
        for i in 0..active {
            senders.push(make_sender(&format!("a{i}@test.com"), 1));
        }
        for i in 0..stale {
            senders.push(make_stale_sender(&format!("s{i}@test.com"), 1));
        }
        app_with_history(senders, &history, Preferences::default())
    }

    #[test]
    fn a_jump_from_any_row_lands_on_a_selectable_row() {
        // Where the headers and spacers fall depends on the section sizes, so
        // sweep a range of layouts and every starting row in both directions.
        // A jump that counted display rows instead of selectable ones would
        // strand the cursor on a spacer in one of these.
        for (previous, active, stale) in [
            (0, 0, 0),
            (0, 1, 0),
            (0, 3, 0),
            (0, 3, 2),
            (2, 1, 2),
            (2, 0, 0),
            (1, 4, 1),
            (3, 3, 3),
            (6, 0, 6),
        ] {
            for start in selectable_rows(&sections_of(previous, active, stale)) {
                let mut down = sections_of(previous, active, stale);
                down.cursor = start;
                down.move_down_by(JUMP_ROWS);
                assert!(
                    !down.is_non_selectable(down.cursor),
                    "in ({previous},{active},{stale}), jump down from row {start} \
                     landed on row {} ({:?})",
                    down.cursor,
                    down.row_kind(down.cursor)
                );

                let mut up = sections_of(previous, active, stale);
                up.cursor = start;
                up.move_up_by(JUMP_ROWS);
                assert!(
                    !up.is_non_selectable(up.cursor),
                    "in ({previous},{active},{stale}), jump up from row {start} \
                     landed on row {} ({:?})",
                    up.cursor,
                    up.row_kind(up.cursor)
                );
            }
        }
    }

    #[test]
    fn a_jump_covers_five_selectable_rows_in_every_layout_long_enough_for_it() {
        // Independent of the layout: five steps means five selectable rows,
        // and fewer only when the list runs out.
        for (previous, active, stale) in [(0, 9, 0), (2, 1, 2), (3, 3, 3), (6, 0, 6)] {
            let mut app = sections_of(previous, active, stale);
            let rows = selectable_rows(&app);
            let start = selectable_position(&app);

            app.move_down_by(JUMP_ROWS);

            let expected = (start + 5).min(rows.len() - 1);
            assert_eq!(
                selectable_position(&app),
                expected,
                "({previous},{active},{stale}): jump from selectable row {start} of {}",
                rows.len()
            );
        }
    }

    #[test]
    fn a_jump_down_into_a_trailing_empty_active_section_stops_on_its_select_all() {
        // Layout: PreviousHeader(0), SelectAllPrevious(1), Previous(0..2),
        // Spacer(4), ActiveHeader(5), SelectAllActive(6). The last two rows
        // before the end are a spacer and a header, so an overshooting jump
        // would strand the cursor on one of them.
        let mut app = app_with_history(
            vec![make_sender("p1@test.com", 1), make_sender("p2@test.com", 2)],
            &[unsubscribed("p1@test.com"), unsubscribed("p2@test.com")],
            Preferences::default(),
        );

        app.move_down_by(JUMP_ROWS);

        assert_eq!(app.cursor, 6);
        assert!(matches!(app.row_kind(app.cursor), RowKind::SelectAllActive));
    }

    #[test]
    fn a_jump_in_an_empty_list_does_not_panic() {
        let mut app = app_with_history(vec![], &[], Preferences::default());

        app.move_down_by(JUMP_ROWS);
        assert_eq!(app.cursor, 1);
        app.move_up_by(JUMP_ROWS);
        assert_eq!(app.cursor, 1);
        assert!(matches!(app.row_kind(app.cursor), RowKind::SelectAllActive));
    }

    #[test]
    fn a_jump_in_a_list_shorter_than_the_jump_does_not_overshoot() {
        let mut app = app_with_history(
            vec![make_sender("only@test.com", 1)],
            &[],
            Preferences::default(),
        );
        // Rows: ActiveHeader(0), SelectAllActive(1), Active(0) at 2.
        app.move_down_by(JUMP_ROWS);
        assert_eq!(app.cursor, 2);
        app.move_up_by(JUMP_ROWS);
        assert_eq!(app.cursor, 1);
    }

    #[test]
    fn jumping_does_not_change_any_selection() {
        // Movement is navigation only — a jump that toggled rows on the way
        // past would be silently destructive.
        let mut app = all_three_sections();
        app.move_down_by(JUMP_ROWS);
        app.move_up_by(JUMP_ROWS);

        assert_eq!(app.count_selected(), 0);
    }
}

/// Draw the whole screen, standalone: title, body, and its own help line.
fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(5),    // body
            Constraint::Length(2), // help
        ])
        .split(f.area());

    let title = Paragraph::new("Email Unsubscriber")
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    render(f, chunks[1], app);

    f.render_widget(
        Paragraph::new(keys::hints(&app.actions())).style(Style::default().fg(Color::DarkGray)),
        chunks[2],
    );
}

/// Draw the screen's body into `area`: the scan timestamp (standalone only),
/// the scrollable list, and the selection status bar.
pub(crate) fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let has_timestamp = app.scan_timestamp.is_some();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if has_timestamp { 2 } else { 0 }), // scan timestamp + spacer
            Constraint::Min(5),                                    // list
            Constraint::Length(3),                                 // status bar
        ])
        .split(area);

    // Scan timestamp
    if let Some(ts) = &app.scan_timestamp {
        let color = if is_scan_stale(ts, app.preferences.cache_max_age_days) {
            Color::Red
        } else {
            Color::DarkGray
        };
        let display_ts = utc_to_local_display(ts).unwrap_or_else(|| ts.clone());
        let label = format!(" Last scanned: {display_ts}");
        f.render_widget(
            Paragraph::new(label).style(Style::default().fg(color)),
            chunks[0],
        );
    }

    // Scrollable list — subtract 2 for the top/bottom borders of the Block
    let visible_height = (chunks[1].height as usize).saturating_sub(2);
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
                    &app.previous_verdicts[idx],
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
    f.render_widget(list, chunks[1]);

    // Status bar
    let status = Paragraph::new(format!(
        " {} of {} senders selected ({} emails)",
        app.count_selected(),
        app.total_senders(),
        app.total_emails_selected(),
    ))
    .style(Style::default().fg(Color::Cyan))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[2]);
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

/// A sender we already unsubscribed from, annotated with what happened next.
///
/// Selecting one retries the unsubscribe and archives, exactly like an active
/// sender. What the row adds is the measurement: an HTTP 200 was never the
/// point, the mail stopping was.
fn previous_sender_row(
    sender: &SenderInfo,
    verdict: &SenderVerdict,
    selected: bool,
    is_cursor: bool,
) -> Line<'static> {
    let text = format!(
        "{}  unsubscribed {}  {}{}{}",
        sender_row_text(sender, selected),
        format_date(verdict.unsubscribed_at),
        outcome_label(verdict.outcome),
        violations_label(verdict.violation_count),
        next_step_label(verdict),
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if verdict.outcome.is_resumed() {
        // The one row that is a finding rather than a listing.
        Style::default().fg(Color::Red).bold()
    } else if selected {
        Style::default().fg(Color::Red)
    } else if matches!(verdict.outcome, UnsubscribeOutcome::WithinGrace { .. }) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Line::styled(text, style)
}

/// How an outcome reads on a row.
fn outcome_label(outcome: UnsubscribeOutcome) -> String {
    match outcome {
        UnsubscribeOutcome::NoNewMail => "no new mail".to_string(),
        UnsubscribeOutcome::WithinGrace { days_left } => {
            format!("within grace period ({days_left}d left)")
        }
        UnsubscribeOutcome::Resumed { days_after } => {
            format!("resumed {days_after}d after unsubscribe")
        }
    }
}

/// What a retry of a sender that ignored its unsubscribe would do.
///
/// Only shown for senders that actually resumed: for the rest, what would be
/// tried next is not yet a question anyone is asking.
fn next_step_label(verdict: &SenderVerdict) -> String {
    if !verdict.outcome.is_resumed() {
        return String::new();
    }
    match &verdict.next_step {
        NextStep::Exhausted => "  exhausted \u{2014} no methods left".to_string(),
        step => format!("  {}", step.label()),
    }
}

/// A repeat offender's tally, shown only once there is more than one.
fn violations_label(violation_count: u32) -> String {
    if violation_count > 1 {
        format!("  ({violation_count} violations)")
    } else {
        String::new()
    }
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

/// The key contract the shell and the standalone loop both depend on:
/// which keys end the screen, and what the selection looks like afterwards.
#[cfg(test)]
mod key_handling_tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use unsubscribe_core::{
        annotate_senders, now_unix_secs, AnnotatedSenders, RunPolicy, SenderInfo,
    };

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    fn sender(email: &str, email_count: u32) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: "test.com".to_string(),
            unsubscribe_urls: vec!["https://test.com/unsub".to_string()],
            unsubscribe_mailto: vec![],
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count,
            messages: vec![],
            last_seen: None,
        }
    }

    fn annotated(senders: Vec<SenderInfo>) -> AnnotatedSenders {
        let policy = RunPolicy {
            min_emails: 1,
            stale_after_months: 12,
            grace_period_days: 14,
            dry_run: false,
        };
        annotate_senders("user@example.com", senders, &[], &[], &policy, now_unix_secs())
    }

    fn app() -> App {
        App::new(
            annotated(vec![
                sender("a@test.com", 10),
                sender("b@test.com", 20),
                sender("c@test.com", 5),
            ]),
            Preferences::default(),
        )
    }

    fn chosen(app: &App) -> Vec<String> {
        app.selected_senders()
            .into_iter()
            .map(|sender| sender.email)
            .collect()
    }

    #[test]
    fn enter_confirms_the_selection() {
        assert_eq!(app().on_key(key(KeyCode::Enter)), SelectAction::Confirm);
    }

    #[test]
    fn esc_backs_out_without_running_and_q_is_never_back() {
        assert_eq!(app().on_key(key(KeyCode::Esc)), SelectAction::Cancel);
        assert_eq!(app().on_key(key(KeyCode::Char('q'))), SelectAction::None);
    }

    #[test]
    fn moving_and_toggling_keep_the_screen_open() {
        let mut app = app();

        for code in [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::Char(' '),
            KeyCode::Char('a'),
            KeyCode::Char('n'),
            KeyCode::Char('g'),
            KeyCode::Char('G'),
            KeyCode::Char('z'),
        ] {
            assert_eq!(app.on_key(key(code)), SelectAction::None, "{code:?}");
        }
    }

    #[test]
    fn nothing_is_selected_until_the_user_says_so() {
        assert!(chosen(&app()).is_empty());
    }

    #[test]
    fn a_selects_every_sender_and_n_clears_them_again() {
        let mut app = app();

        app.on_key(key(KeyCode::Char('a')));
        let mut selected = chosen(&app);
        selected.sort();
        assert_eq!(selected, ["a@test.com", "b@test.com", "c@test.com"]);

        app.on_key(key(KeyCode::Char('n')));
        assert!(chosen(&app).is_empty());
    }

    #[test]
    fn space_ticks_exactly_the_sender_under_the_cursor() {
        let mut app = app();
        // From the active select-all row onto the first sender.
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Char(' ')));

        assert_eq!(chosen(&app), ["a@test.com"]);
    }

    #[test]
    fn the_selection_survives_being_read_so_a_declined_run_loses_nothing() {
        let mut app = app();
        app.on_key(key(KeyCode::Char('a')));

        let first = chosen(&app);
        let second = chosen(&app);

        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
    }

    #[test]
    fn a_jump_moves_the_cursor_without_changing_the_selection() {
        let mut app = app();
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Char(' ')));
        let before = app.cursor;

        assert_eq!(app.on_key(ctrl(KeyCode::Down)), SelectAction::None);

        assert_ne!(app.cursor, before);
        assert_eq!(chosen(&app), ["a@test.com"]);
    }

    #[test]
    fn a_screen_with_no_senders_still_answers_every_key() {
        let mut app = App::new(annotated(Vec::new()), Preferences::default());

        assert_eq!(app.on_key(key(KeyCode::Char(' '))), SelectAction::None);
        assert_eq!(app.on_key(key(KeyCode::Char('a'))), SelectAction::None);
        assert!(chosen(&app).is_empty());
        assert_eq!(app.on_key(key(KeyCode::Enter)), SelectAction::Confirm);
    }
}
