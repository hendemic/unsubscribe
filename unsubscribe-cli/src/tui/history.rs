//! The History screen: what has been unsubscribed, and whether it worked.
//!
//! Read-only. The history is append-only evidence and this screen offers no
//! way to edit or delete it. It also does no aggregation of its own: the rows
//! are [`SenderHistoryView`]s from `unsubscribe_core::history_view`, the same
//! structs the headless `history` command reads, and the ordering, filtering
//! and search are that module's pure functions.

use std::collections::HashMap;

use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    visible_histories, HistoryFilter, HistorySort, NextStep, SenderHistoryView, TimelineEvent,
    UnsubscribeMethod, UnsubscribeOutcome,
};

use super::app::{Effect, Nav, SubView};
use super::keys::{self, Action};
use crate::time::format_unix_date;

/// The listing: every sender with at least one recorded attempt.
pub struct HistoryScreen {
    /// Loaded once when the screen opens. Thousands of attempts reduce to one
    /// row per sender here, and only the visible rows are ever rendered.
    views: Vec<SenderHistoryView>,
    filter: HistoryFilter,
    visible: Vec<usize>,
    cursor: usize,
    scroll_offset: usize,
    /// True while the user is typing a search.
    searching: bool,
}

impl HistoryScreen {
    #[must_use]
    pub fn new(views: Vec<SenderHistoryView>) -> Self {
        let filter = HistoryFilter::default();
        let visible = visible_histories(&views, &filter);
        Self {
            views,
            filter,
            visible,
            cursor: 0,
            scroll_offset: 0,
            searching: false,
        }
    }

    fn refilter(&mut self) {
        self.visible = visible_histories(&self.views, &self.filter);
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    fn selected(&self) -> Option<&SenderHistoryView> {
        self.visible
            .get(self.cursor)
            .and_then(|index| self.views.get(*index))
    }

    fn last(&self) -> usize {
        self.visible.len().saturating_sub(1)
    }

    /// Whether a text field has focus, so the shell leaves the keystroke alone.
    #[must_use]
    pub fn captures_text(&self) -> bool {
        self.searching
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
            Action::Mnemonic('s') => {
                self.filter.sort = self.filter.sort.next();
                self.refilter();
            }
            Action::Mnemonic('r') => {
                self.filter.resumed_only = !self.filter.resumed_only;
                self.refilter();
            }
            Action::Search => self.searching = true,
            Action::Activate => {
                if let Some(view) = self.selected() {
                    return Nav::Push(SubView::SenderHistory(Box::new(DetailScreen::new(
                        view.clone(),
                    ))));
                }
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
        keys::list_actions(&[
            Action::Activate,
            Action::Mnemonic('s'),
            Action::Mnemonic('r'),
            Action::Search,
        ])
    }

    fn scroll_into_view(&mut self, height: usize) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if height > 0 && self.cursor >= self.scroll_offset + height {
            self.scroll_offset = self.cursor - height + 1;
        }
    }
}

/// One sender's timeline, in full.
pub struct DetailScreen {
    view: SenderHistoryView,
    /// The timeline as lines, built once when the screen opens. An escalated
    /// attempt contributes a second, indented line naming what it answers, so
    /// the pair reads as one story rather than two unrelated rows.
    rows: Vec<TimelineRow>,
    scroll_offset: usize,
    cursor: usize,
}

/// One rendered line of a timeline.
struct TimelineRow {
    text: String,
    color: Color,
}

impl DetailScreen {
    #[must_use]
    pub fn new(view: SenderHistoryView) -> Self {
        // Attempt id to "what it was and when", for naming the attempt an
        // escalation answers.
        let labels: HashMap<&str, String> = view
            .attempts()
            .map(|attempt| {
                (
                    attempt.id.as_str(),
                    format!(
                        "{} of {}",
                        method_label(&attempt.method),
                        format_unix_date(attempt.attempted_at)
                    ),
                )
            })
            .collect();
        let rows = view
            .timeline
            .iter()
            .flat_map(|event| timeline_rows(event, &labels))
            .collect();
        Self {
            view,
            rows,
            scroll_offset: 0,
            cursor: 0,
        }
    }

    /// The sender this timeline is about, as the cache would name it.
    #[must_use]
    pub fn sender(&self) -> (&str, Option<&str>) {
        (&self.view.sender_email, self.view.list_id.as_deref())
    }

    /// Whether this sender can be acted on: it ignored an unsubscribe and it
    /// is in the scan the app is working from.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.view.is_resumed() && self.view.in_current_scan()
    }

    pub fn on_action(&mut self, action: Action) -> Nav {
        let last = self.rows.len().saturating_sub(1);
        if let Some(cursor) = keys::move_cursor(action, self.cursor, last) {
            self.cursor = cursor;
            return Nav::Stay;
        }
        match action {
            Action::Mnemonic('u') if self.is_actionable() => {
                Nav::Effect(Effect::RunFromHistory)
            }
            Action::Back => Nav::Pop,
            _ => Nav::Stay,
        }
    }

    /// The actions this sub-view answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        let own: &[Action] = if self.is_actionable() {
            &[Action::Mnemonic('u')]
        } else {
            &[]
        };
        keys::list_actions(own)
    }

    fn scroll_into_view(&mut self, height: usize) {
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if height > 0 && self.cursor >= self.scroll_offset + height {
            self.scroll_offset = self.cursor - height + 1;
        }
    }
}

/// The line (or two) one event contributes.
fn timeline_rows(event: &TimelineEvent, labels: &HashMap<&str, String>) -> Vec<TimelineRow> {
    match event {
        TimelineEvent::Attempt(attempt) => {
            let status = attempt
                .http_status
                .map(|status| format!(" {status}"))
                .unwrap_or_default();
            let target = attempt
                .final_url
                .as_deref()
                .filter(|final_url| *final_url != attempt.url)
                .map(|final_url| format!(" \u{2192} {final_url}"))
                .unwrap_or_default();
            let mut rows = vec![TimelineRow {
                text: format!(
                    " {}  {:<14} {:<4}{:<4}  {}",
                    format_unix_date(attempt.attempted_at),
                    method_label(&attempt.method),
                    if attempt.success { "ok" } else { "fail" },
                    status,
                    truncate(&attempt.detail, 60),
                ),
                color: if attempt.success {
                    Color::Green
                } else {
                    Color::Red
                },
            }];
            rows.push(TimelineRow {
                text: format!(
                    "                 {}",
                    truncate(&format!("{}{target}", attempt.url), 96)
                ),
                color: Color::DarkGray,
            });
            // The escalation names the attempt it answers, so the pair can be
            // read as one exchange: asked this way, ignored, asked that way.
            if let Some(label) = attempt
                .follows_attempt_id
                .as_ref()
                .and_then(|id| labels.get(id.as_str()))
            {
                rows.push(TimelineRow {
                    text: format!("                 \u{21b3} follows the {label}"),
                    color: Color::Cyan,
                });
            }
            rows
        }
        TimelineEvent::Resumption(resumption) => vec![TimelineRow {
            text: format!(
                " {}  {:<14} kept mailing \u{2014} newest of {} emails dated {}",
                format_unix_date(resumption.observed_at),
                "resumed",
                resumption.email_count,
                format_unix_date(resumption.last_seen),
            ),
            color: Color::Yellow,
        }],
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render_list(f: &mut Frame, area: Rect, screen: &mut HistoryScreen) {
    if screen.views.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(
                    "  Nothing here yet.",
                    Style::default().fg(Color::Cyan).bold(),
                ),
                Line::raw(""),
                Line::styled(
                    "  History starts with your first run: every unsubscribe attempt is",
                    Style::default().fg(Color::DarkGray),
                ),
                Line::styled(
                    "  recorded here, along with whether the mail actually stopped.",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .block(Block::default().borders(Borders::ALL).title(" History ")),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    let height = (chunks[0].height as usize).saturating_sub(2);
    screen.scroll_into_view(height);

    let rows: Vec<Line> = screen
        .visible
        .iter()
        .enumerate()
        .skip(screen.scroll_offset)
        .take(height)
        .map(|(position, index)| history_row(&screen.views[*index], position == screen.cursor))
        .collect();

    f.render_widget(
        Paragraph::new(if rows.is_empty() {
            vec![Line::styled(
                " Nothing matches.",
                Style::default().fg(Color::DarkGray),
            )]
        } else {
            rows
        })
        .block(Block::default().borders(Borders::ALL).title(format!(
            " History \u{2014} {} of {} sender(s) ",
            screen.visible.len(),
            screen.views.len()
        ))),
        chunks[0],
    );

    f.render_widget(controls(screen), chunks[1]);
}

/// One sender's row: when it was last asked, how, and what happened after.
fn history_row(view: &SenderHistoryView, is_cursor: bool) -> Line<'static> {
    let violations = if view.violation_count > 1 {
        format!(" x{}", view.violation_count)
    } else {
        String::new()
    };
    let text = format!(
        " {:<38} {:<12} {:<14} {:<30}{violations}",
        truncate(&view.sender_email, 38),
        format_unix_date(view.last_attempt_at),
        truncate(method_label(&view.last_method), 14),
        outcome_label(view),
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if view.is_resumed() {
        Style::default().fg(Color::Red).bold()
    } else if matches!(view.outcome, Some(UnsubscribeOutcome::WithinGrace { .. })) {
        Style::default().fg(Color::Yellow)
    } else if view.outcome.is_none() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Green)
    };
    Line::styled(text, style)
}

/// What the history says happened after the last successful unsubscribe.
fn outcome_label(view: &SenderHistoryView) -> String {
    let Some(outcome) = view.outcome else {
        // Absent from the scan is not the same as honoured: nothing has
        // arrived to judge, and saying otherwise would invent a verdict.
        return "not in the last scan".to_string();
    };
    let base = match outcome {
        UnsubscribeOutcome::NoNewMail => "no new mail".to_string(),
        UnsubscribeOutcome::WithinGrace { days_left } => {
            format!("within grace ({days_left}d left)")
        }
        UnsubscribeOutcome::Resumed { days_after } => format!("resumed {days_after}d after"),
    };
    match &view.next_step {
        Some(NextStep::Exhausted) if outcome.is_resumed() => format!("{base} \u{2014} exhausted"),
        Some(step) if outcome.is_resumed() => format!("{base} \u{2014} {}", step.label()),
        _ => base,
    }
}

/// The sort, filter and search line under the listing.
fn controls(screen: &HistoryScreen) -> Paragraph<'static> {
    let sort = match screen.filter.sort {
        HistorySort::LastAttempt => "last attempt",
        HistorySort::Violations => "violations",
        HistorySort::Sender => "sender",
    };
    let search = if screen.searching {
        format!("/{}\u{2588}", screen.filter.search)
    } else if screen.filter.search.is_empty() {
        "none".to_string()
    } else {
        format!("/{}", screen.filter.search)
    };
    Paragraph::new(Line::from(vec![
        Span::styled(" sort ", Style::default().fg(Color::DarkGray)),
        Span::styled(sort, Style::default().fg(Color::Cyan)),
        Span::styled("   resumed only ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            if screen.filter.resumed_only { "on" } else { "off" },
            Style::default().fg(if screen.filter.resumed_only {
                Color::Red
            } else {
                Color::Cyan
            }),
        ),
        Span::styled("   search ", Style::default().fg(Color::DarkGray)),
        Span::styled(search, Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL))
}

pub(crate) fn render_detail(f: &mut Frame, area: Rect, screen: &mut DetailScreen) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(5)])
        .split(area);

    let view = &screen.view;
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(
                    view.sender_email.clone(),
                    Style::default().fg(Color::Cyan).bold(),
                ),
                Span::styled(
                    format!("   {}", view.sender_domain),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::styled(
                format!(
                    " list-id: {}",
                    view.list_id.clone().unwrap_or_else(|| "none".to_string())
                ),
                Style::default().fg(Color::DarkGray),
            ),
            Line::styled(
                format!(
                    " {}   {} violation(s)",
                    outcome_label(view),
                    view.violation_count
                ),
                if view.is_resumed() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let height = (chunks[1].height as usize).saturating_sub(2);
    screen.scroll_into_view(height);

    let rows: Vec<Line> = screen
        .rows
        .iter()
        .enumerate()
        .skip(screen.scroll_offset)
        .take(height)
        .map(|(index, row)| {
            let style = if index == screen.cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(row.color)
            };
            Line::styled(row.text.clone(), style)
        })
        .collect();

    f.render_widget(
        Paragraph::new(rows).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Timeline \u{2014} {} event(s) ",
                    screen.view.timeline.len()
                )),
        ),
        chunks[1],
    );
}

/// The display name of a stored method id, falling back to the id itself so
/// a record written by a newer build is never shown as blank.
pub(crate) fn method_label(id: &str) -> &str {
    UnsubscribeMethod::from_id(id).map_or(id, |method| method.label())
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
    use unsubscribe_core::{Resumption, UnsubscribeAttempt};

    const DAY: i64 = 24 * 60 * 60;
    const T0: i64 = 1_700_000_000;

    fn typed(screen: &mut HistoryScreen, text: &str) {
        for c in text.chars() {
            screen.on_action(Action::Type(c));
        }
    }

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(SubView::SenderHistory(_)) => "push detail",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Quit => "quit",
            Nav::Effect(Effect::RunFromHistory) => "run from history",
            Nav::Effect(_) => "other effect",
        }
    }

    fn attempt(id: &str, email: &str, at: i64, follows: Option<&str>) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: id.to_string(),
            account: "user@example.com".to_string(),
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
            follows_attempt_id: follows.map(str::to_string),
            detail: "HTTP 200".to_string(),
        }
    }

    fn view(email: &str, list_id: Option<&str>, violations: usize) -> SenderHistoryView {
        SenderHistoryView {
            sender_email: email.to_string(),
            sender_domain: email.split('@').nth(1).unwrap_or("").to_string(),
            list_id: list_id.map(str::to_string),
            last_attempt_at: T0 - 30 * DAY,
            last_method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            outcome: None,
            violation_count: violations,
            next_step: None,
            timeline: vec![TimelineEvent::Attempt(attempt("a1", email, T0 - 30 * DAY, None))],
        }
    }

    /// A view for a sender that is mailing again and is in the current scan:
    /// the only case the `u` key is offered for.
    fn resumed_and_scanned(email: &str) -> SenderHistoryView {
        SenderHistoryView {
            outcome: Some(UnsubscribeOutcome::Resumed { days_after: 20 }),
            next_step: Some(NextStep::FirstAttempt),
            violation_count: 1,
            ..view(email, Some("news.acme"), 1)
        }
    }

    fn listing() -> HistoryScreen {
        HistoryScreen::new(vec![
            resumed_and_scanned("bad@acme.example.com"),
            view("quiet@beta.example.org", None, 0),
            view("gone@gamma.example.net", Some("deals.gamma"), 0),
        ])
    }

    fn visible_addresses(screen: &HistoryScreen) -> Vec<&str> {
        screen
            .visible
            .iter()
            .map(|index| screen.views[*index].sender_email.as_str())
            .collect()
    }

    // -- the listing ---------------------------------------------------------

    #[test]
    fn every_sender_is_listed_before_any_filter_is_applied() {
        let screen = listing();

        assert_eq!(screen.visible.len(), 3);
        assert_eq!(screen.cursor, 0);
    }

    #[test]
    fn the_cursor_stops_at_both_ends() {
        let mut screen = listing();

        for _ in 0..10 {
            screen.on_action(Action::MoveDown);
        }
        assert_eq!(screen.cursor, 2);

        for _ in 0..10 {
            screen.on_action(Action::MoveUp);
        }
        assert_eq!(screen.cursor, 0);
    }

    #[test]
    fn a_page_moves_ten_rows_and_clamps() {
        let mut screen = HistoryScreen::new(
            (0..25)
                .map(|i| view(&format!("s{i:02}@acme.example.com"), None, 0))
                .collect(),
        );

        screen.on_action(Action::PageDown);
        assert_eq!(screen.cursor, 10);
        screen.on_action(Action::PageDown);
        screen.on_action(Action::PageDown);
        assert_eq!(screen.cursor, 24);
        screen.on_action(Action::PageUp);
        assert_eq!(screen.cursor, 14);
    }

    #[test]
    fn esc_goes_back_one_level_and_q_is_never_back() {
        assert_eq!(nav_name(&listing().on_action(Action::Back)), "pop");
        assert_eq!(nav_name(&listing().on_action(Action::Quit)), "stay");
    }

    #[test]
    fn enter_opens_the_timeline_of_the_highlighted_sender() {
        let mut screen = listing();
        screen.on_action(Action::MoveDown);

        let nav = screen.on_action(Action::Activate);

        assert_eq!(nav_name(&nav), "push detail");
        match nav {
            Nav::Push(SubView::SenderHistory(detail)) => {
                assert_eq!(detail.sender().0, visible_addresses(&screen)[1]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn an_empty_history_offers_nothing_to_open_and_still_goes_back() {
        let mut screen = HistoryScreen::new(Vec::new());

        assert_eq!(nav_name(&screen.on_action(Action::Activate)), "stay");
        assert_eq!(nav_name(&screen.on_action(Action::MoveDown)), "stay");
        assert_eq!(nav_name(&screen.on_action(Action::Back)), "pop");
    }

    // -- sorting and filtering -----------------------------------------------

    #[test]
    fn s_cycles_the_sort_through_every_order_and_back() {
        let mut screen = listing();
        let start = screen.filter.sort;

        let mut seen = vec![start];
        for _ in 0..HistorySort::ALL.len() - 1 {
            screen.on_action(Action::Mnemonic('s'));
            seen.push(screen.filter.sort);
        }
        screen.on_action(Action::Mnemonic('s'));

        assert_eq!(screen.filter.sort, start, "the cycle closes");
        for order in HistorySort::ALL {
            assert!(seen.contains(&order), "{order:?} is reachable");
        }
    }

    #[test]
    fn r_shows_only_the_senders_that_ignored_an_unsubscribe() {
        let mut screen = listing();

        screen.on_action(Action::Mnemonic('r'));
        assert!(screen.filter.resumed_only);
        assert_eq!(visible_addresses(&screen), ["bad@acme.example.com"]);

        screen.on_action(Action::Mnemonic('r'));
        assert_eq!(visible_addresses(&screen).len(), 3);
    }

    #[test]
    fn a_filter_that_shrinks_the_list_pulls_the_cursor_back_into_it() {
        let mut screen = listing();
        screen.on_action(Action::Last);
        assert_eq!(screen.cursor, 2);

        screen.on_action(Action::Mnemonic('r'));

        assert_eq!(screen.cursor, 0, "one row left, so the cursor is on it");
        assert!(screen.selected().is_some());
    }

    // -- search --------------------------------------------------------------

    #[test]
    fn slash_starts_a_search_and_the_keys_typed_become_the_needle() {
        let mut screen = listing();

        screen.on_action(Action::Search);
        assert!(screen.searching);
        typed(&mut screen, "beta");

        assert_eq!(screen.filter.search, "beta");
        assert_eq!(visible_addresses(&screen), ["quiet@beta.example.org"]);
    }

    #[test]
    fn while_searching_the_list_keys_are_taken_as_text() {
        // `r`, `s` and `q` are filter keys outside the field and letters in it.
        let mut screen = listing();
        screen.on_action(Action::Search);

        typed(&mut screen, "rsq");

        assert_eq!(screen.filter.search, "rsq");
        assert!(!screen.filter.resumed_only, "r did not toggle the filter");
        assert_eq!(screen.filter.sort, HistorySort::default(), "s did not sort");
    }

    #[test]
    fn backspace_takes_back_one_character_and_widens_the_list_again() {
        let mut screen = listing();
        screen.on_action(Action::Search);
        typed(&mut screen, "beta");

        screen.on_action(Action::Erase);

        assert_eq!(screen.filter.search, "bet");
        screen.on_action(Action::Erase);
        screen.on_action(Action::Erase);
        screen.on_action(Action::Erase);
        assert_eq!(screen.filter.search, "");
        assert_eq!(visible_addresses(&screen).len(), 3);
    }

    #[test]
    fn backspace_on_an_empty_needle_does_nothing() {
        let mut screen = listing();
        screen.on_action(Action::Search);

        screen.on_action(Action::Erase);

        assert_eq!(screen.filter.search, "");
        assert!(screen.searching);
    }

    #[test]
    fn enter_leaves_the_search_field_and_keeps_what_was_typed() {
        let mut screen = listing();
        screen.on_action(Action::Search);
        typed(&mut screen, "beta");

        screen.on_action(Action::Activate);

        assert!(!screen.searching);
        assert_eq!(screen.filter.search, "beta");
        assert_eq!(visible_addresses(&screen), ["quiet@beta.example.org"]);
    }

    #[test]
    fn esc_in_the_search_field_clears_the_needle_rather_than_leaving_the_screen() {
        let mut screen = listing();
        screen.on_action(Action::Search);
        typed(&mut screen, "beta");

        let nav = screen.on_action(Action::Back);

        assert_eq!(nav_name(&nav), "stay", "the screen stays open");
        assert!(!screen.searching);
        assert_eq!(screen.filter.search, "");
        assert_eq!(visible_addresses(&screen).len(), 3);
    }

    #[test]
    fn a_search_matches_the_list_id_as_well_as_the_address() {
        let mut screen = listing();
        screen.on_action(Action::Search);
        typed(&mut screen, "deals.gamma");

        assert_eq!(visible_addresses(&screen), ["gone@gamma.example.net"]);
    }

    #[test]
    fn a_needle_that_matches_nothing_leaves_no_row_selected() {
        let mut screen = listing();
        screen.on_action(Action::Search);
        typed(&mut screen, "nobody");

        assert!(screen.visible.is_empty());
        assert!(screen.selected().is_none(), "and nothing can be opened");
    }

    // -- the timeline --------------------------------------------------------

    fn resumption(id: &str, attempt_id: &str, at: i64) -> Resumption {
        Resumption {
            id: id.to_string(),
            account: "user@example.com".to_string(),
            sender_email: "bad@acme.example.com".to_string(),
            list_id: None,
            attempt_id: attempt_id.to_string(),
            observed_at: at,
            last_seen: at - DAY,
            email_count: 3,
        }
    }

    fn detail_of(timeline: Vec<TimelineEvent>) -> DetailScreen {
        DetailScreen::new(SenderHistoryView {
            timeline,
            ..view("bad@acme.example.com", None, 0)
        })
    }

    fn rows_of(detail: &DetailScreen) -> Vec<&str> {
        detail.rows.iter().map(|row| row.text.as_str()).collect()
    }

    #[test]
    fn an_attempt_contributes_its_summary_and_the_url_it_aimed_at() {
        let detail = detail_of(vec![TimelineEvent::Attempt(attempt(
            "a1",
            "bad@acme.example.com",
            T0 - 30 * DAY,
            None,
        ))]);

        assert_eq!(detail.rows.len(), 2);
        assert!(rows_of(&detail)[1].contains("https://acme.example.com/unsub"));
    }

    #[test]
    fn an_escalation_names_the_attempt_it_answers() {
        let detail = detail_of(vec![
            TimelineEvent::Attempt(attempt("a1", "bad@acme.example.com", T0 - 100 * DAY, None)),
            TimelineEvent::Attempt(attempt(
                "a2",
                "bad@acme.example.com",
                T0 - 30 * DAY,
                Some("a1"),
            )),
        ]);

        let follows: Vec<&str> = rows_of(&detail)
            .into_iter()
            .filter(|row| row.contains("follows the"))
            .collect();
        assert_eq!(follows.len(), 1, "one link, on the escalated attempt");
        assert!(
            follows[0].contains(UnsubscribeMethod::OneClickPost.label()),
            "{}",
            follows[0]
        );
    }

    #[test]
    fn an_escalation_pointing_at_an_attempt_outside_the_timeline_adds_no_link() {
        // The referenced attempt belongs to another sender's group, so there
        // is nothing to name and a dangling line would be worse than none.
        let detail = detail_of(vec![TimelineEvent::Attempt(attempt(
            "a2",
            "bad@acme.example.com",
            T0 - 30 * DAY,
            Some("somewhere-else"),
        ))]);

        assert!(!rows_of(&detail).iter().any(|row| row.contains("follows the")));
    }

    #[test]
    fn a_resumption_contributes_exactly_one_row() {
        let detail = detail_of(vec![TimelineEvent::Resumption(resumption(
            "r1",
            "a1",
            T0 - 20 * DAY,
        ))]);

        assert_eq!(detail.rows.len(), 1);
        assert!(rows_of(&detail)[0].contains("kept mailing"));
    }

    #[test]
    fn the_timeline_cursor_stops_at_both_ends() {
        let mut detail = detail_of(vec![
            TimelineEvent::Attempt(attempt("a1", "bad@acme.example.com", T0 - 100 * DAY, None)),
            TimelineEvent::Resumption(resumption("r1", "a1", T0 - 60 * DAY)),
        ]);
        let last = detail.rows.len() - 1;

        for _ in 0..10 {
            detail.on_action(Action::MoveDown);
        }
        assert_eq!(detail.cursor, last);

        for _ in 0..10 {
            detail.on_action(Action::MoveUp);
        }
        assert_eq!(detail.cursor, 0);
    }

    #[test]
    fn an_empty_timeline_does_not_panic() {
        let mut detail = detail_of(Vec::new());

        for action in [
            Action::MoveDown,
            Action::MoveUp,
            Action::Last,
            Action::PageDown,
        ] {
            detail.on_action(action);
            assert_eq!(detail.cursor, 0);
        }
    }

    // -- acting from the timeline -------------------------------------------

    #[test]
    fn a_resumed_sender_in_the_current_scan_can_be_escalated_from_its_timeline() {
        let mut detail = DetailScreen::new(resumed_and_scanned("bad@acme.example.com"));

        assert!(detail.is_actionable());
        assert_eq!(
            nav_name(&detail.on_action(Action::Mnemonic('u'))),
            "run from history"
        );
        assert!(detail.actions().contains(&Action::Mnemonic('u')));
    }

    #[test]
    fn a_sender_that_never_resumed_offers_no_second_attempt() {
        let mut detail = DetailScreen::new(SenderHistoryView {
            outcome: Some(UnsubscribeOutcome::NoNewMail),
            next_step: Some(NextStep::FirstAttempt),
            ..view("quiet@beta.example.org", None, 0)
        });

        assert!(!detail.is_actionable());
        assert_eq!(nav_name(&detail.on_action(Action::Mnemonic('u'))), "stay");
        assert!(!detail.actions().contains(&Action::Mnemonic('u')));
    }

    #[test]
    fn a_resumed_sender_absent_from_the_scan_offers_no_second_attempt() {
        // There is no mail to act on and no rung to climb to.
        let mut detail = DetailScreen::new(SenderHistoryView {
            outcome: Some(UnsubscribeOutcome::Resumed { days_after: 20 }),
            next_step: None,
            ..view("bad@acme.example.com", None, 1)
        });

        assert!(!detail.is_actionable());
        assert_eq!(nav_name(&detail.on_action(Action::Mnemonic('u'))), "stay");
    }

    #[test]
    fn a_timeline_names_the_sender_the_way_the_cache_would() {
        let detail = DetailScreen::new(view("bad@acme.example.com", Some("news.acme"), 0));

        assert_eq!(detail.sender(), ("bad@acme.example.com", Some("news.acme")));
    }

    #[test]
    fn esc_and_q_leave_a_timeline() {
        let mut detail = DetailScreen::new(view("bad@acme.example.com", None, 0));

        assert_eq!(nav_name(&detail.on_action(Action::Back)), "pop");
        assert_eq!(nav_name(&detail.on_action(Action::Quit)), "stay");
    }

    // -- wording -------------------------------------------------------------

    #[test]
    fn a_sender_absent_from_the_scan_is_not_called_honoured() {
        let label = outcome_label(&view("gone@acme.example.com", None, 0));

        assert_eq!(label, "not in the last scan");
    }

    #[test]
    fn a_resumed_sender_is_labelled_with_what_would_be_tried_next() {
        let label = outcome_label(&resumed_and_scanned("bad@acme.example.com"));

        assert!(label.contains("resumed 20d after"), "{label}");
        assert!(label.contains(&NextStep::FirstAttempt.label()), "{label}");
    }

    #[test]
    fn a_resumed_sender_with_nothing_left_to_try_says_exhausted() {
        let label = outcome_label(&SenderHistoryView {
            next_step: Some(NextStep::Exhausted),
            ..resumed_and_scanned("bad@acme.example.com")
        });

        assert!(label.contains("exhausted"), "{label}");
    }

    #[test]
    fn a_sender_that_stopped_mailing_is_labelled_without_a_next_step() {
        let label = outcome_label(&SenderHistoryView {
            outcome: Some(UnsubscribeOutcome::NoNewMail),
            next_step: Some(NextStep::FirstAttempt),
            ..view("quiet@beta.example.org", None, 0)
        });

        assert_eq!(label, "no new mail", "nothing is owed, so nothing is offered");
    }

    #[test]
    fn a_method_id_this_build_does_not_know_is_shown_as_itself() {
        assert_eq!(method_label("some_future_method"), "some_future_method");
        assert_eq!(
            method_label(UnsubscribeMethod::OneClickPost.as_id()),
            UnsubscribeMethod::OneClickPost.label()
        );
    }
}
