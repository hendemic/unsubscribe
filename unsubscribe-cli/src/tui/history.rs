//! The History screen: what has been unsubscribed, and whether it worked.
//!
//! Read-only. The history is append-only evidence and this screen offers no
//! way to edit or delete it. It also does no aggregation of its own: the rows
//! are [`SenderHistoryView`]s from `unsubscribe_core::history_view`, the same
//! structs the headless `history` command reads, and the ordering, filtering
//! and search are that module's pure functions.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    visible_histories, HistoryFilter, HistorySort, NextStep, SenderHistoryView, TimelineEvent,
    UnsubscribeMethod, UnsubscribeOutcome,
};

use super::app::{Effect, Nav, Screen};
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

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        if self.searching {
            match key.code {
                KeyCode::Char(c) => {
                    self.filter.search.push(c);
                    self.refilter();
                }
                KeyCode::Backspace => {
                    self.filter.search.pop();
                    self.refilter();
                }
                // Enter keeps the needle and leaves the field; Esc clears it.
                KeyCode::Enter => self.searching = false,
                KeyCode::Esc => {
                    self.searching = false;
                    self.filter.search.clear();
                    self.refilter();
                }
                _ => {}
            }
            return Nav::Stay;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.cursor = (self.cursor + 1).min(self.last()),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::PageDown => self.cursor = (self.cursor + 10).min(self.last()),
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = self.last(),
            KeyCode::Char('s') => {
                self.filter.sort = self.filter.sort.next();
                self.refilter();
            }
            KeyCode::Char('r') => {
                self.filter.resumed_only = !self.filter.resumed_only;
                self.refilter();
            }
            KeyCode::Char('/') => self.searching = true,
            KeyCode::Enter => {
                if let Some(view) = self.selected() {
                    return Nav::Push(Screen::SenderHistory(Box::new(DetailScreen::new(
                        view.clone(),
                    ))));
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => return Nav::Pop,
            _ => {}
        }
        Nav::Stay
    }

    pub fn hints(&self) -> &'static str {
        if self.searching {
            " type to search | Enter: keep | Esc: clear"
        } else {
            " j/k: move | Enter: detail | s: sort | r: resumed only | /: search | Esc: back"
        }
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("j / k / \u{2191}\u{2193}", "move"),
            ("PgUp / PgDn", "move a page"),
            ("Enter", "open the sender's timeline"),
            ("s", "cycle sort: date, violations, sender"),
            ("r", "show only senders that resumed"),
            ("/", "search address, domain or list id"),
            ("Esc / q", "back"),
        ]
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

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        let last = self.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.cursor = (self.cursor + 1).min(last),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::PageDown => self.cursor = (self.cursor + 10).min(last),
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = last,
            KeyCode::Char('u') if self.is_actionable() => {
                return Nav::Effect(Effect::RunFromHistory);
            }
            KeyCode::Esc | KeyCode::Char('q') => return Nav::Pop,
            _ => {}
        }
        Nav::Stay
    }

    pub fn hints(&self) -> &'static str {
        if self.is_actionable() {
            " j/k: move | u: unsubscribe again | Esc: back"
        } else {
            " j/k: move | Esc: back"
        }
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("j / k / \u{2191}\u{2193}", "scroll the timeline"),
            ("u", "escalate this sender now (resumed senders in the scan)"),
            ("Esc / q", "back"),
        ]
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
fn method_label(id: &str) -> &str {
    UnsubscribeMethod::from_id(id).map_or(id, |method| method.label())
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}
