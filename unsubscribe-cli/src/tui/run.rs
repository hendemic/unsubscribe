//! The Run screen: each sender's attempt as it completes, then the archive,
//! then what happened.
//!
//! Like the scan screen, this owns no pipeline. A worker thread runs
//! [`unsubscribe_core::execute_run`] and appends to a shared log; this reads
//! it every frame. Cancelling sets the flag the run observer polls between
//! senders, which is why an attempt is never abandoned half-made.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{RunOutcome, RunPlan};

use super::app::{Effect, Nav};
use super::worker::{RunEvent, RunResult, RunShared};

/// The parts of a plan the screen still needs once the plan itself has been
/// handed to the worker.
#[derive(Debug, Clone, Default)]
pub struct PlanCounts {
    pub to_unsubscribe: usize,
    pub archive_only: usize,
    pub exhausted: usize,
    /// Addresses with nothing left to try -- the candidates for a server-side
    /// filter or a report, so the run names them rather than losing them in
    /// the archive.
    pub exhausted_senders: Vec<String>,
}

impl PlanCounts {
    #[must_use]
    pub fn of(plan: &RunPlan) -> Self {
        Self {
            to_unsubscribe: plan.to_unsubscribe.len(),
            archive_only: plan.archive_only.len(),
            exhausted: plan.exhausted.len(),
            exhausted_senders: plan
                .exhausted
                .iter()
                .map(|sender| sender.email.clone())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    /// Cancel has been asked for; the worker stops before the next sender.
    Cancelling,
    /// The worker is done and the summary is on screen.
    Finished,
}

pub struct RunScreen {
    shared: Arc<RunShared>,
    result: Receiver<RunResult>,
    counts: PlanCounts,
    dry_run: bool,
    state: RunState,
    /// Set once the worker reports. `Err` is an archive failure.
    outcome: Option<Result<Box<RunOutcome>, String>>,
    cursor: usize,
    scroll_offset: usize,
    /// Index into the rendered rows of the attempt being inspected.
    detail: Option<usize>,
}

impl RunScreen {
    #[must_use]
    pub fn new(
        shared: Arc<RunShared>,
        result: Receiver<RunResult>,
        counts: PlanCounts,
        dry_run: bool,
    ) -> Self {
        Self {
            shared,
            result,
            counts,
            dry_run,
            state: RunState::Running,
            outcome: None,
            cursor: 0,
            scroll_offset: 0,
            detail: None,
        }
    }

    /// The message of a run that ended badly: an archive that failed, or a
    /// worker that died. `None` while running and for a clean finish.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        match self.outcome.as_ref() {
            Some(Err(message)) => Some(message),
            _ => None,
        }
    }

    /// Ask the worker to stop before the next sender.
    pub fn request_cancel(&mut self) {
        self.shared.cancel();
        self.state = RunState::Cancelling;
    }

    pub fn tick(&mut self) -> Nav {
        if self.state == RunState::Finished {
            return Nav::Stay;
        }
        self.outcome = match self.result.try_recv() {
            Ok(RunResult::Done(outcome)) => Some(Ok(outcome)),
            Ok(RunResult::Failed(message)) => Some(Err(message)),
            Err(TryRecvError::Empty) => return Nav::Stay,
            Err(TryRecvError::Disconnected) => Some(Err(
                "The run stopped without reporting a result.".to_string()
            )),
        };
        self.state = RunState::Finished;
        // The screen stays up with its summary; the shell only refreshes the
        // counts behind it.
        Nav::Effect(Effect::RunEnded)
    }

    fn attempts(&self) -> Vec<RunEvent> {
        self.shared
            .events()
            .into_iter()
            .filter(|event| matches!(event, RunEvent::Sender { .. }))
            .collect()
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        if self.detail.is_some() {
            self.detail = None;
            return Nav::Stay;
        }
        let last = self.attempts().len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.cursor = (self.cursor + 1).min(last),
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = last,
            KeyCode::Enter if self.state == RunState::Finished => {
                self.detail = Some(self.cursor);
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                return match self.state {
                    // Finishing returns Home; the counts there are already
                    // refreshed by the time the user gets back.
                    RunState::Finished => Nav::Pop,
                    RunState::Running => Nav::Effect(Effect::ConfirmCancelRun),
                    // Already stopping: asking again would change nothing.
                    RunState::Cancelling => Nav::Stay,
                };
            }
            _ => {}
        }
        Nav::Stay
    }

    pub fn hints(&self) -> &'static str {
        match self.state {
            RunState::Running => " j/k: scroll | Esc: cancel the run | ?: keys",
            RunState::Cancelling => " stopping after the current sender\u{2026}",
            RunState::Finished if self.detail.is_some() => " any key: close",
            RunState::Finished => " j/k: move | Enter: inspect | Esc: back to Home",
        }
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("j / k / \u{2191}\u{2193}", "scroll the attempts"),
            ("Enter", "inspect the highlighted attempt"),
            ("Esc / q", "cancel while running, back when finished"),
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

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render(f: &mut Frame, area: Rect, screen: &mut RunScreen) {
    let events = screen.shared.events();
    let attempts: Vec<&RunEvent> = events
        .iter()
        .filter(|event| matches!(event, RunEvent::Sender { .. }))
        .collect();
    // While the run is going the newest row is the interesting one, so the
    // cursor follows it until the user takes hold of it.
    if screen.state == RunState::Running {
        screen.cursor = attempts.len().saturating_sub(1);
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(6)])
        .split(area);

    let height = (chunks[0].height as usize).saturating_sub(2);
    screen.scroll_into_view(height);

    let rows: Vec<Line> = attempts
        .iter()
        .enumerate()
        .skip(screen.scroll_offset)
        .take(height)
        .map(|(index, event)| attempt_row(event, index == screen.cursor))
        .collect();

    let title = match (screen.dry_run, screen.state) {
        (true, RunState::Finished) => " Dry run \u{2014} nothing was changed ".to_string(),
        (true, _) => " Dry run \u{2014} nothing will be changed ".to_string(),
        (false, RunState::Cancelling) => " Unsubscribing \u{2014} stopping ".to_string(),
        (false, RunState::Finished) => " Attempts ".to_string(),
        (false, RunState::Running) => format!(
            " Unsubscribing \u{2014} {} of {} ",
            attempts.len(),
            screen.shared.planned().max(screen.counts.to_unsubscribe as u32)
        ),
    };

    f.render_widget(
        Paragraph::new(if rows.is_empty() {
            vec![Line::styled(
                " Starting\u{2026}",
                Style::default().fg(Color::DarkGray),
            )]
        } else {
            rows
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if screen.dry_run {
                    Color::Yellow
                } else {
                    Color::Reset
                }))
                .title(title),
        ),
        chunks[0],
    );

    f.render_widget(footer(screen, &events), chunks[1]);

    if let Some(index) = screen.detail {
        if let Some(event) = attempts.get(index) {
            render_detail(f, event);
        }
    }
}

/// One attempt's row: what was tried, how it went, and what it climbed from.
fn attempt_row(event: &RunEvent, is_cursor: bool) -> Line<'static> {
    let RunEvent::Sender {
        email,
        success,
        method,
        detail,
        escalation,
    } = event
    else {
        return Line::raw("");
    };
    let tag = if *success { "[OK]  " } else { "[FAIL]" };
    let note = escalation
        .as_ref()
        .map(|text| format!("  ({text})"))
        .unwrap_or_default();
    let text = format!(
        " {tag} {:<38} {:<14} {}{note}",
        truncate(email, 38),
        truncate(method, 14),
        truncate(detail, 40),
    );
    let style = if is_cursor {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else if *success {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    };
    Line::styled(text, style)
}

/// The phase line while running, and the summary once finished.
fn footer(screen: &RunScreen, events: &[RunEvent]) -> Paragraph<'static> {
    let warnings: Vec<&String> = events
        .iter()
        .filter_map(|event| match event {
            RunEvent::Warning(text) => Some(text),
            _ => None,
        })
        .collect();

    let mut lines: Vec<Line> = Vec::new();

    match screen.outcome.as_ref() {
        None => {
            // The phases in reverse: whichever the run reached last is the
            // one it is in.
            let phase = events.iter().rev().find_map(|event| match event {
                RunEvent::Archived { archived } => {
                    Some(format!(" Archived {archived} messages."))
                }
                RunEvent::Archiving { messages, emails } => Some(format!(
                    " Archiving {messages} messages from {emails} emails\u{2026}"
                )),
                _ => None,
            });
            lines.push(Line::styled(
                phase.unwrap_or_else(|| " Unsubscribing\u{2026}".to_string()),
                Style::default().fg(Color::Cyan),
            ));
        }
        Some(Err(message)) => {
            lines.push(Line::styled(
                format!(" Archive failed: {message}"),
                Style::default().fg(Color::Red).bold(),
            ));
            lines.push(Line::styled(
                " Every unsubscribe already made is still recorded in the history.",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Some(Ok(outcome)) => {
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(
                    format!("{} succeeded", outcome.succeeded()),
                    Style::default().fg(Color::Green).bold(),
                ),
                Span::raw(", "),
                Span::styled(
                    format!("{} failed", outcome.failed()),
                    Style::default().fg(if outcome.failed() > 0 {
                        Color::Red
                    } else {
                        Color::DarkGray
                    }),
                ),
                Span::raw(", "),
                Span::styled(
                    format!("{} archived only", screen.counts.archive_only),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(", "),
                Span::styled(
                    format!("{} exhausted", screen.counts.exhausted),
                    Style::default().fg(if screen.counts.exhausted > 0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]));
            lines.push(Line::styled(
                format!(" {} messages archived.", outcome.archived),
                Style::default().fg(Color::DarkGray),
            ));
            if outcome.cancelled {
                lines.push(Line::styled(
                    " Cancelled: the senders not reached were left exactly as they were.",
                    Style::default().fg(Color::Yellow),
                ));
            }
            if !screen.counts.exhausted_senders.is_empty() {
                lines.push(Line::styled(
                    format!(
                        " No method left for: {}",
                        truncate(&screen.counts.exhausted_senders.join(", "), 90)
                    ),
                    Style::default().fg(Color::Yellow),
                ));
            }
        }
    }

    if let Some(warning) = warnings.last() {
        lines.push(Line::styled(
            format!(" {warning}"),
            Style::default().fg(Color::Yellow),
        ));
    }

    Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" Results "))
}

/// The full record of one attempt, for a failure worth reading.
fn render_detail(f: &mut Frame, event: &RunEvent) {
    let RunEvent::Sender {
        email,
        success,
        method,
        detail,
        escalation,
    } = event
    else {
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("  sender   ", Style::default().fg(Color::DarkGray)),
            Span::raw(email.clone()),
        ]),
        Line::from(vec![
            Span::styled("  method   ", Style::default().fg(Color::DarkGray)),
            Span::raw(method.clone()),
        ]),
        Line::from(vec![
            Span::styled("  result   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if *success { "succeeded" } else { "failed" }.to_string(),
                Style::default().fg(if *success { Color::Green } else { Color::Red }),
            ),
        ]),
        Line::from(vec![
            Span::styled("  detail   ", Style::default().fg(Color::DarkGray)),
            Span::raw(detail.clone()),
        ]),
    ];
    if let Some(escalation) = escalation {
        lines.push(Line::from(vec![
            Span::styled("  ladder   ", Style::default().fg(Color::DarkGray)),
            Span::raw(escalation.clone()),
        ]));
    }

    let area = centered(f.area(), 78, lines.len() as u16 + 2);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Attempt "),
        ),
        area,
    );
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}
