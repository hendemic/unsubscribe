//! The Scan screen: what the mailbox scan is doing, while it does it.
//!
//! The screen owns no scanning. A worker thread runs the core stage and
//! writes into a shared snapshot ([`ScanShared`]); this reads it every frame
//! and asks for a stop by setting the flag the port polls.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::ObtainedSenders;

use super::app::{Effect, Nav};
use super::worker::{ScanOutcome, ScanShared};

/// Where the scan has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Running,
    /// Cancel has been asked for; the worker stops at its next batch.
    Cancelling,
    Ended,
}

/// How the scan ended, for the shell to act on.
pub enum ScanEnded {
    Done(Box<ObtainedSenders>),
    /// Nothing was written: the cache from the last complete scan stands.
    Cancelled,
    Failed(String),
}

pub struct ScanScreen {
    shared: Arc<ScanShared>,
    outcome: Receiver<ScanOutcome>,
    state: ScanState,
    started: Instant,
    ended: Option<ScanEnded>,
}

impl ScanScreen {
    #[must_use]
    pub fn new(shared: Arc<ScanShared>, outcome: Receiver<ScanOutcome>) -> Self {
        Self {
            shared,
            outcome,
            state: ScanState::Running,
            started: Instant::now(),
            ended: None,
        }
    }

    /// Take the ending, once [`ScanState::Ended`] says there is one.
    #[must_use]
    pub fn into_ended(self) -> ScanEnded {
        self.ended
            .unwrap_or_else(|| ScanEnded::Failed("The scan ended without a result.".to_string()))
    }

    /// Ask the worker to stop. It does so at its next batch boundary.
    pub fn request_cancel(&mut self) {
        self.shared.cancel();
        self.state = ScanState::Cancelling;
    }

    /// Poll the worker. Called once a frame by the shell.
    pub fn tick(&mut self) -> Nav {
        if self.state == ScanState::Ended {
            return Nav::Stay;
        }
        self.ended = match self.outcome.try_recv() {
            Ok(ScanOutcome::Done(obtained)) => Some(ScanEnded::Done(obtained)),
            Ok(ScanOutcome::Cancelled) => Some(ScanEnded::Cancelled),
            Ok(ScanOutcome::Failed(message)) => Some(ScanEnded::Failed(message)),
            Err(TryRecvError::Empty) => return Nav::Stay,
            // The thread went away without reporting, which only a panic
            // escaping `catch_unwind` can do. Say so rather than hang.
            Err(TryRecvError::Disconnected) => Some(ScanEnded::Failed(
                "The scan stopped without reporting a result.".to_string(),
            )),
        };
        self.state = ScanState::Ended;
        Nav::Effect(Effect::ScanEnded)
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        match key.code {
            // Already stopping: asking again would change nothing.
            KeyCode::Esc | KeyCode::Char('q') if self.state == ScanState::Running => {
                Nav::Effect(Effect::ConfirmCancelScan)
            }
            _ => Nav::Stay,
        }
    }

    pub fn hints(&self) -> &'static str {
        match self.state {
            ScanState::Running => " Esc: cancel the scan | ?: keys",
            ScanState::Cancelling => " stopping at the next batch\u{2026}",
            ScanState::Ended => " finishing\u{2026}",
        }
    }

    pub fn keys(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("Esc / q", "cancel the scan"),
            ("?", "show this help"),
        ]
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render(f: &mut Frame, area: Rect, screen: &ScanScreen) {
    let folders = screen.shared.folders();
    let (senders, warnings) = screen.shared.totals();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // per-folder bars
            Constraint::Length(4), // totals
        ])
        .split(area);

    let bars: Vec<Line> = folders
        .iter()
        .map(|folder| {
            let style = if folder.done {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Cyan)
            };
            Line::from(vec![
                Span::styled(format!(" {:<16}", truncate(&folder.name, 16)), style),
                Span::styled(bar(folder.scanned, folder.total), style),
                Span::styled(
                    format!("  {}/{}", folder.scanned, folder.total),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();

    let body = if bars.is_empty() {
        vec![Line::styled(
            " Connecting\u{2026}",
            Style::default().fg(Color::DarkGray),
        )]
    } else {
        bars
    };
    f.render_widget(
        Paragraph::new(body).block(
            Block::default()
                .borders(Borders::ALL)
                .title(match screen.state {
                    ScanState::Cancelling => " Scanning \u{2014} stopping ",
                    _ => " Scanning ",
                }),
        ),
        chunks[0],
    );

    let scanned: u32 = folders.iter().map(|folder| folder.scanned).sum();
    let elapsed = screen.started.elapsed().as_secs();
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::raw(" "),
                Span::styled(senders.to_string(), Style::default().fg(Color::Cyan).bold()),
                Span::raw(" senders with unsubscribe links, "),
                Span::styled(
                    warnings.to_string(),
                    Style::default().fg(if warnings > 0 {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    }),
                ),
                Span::raw(" unparseable header(s)"),
            ]),
            Line::styled(
                format!(" {scanned} messages read, {elapsed}s elapsed"),
                Style::default().fg(Color::DarkGray),
            ),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Found ")),
        chunks[1],
    );
}

/// A fixed-width progress bar. An unknown total draws as empty rather than
/// full, which is the honest reading of "we do not know yet".
fn bar(done: u32, total: u32) -> String {
    const WIDTH: usize = 30;
    let filled = if total == 0 {
        0
    } else {
        (done as usize * WIDTH / total as usize).min(WIDTH)
    };
    format!("[{}{}]", "=".repeat(filled), " ".repeat(WIDTH - filled))
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => s[..byte_idx].to_string(),
        None => s.to_string(),
    }
}
