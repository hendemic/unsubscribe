//! The Scan screen: what the mailbox scan is doing, while it does it.
//!
//! The screen owns no scanning. A worker thread runs the core stage and
//! writes into a shared snapshot ([`ScanShared`]); this reads it every frame
//! and asks for a stop by setting the flag the port polls.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Instant;

use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::ObtainedSenders;

use super::app::{Effect, Nav};
use super::keys::Action;
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

    pub fn on_action(&mut self, action: Action) -> Nav {
        match action {
            // Esc asks before throwing the work away; already stopping,
            // asking again would change nothing.
            Action::Back if self.state == ScanState::Running => {
                Nav::Effect(Effect::ConfirmCancelScan)
            }
            _ => Nav::Stay,
        }
    }

    /// The actions this sub-view answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        match self.state {
            ScanState::Running => vec![Action::Help, Action::Back],
            _ => vec![Action::Help],
        }
    }

    /// A word for what the scan is doing, for the working area's title.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        match self.state {
            ScanState::Running => "scanning",
            ScanState::Cancelling => "stopping at the next batch",
            ScanState::Ended => "finishing",
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    use super::super::app::Effect;

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Quit => "quit",
            Nav::Effect(Effect::ScanEnded) => "scan ended",
            Nav::Effect(Effect::ConfirmCancelScan) => "confirm cancel",
            Nav::Effect(_) => "other effect",
        }
    }

    fn obtained(count: usize) -> Box<ObtainedSenders> {
        Box::new(ObtainedSenders {
            senders: (0..count)
                .map(|i| unsubscribe_core::SenderInfo {
                    display_name: "Acme News".to_string(),
                    email: format!("s{i}@acme.example.com"),
                    domain: "acme.example.com".to_string(),
                    unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
                    unsubscribe_mailto: Vec::new(),
                    one_click: true,
                    list_id: None,
                    list_unsubscribe_raw: None,
                    email_count: 3,
                    messages: Vec::new(),
                    last_seen: None,
                })
                .collect(),
            warnings: Vec::new(),
            scanned_at: "2026-06-01T09:00:00Z".to_string(),
            from_cache: false,
        })
    }

    /// A screen whose worker has already reported `outcome`.
    fn ended_with(outcome: ScanOutcome) -> ScanScreen {
        let (tx, rx) = mpsc::channel();
        tx.send(outcome).expect("the screen is listening");
        ScanScreen::new(ScanShared::new(), rx)
    }

    /// A screen with a worker that is still going.
    fn running() -> (ScanScreen, mpsc::Sender<ScanOutcome>) {
        let (tx, rx) = mpsc::channel();
        (ScanScreen::new(ScanShared::new(), rx), tx)
    }

    #[test]
    fn a_scan_that_has_not_reported_yet_asks_the_shell_for_nothing() {
        let (mut screen, _tx) = running();

        assert_eq!(nav_name(&screen.tick()), "stay");
        assert_eq!(screen.state, ScanState::Running);
    }

    #[test]
    fn esc_while_scanning_asks_before_stopping() {
        let (mut screen, _tx) = running();

        assert_eq!(nav_name(&screen.on_action(Action::Back)), "confirm cancel");
        // q is never "back", so it cannot silently abandon a scan.
        assert_eq!(nav_name(&screen.on_action(Action::Quit)), "stay");
    }

    #[test]
    fn cancelling_raises_the_flag_the_adapter_polls() {
        let (tx, rx) = mpsc::channel::<ScanOutcome>();
        let shared = ScanShared::new();
        let mut screen = ScanScreen::new(Arc::clone(&shared), rx);

        screen.request_cancel();

        assert!(shared.cancel_requested());
        assert_eq!(screen.state, ScanState::Cancelling);
        drop(tx);
    }

    #[test]
    fn asking_to_stop_a_second_time_changes_nothing() {
        let (mut screen, _tx) = running();
        screen.request_cancel();

        assert_eq!(nav_name(&screen.on_action(Action::Back)), "stay");
        assert_eq!(screen.state, ScanState::Cancelling);
    }

    #[test]
    fn a_completed_scan_hands_its_senders_to_the_shell() {
        let mut screen = ended_with(ScanOutcome::Done(obtained(3)));

        assert_eq!(nav_name(&screen.tick()), "scan ended");
        assert_eq!(screen.state, ScanState::Ended);
        match screen.into_ended() {
            ScanEnded::Done(obtained) => assert_eq!(obtained.senders.len(), 3),
            _ => panic!("expected a completed scan"),
        }
    }

    #[test]
    fn a_cancelled_scan_ends_as_cancelled_not_as_a_failure() {
        let mut screen = ended_with(ScanOutcome::Cancelled);

        assert_eq!(nav_name(&screen.tick()), "scan ended");
        assert!(matches!(screen.into_ended(), ScanEnded::Cancelled));
    }

    #[test]
    fn a_failed_scan_carries_its_message_to_the_dialog() {
        let mut screen = ended_with(ScanOutcome::Failed("connection refused".to_string()));

        screen.tick();

        match screen.into_ended() {
            ScanEnded::Failed(message) => assert_eq!(message, "connection refused"),
            _ => panic!("expected a failure"),
        }
    }

    #[test]
    fn a_worker_that_dies_without_reporting_becomes_a_failure_rather_than_a_hang() {
        let (tx, rx) = mpsc::channel::<ScanOutcome>();
        let mut screen = ScanScreen::new(ScanShared::new(), rx);
        drop(tx);

        assert_eq!(nav_name(&screen.tick()), "scan ended");
        assert!(matches!(screen.into_ended(), ScanEnded::Failed(_)));
    }

    #[test]
    fn the_ending_is_announced_once_however_many_frames_are_drawn() {
        let mut screen = ended_with(ScanOutcome::Cancelled);

        assert_eq!(nav_name(&screen.tick()), "scan ended");
        assert_eq!(nav_name(&screen.tick()), "stay");
        assert_eq!(nav_name(&screen.tick()), "stay");
    }

    #[test]
    fn a_screen_taken_apart_before_it_ended_says_so_rather_than_panicking() {
        let (screen, _tx) = running();

        assert!(matches!(screen.into_ended(), ScanEnded::Failed(_)));
    }

    #[test]
    fn a_cancelled_scan_that_then_reports_still_ends_as_cancelled() {
        let (tx, rx) = mpsc::channel();
        let shared = ScanShared::new();
        let mut screen = ScanScreen::new(Arc::clone(&shared), rx);

        screen.request_cancel();
        tx.send(ScanOutcome::Cancelled).expect("listening");
        screen.tick();

        assert!(matches!(screen.into_ended(), ScanEnded::Cancelled));
    }

    #[test]
    fn the_working_area_says_what_the_scan_is_doing() {
        let (mut screen, _tx) = running();
        assert_eq!(screen.state_label(), "scanning");
        assert!(screen.actions().contains(&Action::Back), "cancel is offered");

        screen.request_cancel();
        assert!(screen.state_label().contains("stopping"));
        assert!(
            !screen.actions().contains(&Action::Back),
            "asking again would change nothing"
        );
    }
}
