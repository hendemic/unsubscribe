//! The Run screen: each sender's attempt as it completes, then the archive,
//! then what happened.
//!
//! Like the scan screen, this owns no pipeline. A worker thread runs
//! [`unsubscribe_core::execute_run`] and appends to a shared log; this reads
//! it every frame. Cancelling sets the flag the run observer polls between
//! senders, which is why an attempt is never abandoned half-made.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;

use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{RunOutcome, RunPlan};

use super::app::{Effect, Nav};
use super::keys::{self, Action};
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
    /// Whether the action button below the list has the cursor rather than an
    /// attempt row. It starts with it: while a run is going there is nothing
    /// worth browsing yet, and stopping should not need the hotkey.
    on_button: bool,
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
            on_button: true,
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

    /// Whether a worker is still out there, for the shell's "there is work in
    /// flight" questions (the nav marker, and quitting).
    #[must_use]
    pub fn is_working(&self) -> bool {
        self.state != RunState::Finished
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

    /// The action row under the list, and what it says it does. `None` while
    /// the run is already stopping: there is nothing left for it to do.
    #[must_use]
    pub fn button(&self) -> Option<&'static str> {
        match self.state {
            RunState::Running => Some("Stop run"),
            RunState::Cancelling => None,
            RunState::Finished => Some("Close"),
        }
    }

    /// Whether the button is what `Enter` would act on right now.
    #[must_use]
    pub fn button_focused(&self) -> bool {
        self.on_button && self.button().is_some()
    }

    /// Move between the attempt rows and the button below them.
    ///
    /// The button sits one row past the end of the list, so `End`/`G` and
    /// pressing down past the last attempt both land on it, and moving up
    /// from it takes hold of the list.
    fn move_cursor(&mut self, action: Action) -> bool {
        let attempts = self.attempts().len();
        let last = attempts.saturating_sub(1);

        if self.on_button {
            if keys::is_backwards(action) && attempts > 0 {
                self.on_button = false;
                self.cursor = match action {
                    Action::First => 0,
                    _ => last,
                };
            }
            return keys::move_cursor(action, 0, 0).is_some();
        }
        let Some(cursor) = keys::move_cursor(action, self.cursor, last) else {
            return false;
        };
        // Past the bottom of the list is the button, not a clamp.
        self.on_button =
            !keys::is_backwards(action) && (cursor == self.cursor || action == Action::Last);
        self.cursor = cursor;
        true
    }

    pub fn on_action(&mut self, action: Action) -> Nav {
        // The inspection pop-up is one level of its own: Esc closes it before
        // anything else can read the key.
        if self.detail.is_some() {
            if matches!(action, Action::Back | Action::Activate) {
                self.detail = None;
            }
            return Nav::Stay;
        }
        if self.move_cursor(action) {
            return Nav::Stay;
        }
        match action {
            // The button and `c` are the same action; a sender row keeps its
            // own meaning of "show me this attempt".
            Action::Activate if self.button_focused() => self.cancel(),
            Action::Activate if self.state == RunState::Finished => {
                self.detail = Some(self.cursor);
                Nav::Stay
            }
            // Esc parks the run rather than ending it: the worker carries on
            // and the nav becomes reachable while it does.
            Action::Back => Nav::Park,
            Action::Mnemonic('c') => self.cancel(),
            _ => Nav::Stay,
        }
    }

    /// What `c` and the button both do.
    fn cancel(&mut self) -> Nav {
        match self.state {
            RunState::Running => Nav::Effect(Effect::ConfirmCancelRun),
            // Already stopping: asking again would change nothing.
            RunState::Cancelling => Nav::Stay,
            // Nothing left to stop; the results close back to the panel,
            // whose counts are already refreshed by then.
            RunState::Finished => Nav::Pop,
        }
    }

    /// The actions this sub-view answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Action> {
        if self.detail.is_some() {
            return vec![Action::Back];
        }
        match self.state {
            RunState::Cancelling => vec![Action::Help, Action::Back],
            _ => keys::list_actions(&[Action::Activate, Action::Mnemonic('c')]),
        }
    }

    /// A word for what the run is doing, for the working area's title.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        match self.state {
            RunState::Running => "running",
            RunState::Cancelling => "stopping after the current sender",
            RunState::Finished => "finished",
        }
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
    // cursor follows it until the user takes hold of the list.
    if screen.state == RunState::Running && screen.on_button {
        screen.cursor = attempts.len().saturating_sub(1);
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(u16::from(screen.button().is_some())),
            Constraint::Length(6),
        ])
        .split(area);

    let height = (chunks[0].height as usize).saturating_sub(2);
    screen.scroll_into_view(height);

    let rows: Vec<Line> = attempts
        .iter()
        .enumerate()
        .skip(screen.scroll_offset)
        .take(height)
        .map(|(index, event)| {
            attempt_row(event, index == screen.cursor && !screen.button_focused())
        })
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

    if let Some(label) = screen.button() {
        f.render_widget(
            super::components::button(label, screen.button_focused()),
            chunks[1],
        );
    }

    f.render_widget(footer(screen, &events), chunks[2]);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use unsubscribe_core::{
        Folder, FolderMessage, MessageId, NextStep, PlannedSender, RunOutcome, SenderInfo,
    };

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Park => "park",
            Nav::Quit => "quit",
            Nav::Effect(Effect::RunEnded) => "run ended",
            Nav::Effect(Effect::ConfirmCancelRun) => "confirm cancel",
            Nav::Effect(_) => "other effect",
        }
    }

    fn sender(email: &str, messages: u32) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: messages,
            messages: (0..messages)
                .map(|i| FolderMessage {
                    folder: Folder::new("INBOX"),
                    message_id: MessageId::new(format!("INBOX:{email}:{i}")),
                })
                .collect(),
            last_seen: None,
        }
    }

    /// A screen with `attempts` sender rows already in its shared log.
    fn screen_with(attempts: usize) -> (RunScreen, Arc<RunShared>, mpsc::Sender<RunResult>) {
        let shared = RunShared::new();
        for i in 0..attempts {
            shared.push(RunEvent::Sender {
                email: format!("s{i}@acme.example.com"),
                success: true,
                method: "one-click POST".to_string(),
                detail: "HTTP 200".to_string(),
                escalation: None,
            });
        }
        // Rows the cursor must not be able to land on.
        shared.push(RunEvent::Archiving {
            messages: 6,
            emails: 2,
        });
        let (tx, rx) = mpsc::channel();
        let screen = RunScreen::new(Arc::clone(&shared), rx, PlanCounts::default(), false);
        (screen, shared, tx)
    }

    fn finished(result: RunResult) -> RunScreen {
        let (mut screen, _shared, tx) = screen_with(2);
        tx.send(result).expect("the screen is listening");
        screen.tick();
        screen
    }

    // -- ending --------------------------------------------------------------

    #[test]
    fn a_run_that_has_not_reported_yet_asks_the_shell_for_nothing() {
        let (mut screen, _shared, _tx) = screen_with(1);

        assert_eq!(nav_name(&screen.tick()), "stay");
        assert_eq!(screen.state, RunState::Running);
    }

    #[test]
    fn a_finished_run_tells_the_shell_to_refresh_what_changed() {
        let (mut screen, _shared, tx) = screen_with(2);
        tx.send(RunResult::Done(Box::default()))
            .expect("listening");

        assert_eq!(nav_name(&screen.tick()), "run ended");
        assert_eq!(screen.state, RunState::Finished);
        assert_eq!(screen.failure(), None, "a clean finish is not a failure");
    }

    #[test]
    fn the_ending_is_announced_once_however_many_frames_are_drawn() {
        let (mut screen, _shared, tx) = screen_with(1);
        tx.send(RunResult::Done(Box::default()))
            .expect("listening");

        assert_eq!(nav_name(&screen.tick()), "run ended");
        assert_eq!(nav_name(&screen.tick()), "stay");
    }

    #[test]
    fn an_archive_that_failed_is_surfaced_as_a_failure_the_shell_can_show() {
        let screen = finished(RunResult::Failed("mailbox refused the move".to_string()));

        assert_eq!(screen.failure(), Some("mailbox refused the move"));
    }

    #[test]
    fn a_worker_that_dies_without_reporting_becomes_a_failure_rather_than_a_hang() {
        let (mut screen, _shared, tx) = screen_with(1);
        drop(tx);

        assert_eq!(nav_name(&screen.tick()), "run ended");
        assert!(screen.failure().is_some());
    }

    // -- cancelling ----------------------------------------------------------

    #[test]
    fn esc_while_running_parks_the_run_rather_than_ending_it() {
        let (mut screen, shared, _tx) = screen_with(1);

        assert_eq!(nav_name(&screen.on_action(Action::Back)), "park");
        assert_eq!(screen.state, RunState::Running);
        assert!(!shared.cancel_requested(), "the worker was left alone");
        // q is never "back", so it cannot silently abandon a run.
        assert_eq!(nav_name(&screen.on_action(Action::Quit)), "stay");
    }

    #[test]
    fn esc_keeps_parking_once_the_run_is_stopping() {
        let (mut screen, _shared, _tx) = screen_with(1);
        screen.request_cancel();

        assert_eq!(nav_name(&screen.on_action(Action::Back)), "park");
        assert_eq!(screen.state, RunState::Cancelling);
    }

    #[test]
    fn c_while_running_asks_before_stopping() {
        let (mut screen, shared, _tx) = screen_with(1);

        assert_eq!(
            nav_name(&screen.on_action(Action::Mnemonic('c'))),
            "confirm cancel"
        );
        assert!(
            !shared.cancel_requested(),
            "nothing is cancelled until the question is answered"
        );
    }

    #[test]
    fn a_letter_the_screen_does_not_offer_does_nothing_at_all() {
        let (mut screen, _shared, _tx) = screen_with(1);

        for c in ['a', 'n', 's', 'd', 'u', 'w', 'x', 'y'] {
            assert_eq!(nav_name(&screen.on_action(Action::Mnemonic(c))), "stay", "{c}");
        }
    }

    #[test]
    fn a_run_is_working_until_its_worker_has_reported() {
        let (mut screen, _shared, _tx) = screen_with(1);
        assert!(screen.is_working());

        screen.request_cancel();
        assert!(screen.is_working(), "the worker has not stopped yet");

        let finished = finished(RunResult::Done(Box::default()));
        assert!(!finished.is_working());
    }

    #[test]
    fn cancelling_raises_the_flag_the_pipeline_polls_between_senders() {
        let (mut screen, shared, _tx) = screen_with(1);

        screen.request_cancel();

        assert!(shared.cancel_requested());
        assert_eq!(screen.state, RunState::Cancelling);
    }

    #[test]
    fn asking_to_stop_a_second_time_changes_nothing() {
        let (mut screen, _shared, _tx) = screen_with(1);
        screen.request_cancel();

        assert_eq!(nav_name(&screen.on_action(Action::Mnemonic('c'))), "stay");
        assert_eq!(screen.state, RunState::Cancelling);
    }

    #[test]
    fn the_working_area_says_the_run_is_stopping_after_the_current_sender() {
        let (mut screen, _shared, _tx) = screen_with(1);
        assert_eq!(screen.state_label(), "running");
        assert!(
            screen.actions().contains(&Action::Mnemonic('c')),
            "cancel is offered"
        );

        screen.request_cancel();

        assert!(
            !screen.actions().contains(&Action::Mnemonic('c')),
            "asking again would change nothing"
        );
        assert!(
            screen.actions().contains(&Action::Back),
            "but the nav is still reachable while it stops"
        );

        assert!(
            screen.state_label().contains("stopping after the current sender"),
            "got {:?}",
            screen.state_label()
        );
    }

    #[test]
    fn the_attempts_already_made_are_still_on_screen_after_cancelling() {
        let (mut screen, _shared, tx) = screen_with(2);
        screen.request_cancel();
        tx.send(RunResult::Done(Box::new(RunOutcome {
            results: Vec::new(),
            archived: 4,
            cancelled: true,
        })))
        .expect("listening");
        screen.tick();

        assert_eq!(
            screen.attempts().len(),
            2,
            "a cancelled run keeps the senders it did attempt"
        );
    }

    // -- leaving -------------------------------------------------------------

    #[test]
    fn esc_over_the_results_parks_them_rather_than_closing_them() {
        // The results are worth coming back to, and the Run workflow's Esc
        // means the same thing on every one of its screens.
        let mut screen = finished(RunResult::Done(Box::default()));

        assert_eq!(nav_name(&screen.on_action(Action::Back)), "park");
    }

    #[test]
    fn c_over_the_results_closes_them_without_asking() {
        // There is no work left to stop and nothing to lose, so the question
        // a running run asks would be noise here.
        let mut screen = finished(RunResult::Done(Box::default()));

        assert_eq!(nav_name(&screen.on_action(Action::Mnemonic('c'))), "pop");
    }

    #[test]
    fn c_closes_a_run_that_ended_badly_just_the_same() {
        let mut screen = finished(RunResult::Failed("mailbox refused".to_string()));

        assert_eq!(nav_name(&screen.on_action(Action::Mnemonic('c'))), "pop");
    }

    // -- the attempt list ----------------------------------------------------

    #[test]
    fn the_cursor_moves_only_over_the_sender_rows() {
        // The log also holds archive rows; they are not attempts and the
        // cursor must not reach them.
        let (mut screen, _shared, _tx) = screen_with(3);
        screen.on_action(Action::First); // take hold of the list

        for _ in 0..10 {
            screen.on_action(Action::MoveDown);
        }

        assert_eq!(screen.cursor, 2, "three attempts, so the last index is 2");
    }

    #[test]
    fn moving_up_stops_at_the_first_attempt() {
        let (mut screen, _shared, _tx) = screen_with(3);
        screen.on_action(Action::MoveUp); // off the button, onto the last row

        for _ in 0..10 {
            screen.on_action(Action::MoveUp);
        }

        assert_eq!(screen.cursor, 0);
        assert!(!screen.button_focused());
    }

    #[test]
    fn g_and_shift_g_jump_to_the_last_row_and_the_first_attempt() {
        let (mut screen, _shared, _tx) = screen_with(4);

        screen.on_action(Action::First);
        assert_eq!(screen.cursor, 0);
        assert!(!screen.button_focused());

        // The button is the last row, so G lands on it rather than on the
        // last attempt -- the same rule every list in the app follows.
        screen.on_action(Action::Last);
        assert!(screen.button_focused());
    }

    // -- the cancel button ---------------------------------------------------

    #[test]
    fn the_button_has_the_cursor_before_the_user_touches_anything() {
        // A run has little else worth focusing, so stopping it must not
        // depend on knowing the hotkey.
        let (screen, _shared, _tx) = screen_with(2);

        assert!(screen.button_focused());
        assert_eq!(screen.button(), Some("Stop run"));
    }

    #[test]
    fn enter_on_the_button_asks_the_same_question_as_c() {
        let (mut screen, _shared, _tx) = screen_with(2);

        assert_eq!(
            nav_name(&screen.on_action(Action::Activate)),
            "confirm cancel"
        );
    }

    #[test]
    fn enter_on_an_attempt_row_still_inspects_it() {
        let mut screen = finished(RunResult::Done(Box::default()));
        screen.on_action(Action::First);

        screen.on_action(Action::Activate);

        assert_eq!(screen.detail, Some(0), "the row, not the button");
    }

    #[test]
    fn moving_up_from_the_button_takes_hold_of_the_list_and_down_gives_it_back() {
        let (mut screen, _shared, _tx) = screen_with(3);

        screen.on_action(Action::MoveUp);
        assert!(!screen.button_focused());
        assert_eq!(screen.cursor, 2, "the last attempt");

        screen.on_action(Action::MoveDown);
        assert!(screen.button_focused(), "past the bottom is the button");
    }

    #[test]
    fn the_button_says_what_it_does_at_each_stage_and_goes_when_there_is_nothing_to_do() {
        let (mut screen, _shared, _tx) = screen_with(1);
        assert_eq!(screen.button(), Some("Stop run"));

        screen.request_cancel();
        assert_eq!(screen.button(), None, "already stopping");
        assert!(!screen.button_focused());
        assert_eq!(nav_name(&screen.on_action(Action::Activate)), "stay");

        let finished = finished(RunResult::Done(Box::default()));
        assert_eq!(finished.button(), Some("Close"));
    }

    #[test]
    fn enter_on_the_results_button_closes_them_without_asking() {
        let mut screen = finished(RunResult::Done(Box::default()));
        screen.on_action(Action::Last); // onto the button

        assert_eq!(nav_name(&screen.on_action(Action::Activate)), "pop");
    }

    #[test]
    fn a_button_that_can_be_pressed_is_a_key_the_screen_advertises() {
        let (screen, _shared, _tx) = screen_with(1);

        assert!(screen.actions().contains(&Action::Activate));
    }

    #[test]
    fn navigating_a_run_with_no_attempts_yet_does_not_panic() {
        let shared = RunShared::new();
        let (_tx, rx) = mpsc::channel();
        let mut screen = RunScreen::new(shared, rx, PlanCounts::default(), false);

        for action in [
            Action::MoveDown,
            Action::MoveUp,
            Action::Last,
            Action::First,
        ] {
            screen.on_action(action);
            assert_eq!(screen.cursor, 0);
            assert!(
                screen.button_focused(),
                "with no attempts the button is all there is to focus"
            );
        }
    }

    // -- the detail overlay --------------------------------------------------

    #[test]
    fn an_attempt_can_only_be_inspected_once_the_run_has_finished() {
        let (mut screen, _shared, _tx) = screen_with(2);
        screen.on_action(Action::First); // off the button, onto a row

        screen.on_action(Action::Activate);

        assert_eq!(screen.detail, None, "the list is still moving");
    }

    #[test]
    fn enter_inspects_the_highlighted_attempt_and_esc_closes_it() {
        let mut screen = finished(RunResult::Done(Box::default()));
        screen.on_action(Action::First);
        screen.on_action(Action::MoveDown);

        screen.on_action(Action::Activate);
        assert_eq!(screen.detail, Some(1));

        // Only the one level: the inspection closes, the screen stays.
        screen.on_action(Action::Toggle);
        assert_eq!(screen.detail, Some(1), "an unrelated key changes nothing");
        screen.on_action(Action::Back);
        assert_eq!(screen.detail, None);
    }

    #[test]
    fn a_key_that_closes_the_detail_does_not_also_leave_the_screen() {
        let mut screen = finished(RunResult::Done(Box::default()));
        screen.on_action(Action::First);
        screen.on_action(Action::Activate);
        assert!(screen.detail.is_some(), "the overlay is up");

        assert_eq!(
            nav_name(&screen.on_action(Action::Back)),
            "stay",
            "Esc closes the overlay; leaving takes a second press"
        );
        assert_eq!(nav_name(&screen.on_action(Action::Back)), "park");
    }

    // -- plan counts ---------------------------------------------------------

    #[test]
    fn the_counts_the_screen_keeps_are_the_plans_own() {
        let plan = RunPlan {
            to_unsubscribe: vec![PlannedSender {
                sender: sender("one@acme.example.com", 2),
                step: NextStep::FirstAttempt,
            }],
            archive_only: vec![sender("stale@acme.example.com", 4)],
            exhausted: vec![sender("spent@acme.example.com", 1)],
        };

        let counts = PlanCounts::of(&plan);

        assert_eq!(counts.to_unsubscribe, 1);
        assert_eq!(counts.archive_only, 1);
        assert_eq!(counts.exhausted, 1);
        assert_eq!(counts.exhausted_senders, ["spent@acme.example.com"]);
    }

    #[test]
    fn an_empty_plan_names_no_exhausted_senders() {
        let counts = PlanCounts::of(&RunPlan::default());

        assert_eq!(counts.to_unsubscribe, 0);
        assert!(counts.exhausted_senders.is_empty());
    }
}
