//! Pieces every screen borrows: the modal dialogs, the help overlay, and the
//! transient status line.
//!
//! State and rendering are separate here too. A [`Dialog`] answers keys
//! without a terminal, so the "are you sure" path can be driven from a test;
//! the `render_*` functions are the only part that needs a [`Frame`].

use std::time::{Duration, Instant};

use crossterm::event::KeyEvent;
use ratatui::prelude::*;
use ratatui::widgets::*;

use super::keys::{self, Action};

/// Width of the key column in the help overlay: a right-aligned key, padded.
const KEY_COLUMN: usize = 15;

/// How long a transient status message stays on screen.
const STATUS_TTL: Duration = Duration::from_secs(4);

/// An action row the cursor can land on, drawn the way Settings draws its
/// `[ Re-authenticate ]` row so a button looks the same everywhere.
///
/// Whether it has the cursor is the screen's business, not this function's:
/// the row is part of the screen's state so `Enter` can act on it.
#[must_use]
pub fn button_line(label: &str, focused: bool) -> Line<'static> {
    let style = if focused {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    } else {
        Style::default().fg(Color::Cyan)
    };
    Line::styled(format!("   [ {label} ]"), style)
}

/// The same row as its own widget, for a screen that gives it a line of the
/// layout rather than a row of a list.
#[must_use]
pub fn button(label: &str, focused: bool) -> Paragraph<'static> {
    Paragraph::new(button_line(label, focused))
}

/// A modal question or notice, drawn over whatever screen is beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    pub kind: DialogKind,
    pub title: String,
    pub body: Vec<String>,
    /// An extra yes/no the dialog carries, shown as a checkbox and toggled
    /// with `d`. Used for the run confirmation's dry-run switch.
    pub toggle: Option<DialogToggle>,
    /// Footer hints, when the default wording would misdescribe the choice
    /// (a two-way question where "no" is an action of its own).
    pub hints: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogKind {
    /// Enter or `y` confirms, Esc or `n` declines.
    Confirm,
    /// Any key dismisses. Drawn in red.
    Error,
}

/// A labelled switch on a confirm dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogToggle {
    pub label: String,
    pub on: bool,
}

/// What a keypress did to a dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogOutcome {
    /// The dialog stays open.
    Open,
    /// The user said yes (or acknowledged an error).
    Confirmed,
    /// The user said no, or pressed Esc.
    Dismissed,
}

impl Dialog {
    /// A yes/no question.
    pub fn confirm(title: impl Into<String>, body: impl IntoIterator<Item = String>) -> Self {
        Self {
            kind: DialogKind::Confirm,
            title: title.into(),
            body: body.into_iter().collect(),
            toggle: None,
            hints: None,
        }
    }

    /// A failure the user has to acknowledge. Errors are never swallowed into
    /// the status line: a dead screen with no explanation is the worst outcome.
    pub fn error(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: DialogKind::Error,
            title: title.into(),
            body: wrapped_lines(&message.into()),
            toggle: None,
            hints: None,
        }
    }

    /// Add a switch the user can flip before confirming.
    #[must_use]
    pub fn with_toggle(mut self, label: impl Into<String>, on: bool) -> Self {
        self.toggle = Some(DialogToggle {
            label: label.into(),
            on,
        });
        self
    }

    /// Replace the footer wording.
    #[must_use]
    pub fn with_hints(mut self, hints: impl Into<String>) -> Self {
        self.hints = Some(hints.into());
        self
    }

    /// Whether the dialog's switch is on. False when it has no switch.
    pub fn toggled(&self) -> bool {
        self.toggle.as_ref().is_some_and(|t| t.on)
    }

    /// Apply one keypress.
    ///
    /// The same key map every panel uses, so a question answers `y`/`Enter`
    /// and `n`/`Esc` exactly as the footer says -- and `q` does nothing here,
    /// because `q` is never "back".
    pub fn on_key(&mut self, key: KeyEvent) -> DialogOutcome {
        // Anything dismisses a notice, so there is no wrong key to press.
        if self.kind == DialogKind::Error {
            return DialogOutcome::Confirmed;
        }
        match keys::action(key, false) {
            Some(Action::Mnemonic('d')) if self.toggle.is_some() => {
                if let Some(toggle) = self.toggle.as_mut() {
                    toggle.on = !toggle.on;
                }
                DialogOutcome::Open
            }
            Some(Action::Activate | Action::Mnemonic('y')) => DialogOutcome::Confirmed,
            Some(Action::Back | Action::Mnemonic('n')) => DialogOutcome::Dismissed,
            _ => DialogOutcome::Open,
        }
    }

    /// The footer hint while this dialog is up.
    pub fn hints(&self) -> &str {
        if let Some(hints) = &self.hints {
            return hints;
        }
        match self.kind {
            DialogKind::Confirm if self.toggle.is_some() => {
                " Enter/y: confirm | d: toggle dry run | Esc/n: cancel"
            }
            DialogKind::Confirm => " Enter/y: confirm | Esc/n: cancel",
            DialogKind::Error => " any key: dismiss",
        }
    }
}

/// A message that shows for a few seconds and then goes away on its own.
#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub kind: StatusKind,
    shown_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Success,
    Warning,
}

impl StatusMessage {
    pub fn new(kind: StatusKind, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind,
            shown_at: Instant::now(),
        }
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self::new(StatusKind::Success, text)
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(StatusKind::Warning, text)
    }

    /// Whether the message has outlived its welcome.
    pub fn expired(&self) -> bool {
        self.shown_at.elapsed() > STATUS_TTL
    }

    fn color(&self) -> Color {
        match self.kind {
            StatusKind::Success => Color::Green,
            StatusKind::Warning => Color::Yellow,
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Draw a dialog centred over the whole frame, clearing what is under it.
pub fn render_dialog(f: &mut Frame, dialog: &Dialog) {
    let lines: Vec<Line> = dialog
        .body
        .iter()
        .map(|line| Line::raw(format!(" {line}")))
        .chain(dialog.toggle.iter().map(|toggle| {
            let checkbox = if toggle.on { "[x]" } else { "[ ]" };
            Line::styled(
                format!(" {checkbox} {}", toggle.label),
                Style::default().fg(Color::Yellow),
            )
        }))
        .collect();

    let height = (lines.len() as u16 + 4).min(f.area().height);
    let width = lines
        .iter()
        .map(Line::width)
        .chain(std::iter::once(dialog.title.len() + 4))
        .max()
        .unwrap_or(40) as u16;
    let area = centered(f.area(), (width + 4).clamp(30, 90), height.max(5));

    let accent = match dialog.kind {
        DialogKind::Error => Color::Red,
        DialogKind::Confirm => Color::Yellow,
    };

    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(accent))
                .title(format!(" {} ", dialog.title)),
        ),
        area,
    );
}

/// Draw the help overlay: the keys the current screen answers to.
pub fn render_help(f: &mut Frame, screen_title: &str, keys: &[(&str, &str)]) {
    // The key column is padded to a fixed width, so the widest row is that
    // plus the longest description, plus the two borders. Counted in chars:
    // the arrows are multi-byte and `len()` would over-measure them.
    let width = keys
        .iter()
        .map(|(_, what)| KEY_COLUMN + what.chars().count() + 3)
        .max()
        .unwrap_or(40)
        .clamp(34, 90) as u16;
    let lines: Vec<Line> = keys
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(
                    format!(" {key:>width$}  ", width = KEY_COLUMN - 3),
                    Style::default().fg(Color::Yellow).bold(),
                ),
                Span::raw((*what).to_string()),
            ])
        })
        .collect();
    let height = (lines.len() as u16 + 2).min(f.area().height);
    let area = centered(f.area(), width, height);

    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" Keys \u{2014} {screen_title} ")),
        ),
        area,
    );
}

/// Draw a transient status message on one line.
pub fn render_status(f: &mut Frame, area: Rect, status: &StatusMessage) {
    f.render_widget(
        Paragraph::new(format!(" {}", status.text))
            .style(Style::default().fg(status.color()))
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// A `width` x `height` rectangle in the middle of `area`, clamped to fit.
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

/// Split a message into lines a dialog can show, honouring the newlines the
/// error already has. `anyhow` contexts arrive multi-line and pre-formatted.
fn wrapped_lines(message: &str) -> Vec<String> {
    message.lines().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn confirm() -> Dialog {
        Dialog::confirm("Confirm run", ["3 senders.".to_string()])
    }

    // -- confirming and declining -------------------------------------------

    #[test]
    fn enter_and_y_confirm_a_question() {
        for code in [KeyCode::Enter, KeyCode::Char('y')] {
            assert_eq!(
                confirm().on_key(key(code)),
                DialogOutcome::Confirmed,
                "{code:?} should confirm"
            );
        }
    }

    #[test]
    fn esc_and_n_decline_a_question() {
        for code in [KeyCode::Esc, KeyCode::Char('n')] {
            assert_eq!(
                confirm().on_key(key(code)),
                DialogOutcome::Dismissed,
                "{code:?} should decline"
            );
        }
    }

    #[test]
    fn a_key_that_means_nothing_leaves_the_question_open() {
        assert_eq!(confirm().on_key(key(KeyCode::Char('z'))), DialogOutcome::Open);
        assert_eq!(confirm().on_key(key(KeyCode::Down)), DialogOutcome::Open);
        // q is never "back": it would be a silent cancel here.
        assert_eq!(confirm().on_key(key(KeyCode::Char('q'))), DialogOutcome::Open);
    }

    #[test]
    fn any_key_at_all_dismisses_an_error() {
        // There is no wrong key to press on a notice.
        for code in [KeyCode::Char('x'), KeyCode::Esc, KeyCode::Enter, KeyCode::Up] {
            let mut dialog = Dialog::error("Scan failed", "connection refused");
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Confirmed);
        }
    }

    #[test]
    fn an_error_keeps_the_line_breaks_the_message_arrived_with() {
        let dialog = Dialog::error("Scan failed", "could not connect\n\nCheck the host.");

        assert_eq!(dialog.body, ["could not connect", "", "Check the host."]);
    }

    // -- the dry-run switch --------------------------------------------------

    #[test]
    fn a_question_with_no_switch_is_never_toggled_on() {
        let mut dialog = confirm();

        assert_eq!(dialog.on_key(key(KeyCode::Char('d'))), DialogOutcome::Open);
        assert!(!dialog.toggled(), "d is not a switch when there is none");
    }

    #[test]
    fn d_flips_the_switch_without_answering_the_question() {
        let mut dialog = confirm().with_toggle("Dry run", false);

        assert_eq!(dialog.on_key(key(KeyCode::Char('d'))), DialogOutcome::Open);
        assert!(dialog.toggled());
        assert_eq!(dialog.on_key(key(KeyCode::Char('d'))), DialogOutcome::Open);
        assert!(!dialog.toggled(), "and flips back");
    }

    #[test]
    fn the_switch_survives_until_the_question_is_answered() {
        let mut dialog = confirm().with_toggle("Dry run", false);

        dialog.on_key(key(KeyCode::Char('d')));
        dialog.on_key(key(KeyCode::Char('x')));
        assert_eq!(dialog.on_key(key(KeyCode::Enter)), DialogOutcome::Confirmed);
        assert!(
            dialog.toggled(),
            "the shell reads the switch after the answer, so it has to still be there"
        );
    }

    #[test]
    fn a_switch_can_start_on() {
        let dialog = confirm().with_toggle("Dry run", true);

        assert!(dialog.toggled());
    }

    // -- footer wording ------------------------------------------------------

    #[test]
    fn a_question_with_a_switch_says_so_in_the_footer() {
        assert!(confirm().with_toggle("Dry run", false).hints().contains("dry run"));
        assert!(!confirm().hints().contains("dry run"));
    }

    #[test]
    fn replacement_hints_win_over_the_default_wording() {
        let dialog = confirm().with_hints(" y: use the cached scan | n/Esc: scan again");

        assert_eq!(dialog.hints(), " y: use the cached scan | n/Esc: scan again");
    }

    // -- transient status ----------------------------------------------------

    #[test]
    fn a_fresh_status_message_has_not_expired() {
        assert!(!StatusMessage::success("Re-authenticated.").expired());
        assert!(!StatusMessage::warning("Nothing selected.").expired());
    }

    #[test]
    fn a_status_message_keeps_the_kind_it_was_made_with() {
        assert_eq!(StatusMessage::success("ok").kind, StatusKind::Success);
        assert_eq!(StatusMessage::warning("careful").kind, StatusKind::Warning);
    }
}
