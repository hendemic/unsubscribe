//! Pieces every screen borrows: the modal dialogs, the help overlay, and the
//! transient status line.
//!
//! State and rendering are separate here too. A [`Dialog`] answers keys
//! without a terminal, so the "are you sure" path can be driven from a test;
//! the `render_*` functions are the only part that needs a [`Frame`].

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;

/// How long a transient status message stays on screen.
const STATUS_TTL: Duration = Duration::from_secs(4);

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
    /// Any key dismisses. Drawn in the normal accent.
    Notice,
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
    /// The user said yes (or dismissed a notice).
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

    /// Something worth a modal that is not a failure.
    pub fn notice(title: impl Into<String>, body: impl IntoIterator<Item = String>) -> Self {
        Self {
            kind: DialogKind::Notice,
            title: title.into(),
            body: body.into_iter().collect(),
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
    pub fn on_key(&mut self, key: KeyEvent) -> DialogOutcome {
        match self.kind {
            // Anything dismisses a notice, so there is no wrong key to press.
            DialogKind::Error | DialogKind::Notice => DialogOutcome::Confirmed,
            DialogKind::Confirm => match key.code {
                KeyCode::Char('d') if self.toggle.is_some() => {
                    if let Some(toggle) = self.toggle.as_mut() {
                        toggle.on = !toggle.on;
                    }
                    DialogOutcome::Open
                }
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    DialogOutcome::Confirmed
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => {
                    DialogOutcome::Dismissed
                }
                _ => DialogOutcome::Open,
            },
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
            DialogKind::Error | DialogKind::Notice => " any key: dismiss",
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
        DialogKind::Notice => Color::Cyan,
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
    let width = keys
        .iter()
        .map(|(key, what)| key.len() + what.len() + 6)
        .max()
        .unwrap_or(40)
        .clamp(34, 70) as u16;
    let lines: Vec<Line> = keys
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(
                    format!(" {key:>12}  "),
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
