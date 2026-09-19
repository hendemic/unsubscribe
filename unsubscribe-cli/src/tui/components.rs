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

/// An action row in the working area: a label, and whether pressing it would
/// do anything.
///
/// Part of a screen's state rather than something the renderer invents --
/// `Enter` acts on it, so the key handler has to be able to see it. A
/// disabled button still shows: a scan that is stopping says so where the
/// button was, rather than leaving a hole the eye has to account for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Button {
    pub label: &'static str,
    pub enabled: bool,
}

impl Button {
    #[must_use]
    pub fn new(label: &'static str) -> Self {
        Self {
            label,
            enabled: true,
        }
    }

    /// A row that says what is happening and answers nothing.
    #[must_use]
    pub fn inert(label: &'static str) -> Self {
        Self {
            label,
            enabled: false,
        }
    }
}

/// One action row, drawn the way Settings draws its `[ Re-authenticate ]`
/// row so a button looks the same everywhere.
///
/// A disabled row is never drawn as focused, whatever the cursor is doing:
/// highlighting something that will not answer `Enter` is a lie.
#[must_use]
pub fn button_line(button: Button, focused: bool) -> Line<'static> {
    Line::from(vec![
        Span::raw("   "),
        button_span(button.label, button.enabled, focused),
    ])
}

/// One `[ Label ]` as a span, so a row can hold more than one of them.
///
/// The single place the button style is written: a dialog's buttons and a
/// screen's action row have to be recognisable as the same control.
fn button_span(label: &str, enabled: bool, focused: bool) -> Span<'static> {
    let style = match (enabled, focused) {
        (false, _) => Style::default().fg(Color::DarkGray),
        (true, true) => Style::default().bg(Color::DarkGray).fg(Color::White),
        (true, false) => Style::default().fg(Color::Cyan),
    };
    Span::styled(format!("[ {label} ]"), style)
}

/// The same row as its own widget, for a screen that gives it a line of the
/// layout rather than a row of a list.
#[must_use]
pub fn button(button: Button, focused: bool) -> Paragraph<'static> {
    Paragraph::new(button_line(button, focused))
}

/// A modal question or notice, drawn over whatever screen is beneath it.
///
/// Every question carries its buttons as state rather than as decoration:
/// the keys act on whatever has focus, so the control the user is looking at
/// and the control that answers `Enter` can never come apart. Hotkeys stay
/// accelerators on top of that -- `y`, `n` and `Esc` answer from any focus --
/// because nothing here should be reachable only by knowing a letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    pub kind: DialogKind,
    pub title: String,
    pub body: Vec<String>,
    /// An extra yes/no the dialog carries, shown as a checkbox above the
    /// buttons. Used for the run confirmation's dry-run switch.
    pub toggle: Option<DialogToggle>,
    /// The verb on the button that says yes, so a question names what it is
    /// about to do rather than saying "Confirm".
    pub confirm_label: String,
    pub cancel_label: String,
    /// Which control the keys act on.
    pub focus: DialogFocus,
    /// Which button the row is on, remembered while focus is on the
    /// checkbox so that coming back lands where the user left.
    pub button: DialogButton,
}

/// Which of a dialog's controls the keys act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialogFocus {
    /// The checkbox, when the dialog has one.
    Toggle,
    #[default]
    Button,
}

/// The two buttons every question offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialogButton {
    Cancel,
    /// The default: `Enter` answers a question the way it always has,
    /// without the user first having to walk to a button.
    #[default]
    Confirm,
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
            confirm_label: "Confirm".to_string(),
            cancel_label: "Cancel".to_string(),
            focus: DialogFocus::default(),
            button: DialogButton::default(),
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
            confirm_label: "OK".to_string(),
            cancel_label: "OK".to_string(),
            focus: DialogFocus::default(),
            button: DialogButton::default(),
        }
    }

    /// Name what saying yes will do. A question whose button says "Confirm"
    /// makes the user re-read the body to find out what they agreed to.
    #[must_use]
    pub fn with_confirm_label(mut self, label: impl Into<String>) -> Self {
        self.confirm_label = label.into();
        self
    }

    /// Name what backing out leaves behind, where "Cancel" would be
    /// ambiguous -- "Cancel" on a question about cancelling a scan is a trap.
    #[must_use]
    pub fn with_cancel_label(mut self, label: impl Into<String>) -> Self {
        self.cancel_label = label.into();
        self
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
            // The accelerators answer from any focus: they are how the
            // question was always answered, and giving it focusable buttons
            // must not have taken that away.
            Some(Action::Mnemonic('y')) => DialogOutcome::Confirmed,
            Some(Action::Back | Action::Mnemonic('n')) => DialogOutcome::Dismissed,
            Some(Action::Mnemonic('d')) if self.toggle.is_some() => {
                self.flip();
                DialogOutcome::Open
            }
            Some(Action::MoveUp) if self.toggle.is_some() => {
                self.focus = DialogFocus::Toggle;
                DialogOutcome::Open
            }
            Some(Action::MoveDown) if self.toggle.is_some() => {
                self.focus = DialogFocus::Button;
                DialogOutcome::Open
            }
            Some(Action::FocusOut) => {
                self.move_button(DialogButton::Cancel);
                DialogOutcome::Open
            }
            Some(Action::FocusIn) => {
                self.move_button(DialogButton::Confirm);
                DialogOutcome::Open
            }
            // Enter and Space act on whatever has focus, which is what makes
            // the buttons controls rather than a picture of controls.
            Some(Action::Activate | Action::Toggle) => match (self.focus, self.button) {
                (DialogFocus::Toggle, _) => {
                    self.flip();
                    DialogOutcome::Open
                }
                (DialogFocus::Button, DialogButton::Cancel) => DialogOutcome::Dismissed,
                (DialogFocus::Button, DialogButton::Confirm) => DialogOutcome::Confirmed,
            },
            _ => DialogOutcome::Open,
        }
    }

    /// Flip the switch, wherever focus happens to be.
    fn flip(&mut self) {
        if let Some(toggle) = self.toggle.as_mut() {
            toggle.on = !toggle.on;
        }
    }

    /// Move along the button row, which also brings focus down off the
    /// checkbox: a sideways key is only ever about the buttons.
    fn move_button(&mut self, button: DialogButton) {
        self.focus = DialogFocus::Button;
        self.button = button;
    }

    /// What the confirm button says. A switch that is on renames the button
    /// after itself, so the mode cannot be on without the button saying so.
    #[must_use]
    pub fn confirm_button_label(&self) -> &str {
        match &self.toggle {
            Some(toggle) if toggle.on => &toggle.label,
            _ => &self.confirm_label,
        }
    }

    /// The footer hint while this dialog is up.
    pub fn hints(&self) -> &str {
        match self.kind {
            DialogKind::Confirm if self.toggle.is_some() => {
                " \u{2191}\u{2193}\u{2190}\u{2192}: move  |  Space/Enter: activate  |  \
                 d: toggle dry run  |  y: confirm  |  n/Esc: cancel"
            }
            DialogKind::Confirm => {
                " \u{2190}\u{2192}: move  |  Space/Enter: activate  |  y: confirm  |  \
                 n/Esc: cancel"
            }
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
    let mut lines: Vec<Line> = dialog
        .body
        .iter()
        .map(|line| Line::raw(format!(" {line}")))
        .collect();

    if let Some(toggle) = &dialog.toggle {
        lines.push(Line::raw(""));
        lines.push(checkbox_line(toggle, dialog.focus == DialogFocus::Toggle));
    }
    lines.push(Line::raw(""));
    lines.push(button_row(dialog));

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

/// The checkbox row, drawn the way a tickable row is drawn everywhere else
/// so that a control which answers Space looks like one.
fn checkbox_line(toggle: &DialogToggle, focused: bool) -> Line<'static> {
    let checkbox = if toggle.on { "[x]" } else { "[ ]" };
    let style = if focused {
        Style::default().bg(Color::DarkGray).fg(Color::White).bold()
    } else {
        Style::default().fg(Color::Yellow)
    };
    Line::styled(format!(" {checkbox} {}", toggle.label), style)
}

/// A question's buttons; a notice has only the one that dismisses it.
fn button_row(dialog: &Dialog) -> Line<'static> {
    if dialog.kind == DialogKind::Error {
        return Line::from(vec![
            Span::raw("   "),
            button_span(&dialog.confirm_label, true, true),
        ]);
    }
    let on_row = dialog.focus == DialogFocus::Button;
    Line::from(vec![
        Span::raw("   "),
        button_span(
            &dialog.cancel_label,
            true,
            on_row && dialog.button == DialogButton::Cancel,
        ),
        Span::raw("  "),
        button_span(
            dialog.confirm_button_label(),
            true,
            on_row && dialog.button == DialogButton::Confirm,
        ),
    ])
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

    // -- action rows ---------------------------------------------------------

    fn rendered(button: Button, focused: bool) -> String {
        button_line(button, focused)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn every_button_is_written_the_way_settings_writes_its_own() {
        assert_eq!(
            rendered(Button::new("Cancel scan"), false),
            "   [ Cancel scan ]"
        );
        assert_eq!(
            rendered(Button::inert("Cancelling\u{2026}"), false),
            "   [ Cancelling\u{2026} ]"
        );
    }

    /// A button row carries its style on the button itself, so a row can
    /// hold more than one of them.
    fn button_style(line: &Line<'_>) -> Style {
        line.spans.last().expect("a button").style
    }

    #[test]
    fn a_button_with_the_cursor_is_highlighted_and_one_without_is_not() {
        let focused = button_line(Button::new("Close"), true);
        let idle = button_line(Button::new("Close"), false);

        assert_ne!(button_style(&focused), button_style(&idle));
        assert_eq!(button_style(&focused).bg, Some(Color::DarkGray));
    }

    #[test]
    fn an_inert_button_is_never_drawn_as_focused_however_it_is_asked_for() {
        // Highlighting a row that will not answer Enter would promise
        // something the screen cannot deliver.
        let button = Button::inert("Stopping\u{2026}");

        assert_eq!(
            button_style(&button_line(button, true)),
            button_style(&button_line(button, false))
        );
        assert_eq!(button_style(&button_line(button, true)).bg, None);
        assert!(!button.enabled);
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
    fn every_question_advertises_its_buttons_rather_than_only_its_hotkeys() {
        for dialog in [confirm(), toggling()] {
            let hints = dialog.hints();
            assert!(hints.contains("move"), "{hints}");
            assert!(hints.contains("activate"), "{hints}");
            assert!(hints.contains("y: confirm"), "{hints}");
            assert!(hints.contains("n/Esc: cancel"), "{hints}");
        }
        assert_eq!(Dialog::error("x", "y").hints(), " any key: dismiss");
    }

    // -- the buttons every question carries ---------------------------------

    fn toggling() -> Dialog {
        Dialog::confirm("Confirm run", ["3 senders.".to_string()])
            .with_confirm_label("Run")
            .with_toggle("Dry run", false)
    }

    /// The text of the row the renderer draws, buttons and all.
    fn row_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn a_question_starts_on_its_confirm_button_so_enter_still_answers_it() {
        // Muscle memory: Enter has always meant yes, and giving the dialog
        // focusable controls must not add a keypress to the common answer.
        for dialog in [confirm(), toggling()] {
            assert_eq!(dialog.focus, DialogFocus::Button);
            assert_eq!(dialog.button, DialogButton::Confirm);
        }
    }

    #[test]
    fn left_and_right_walk_the_button_row() {
        let mut dialog = confirm();

        assert_eq!(dialog.on_key(key(KeyCode::Left)), DialogOutcome::Open);
        assert_eq!(dialog.button, DialogButton::Cancel);
        assert_eq!(dialog.on_key(key(KeyCode::Right)), DialogOutcome::Open);
        assert_eq!(dialog.button, DialogButton::Confirm);
    }

    #[test]
    fn enter_and_space_answer_whichever_button_has_focus() {
        for code in [KeyCode::Enter, KeyCode::Char(' ')] {
            let mut dialog = confirm();
            dialog.on_key(key(KeyCode::Left));
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Dismissed, "{code:?}");

            let mut dialog = confirm();
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Confirmed, "{code:?}");
        }
    }

    #[test]
    fn the_checkbox_is_a_focus_stop_above_the_buttons() {
        let mut dialog = toggling();

        for code in [KeyCode::Up, KeyCode::Char('k')] {
            dialog.focus = DialogFocus::Button;
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Open);
            assert_eq!(dialog.focus, DialogFocus::Toggle, "{code:?}");
        }
        for code in [KeyCode::Down, KeyCode::Char('j')] {
            dialog.focus = DialogFocus::Toggle;
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Open);
            assert_eq!(dialog.focus, DialogFocus::Button, "{code:?}");
        }
    }

    #[test]
    fn a_question_with_no_checkbox_has_no_stop_to_move_up_to() {
        let mut dialog = confirm();

        assert_eq!(dialog.on_key(key(KeyCode::Up)), DialogOutcome::Open);
        assert_eq!(dialog.focus, DialogFocus::Button, "there is nowhere to go");
    }

    #[test]
    fn space_and_enter_on_the_checkbox_tick_it_rather_than_answering() {
        for code in [KeyCode::Char(' '), KeyCode::Enter] {
            let mut dialog = toggling();
            dialog.on_key(key(KeyCode::Up));

            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Open, "{code:?}");
            assert!(dialog.toggled(), "{code:?} should tick the box");
            assert_eq!(dialog.on_key(key(code)), DialogOutcome::Open);
            assert!(!dialog.toggled(), "and untick it");
        }
    }

    #[test]
    fn a_sideways_key_from_the_checkbox_lands_on_the_button_it_names() {
        let mut dialog = toggling();
        dialog.on_key(key(KeyCode::Up));

        dialog.on_key(key(KeyCode::Left));

        assert_eq!(dialog.focus, DialogFocus::Button);
        assert_eq!(dialog.button, DialogButton::Cancel);
    }

    #[test]
    fn the_hotkeys_still_answer_from_any_focus() {
        for focus in [DialogFocus::Toggle, DialogFocus::Button] {
            for button in [DialogButton::Cancel, DialogButton::Confirm] {
                let mut dialog = toggling();
                (dialog.focus, dialog.button) = (focus, button);
                assert_eq!(dialog.on_key(key(KeyCode::Char('y'))), DialogOutcome::Confirmed);

                let mut dialog = toggling();
                (dialog.focus, dialog.button) = (focus, button);
                assert_eq!(dialog.on_key(key(KeyCode::Char('n'))), DialogOutcome::Dismissed);

                let mut dialog = toggling();
                (dialog.focus, dialog.button) = (focus, button);
                assert_eq!(dialog.on_key(key(KeyCode::Esc)), DialogOutcome::Dismissed);

                let mut dialog = toggling();
                (dialog.focus, dialog.button) = (focus, button);
                assert_eq!(dialog.on_key(key(KeyCode::Char('d'))), DialogOutcome::Open);
                assert!(dialog.toggled(), "d ticks the box wherever focus is");
            }
        }
    }

    // -- what the buttons say ------------------------------------------------

    #[test]
    fn a_question_names_what_saying_yes_will_do() {
        let dialog = Dialog::confirm("Cancel the scan", [])
            .with_confirm_label("Stop scanning")
            .with_cancel_label("Keep scanning");

        assert_eq!(row_text(&button_row(&dialog)), "   [ Keep scanning ]  [ Stop scanning ]");
    }

    #[test]
    fn a_question_that_was_given_no_labels_still_reads_as_a_question() {
        assert_eq!(row_text(&button_row(&confirm())), "   [ Cancel ]  [ Confirm ]");
    }

    #[test]
    fn a_ticked_switch_renames_the_button_after_itself() {
        // The mode cannot be on without the button the user presses saying so.
        let mut dialog = toggling();
        assert_eq!(dialog.confirm_button_label(), "Run");

        dialog.on_key(key(KeyCode::Char('d')));

        assert_eq!(dialog.confirm_button_label(), "Dry run");
        assert!(row_text(&button_row(&dialog)).contains("[ Dry run ]"));
    }

    #[test]
    fn a_notice_offers_only_the_button_that_dismisses_it() {
        let dialog = Dialog::error("Run failed", "connection refused");

        assert_eq!(row_text(&button_row(&dialog)), "   [ OK ]");
    }

    #[test]
    fn the_focused_control_is_highlighted_the_way_a_focused_row_is() {
        let ticked = checkbox_line(&DialogToggle { label: "Dry run".to_string(), on: true }, true);
        let idle = checkbox_line(&DialogToggle { label: "Dry run".to_string(), on: true }, false);

        assert_eq!(ticked.style.bg, Some(Color::DarkGray));
        assert_eq!(idle.style.bg, None);
        assert_eq!(
            button_span("Run", true, true).style.bg,
            Some(Color::DarkGray),
            "a button and a row agree on what focus looks like"
        );
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

