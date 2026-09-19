//! Settings screen behind `unsubscribe config`.
//!
//! Navigation, editing, validation, and dirty-state tracking live in
//! [`SettingsApp`] and [`Draft`], which never touch a terminal. [`run`] owns
//! the event loop and drawing, and delegates every side effect (saving,
//! listing folders, re-authenticating) to a [`SettingsIo`] implementation.

use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use ratatui::prelude::*;
use ratatui::widgets::*;

use unsubscribe_core::{AccountConfig, Preferences};

use super::keys::{self, Action as Key};
use super::{suspended, TerminalGuard};

// ---------------------------------------------------------------------------
// Side effects
// ---------------------------------------------------------------------------

/// Everything the settings screen needs from the outside world.
///
/// Keeping these behind a trait is what lets the screen's state machine be
/// driven without a config file, a keychain, or a network connection.
pub trait SettingsIo {
    /// Persist the edited settings.
    fn save(&self, account: &AccountConfig, preferences: &Preferences) -> Result<()>;

    /// Folder names the provider offers, from the same source as `list-folders`.
    ///
    /// An empty list means the provider has no folders to pick from (Gmail);
    /// an error means the fetch failed. Both fall back to free-text entry.
    fn list_folders(&self) -> Result<Vec<String>>;

    /// Run the existing `reauth` flow and return the config as it stands
    /// afterwards. Called with the terminal restored, so it may prompt.
    fn reauthenticate(&self) -> Result<(AccountConfig, Preferences)>;

    /// Where credentials for this account live, for the Account section's
    /// information line. Never the credentials themselves.
    fn credential_location(&self) -> String;
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

// The settings schema -- every key, its range, and what a valid value looks
// like -- lives in the config layer, so this screen and `unsubscribe config`
// validate identically. Kept under the names this file has always used.
pub use unsubscribe_persistence::{SettingKey as Field, Settings as Draft};
use unsubscribe_persistence::split_folders;

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// A line on the settings screen. Only `Setting` and `Reauthenticate` accept
/// the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    Header(&'static str),
    Spacer,
    Setting(Field),
    /// Where credentials live. Informational, never editable.
    Credentials,
    Reauthenticate,
}

impl Row {
    const fn is_selectable(self) -> bool {
        matches!(self, Row::Setting(_) | Row::Reauthenticate)
    }
}

/// The screen's fixed layout. Every field is shown for every provider: Gmail
/// simply leaves host, port, and SMTP blank.
fn rows() -> Vec<Row> {
    vec![
        Row::Header(" ── Account ──"),
        Row::Setting(Field::Provider),
        Row::Setting(Field::Host),
        Row::Setting(Field::Port),
        Row::Setting(Field::Username),
        Row::Setting(Field::AuthType),
        Row::Credentials,
        Row::Reauthenticate,
        Row::Spacer,
        Row::Header(" ── SMTP ──"),
        Row::Setting(Field::SmtpHost),
        Row::Setting(Field::SmtpPort),
        Row::Spacer,
        Row::Header(" ── Scan ──"),
        Row::Setting(Field::Folders),
        Row::Setting(Field::ArchiveFolder),
        Row::Spacer,
        Row::Header(" ── Preferences ──"),
        Row::Setting(Field::MinEmails),
        Row::Setting(Field::StaleAfterMonths),
        Row::Setting(Field::CacheMaxAgeDays),
    ]
}

// ---------------------------------------------------------------------------
// Folder picker
// ---------------------------------------------------------------------------

/// One row in the folder picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    pub name: String,
    pub selected: bool,
    /// False for folders that are in the config but absent from the server's
    /// list. They stay visible and selected so a save never drops them.
    pub on_server: bool,
}

/// Multi-select folder picker, with a free-text fallback for providers that
/// offer no folder list and for a failed fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderPicker {
    pub entries: Vec<FolderEntry>,
    pub cursor: usize,
    pub scroll_offset: usize,
    /// `Some` when the picker is in free-text mode.
    pub free_text: Option<String>,
    /// Why the picker fell back to free text.
    pub notice: Option<String>,
}

impl FolderPicker {
    /// Build a picker from the server's folders and the configured selection.
    ///
    /// Configured folders the server did not return are appended and stay
    /// selected, so a folder that is temporarily invisible (a rename, a
    /// permissions blip) is never silently dropped on save.
    pub fn new(available: &[String], configured: &[String], notice: Option<String>) -> Self {
        if available.is_empty() {
            return Self {
                entries: Vec::new(),
                cursor: 0,
                scroll_offset: 0,
                free_text: Some(configured.join(", ")),
                notice: Some(notice.unwrap_or_else(|| {
                    "No folder list available — enter folders separated by commas.".to_string()
                })),
            };
        }

        let from_server = available.iter().map(|name| FolderEntry {
            name: name.clone(),
            selected: configured.contains(name),
            on_server: true,
        });
        let missing = configured
            .iter()
            .filter(|name| !available.contains(name))
            .map(|name| FolderEntry {
                name: name.clone(),
                selected: true,
                on_server: false,
            });

        Self {
            entries: from_server.chain(missing).collect(),
            cursor: 0,
            scroll_offset: 0,
            free_text: None,
            notice,
        }
    }

    pub fn move_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.entries.len() {
            self.cursor += 1;
        }
    }

    pub fn toggle(&mut self) {
        if let Some(entry) = self.entries.get_mut(self.cursor) {
            entry.selected = !entry.selected;
        }
    }

    /// The folders the user has chosen.
    pub fn selection(&self) -> Vec<String> {
        match &self.free_text {
            Some(text) => split_folders(text),
            None => self
                .entries
                .iter()
                .filter(|e| e.selected)
                .map(|e| e.name.clone())
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Screen state
// ---------------------------------------------------------------------------

/// What the screen is currently doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Browse,
    Editing {
        field: Field,
        buffer: String,
        error: Option<String>,
    },
    Folders(FolderPicker),
    ConfirmQuit,
}

/// A side effect the event loop must perform on the state's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    OpenFolderPicker,
    Reauthenticate,
    Save,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Warning,
    Error,
}

/// Navigation, editing, and dirty-state tracking for the settings screen.
pub struct SettingsApp {
    /// Values as they are on disk. The baseline for "unsaved".
    saved: Draft,
    /// Values as edited.
    pub draft: Draft,
    rows: Vec<Row>,
    pub cursor: usize,
    scroll_offset: usize,
    pub mode: Mode,
    status: Option<(StatusKind, String)>,
    credential_location: String,
    account_id: String,
}

impl SettingsApp {
    pub fn new(account: &AccountConfig, preferences: &Preferences, credential_location: String) -> Self {
        let draft = Draft::from_config(account, preferences);
        let rows = rows();
        let cursor = rows
            .iter()
            .position(|r| r.is_selectable())
            .unwrap_or_default();
        Self {
            saved: draft.clone(),
            draft,
            rows,
            cursor,
            scroll_offset: 0,
            mode: Mode::Browse,
            status: None,
            credential_location,
            account_id: account.account_id.clone(),
        }
    }

    /// Whether any field differs from what is on disk.
    pub fn is_dirty(&self) -> bool {
        self.draft != self.saved
    }

    /// Whether one field differs from what is on disk.
    pub fn is_field_dirty(&self, field: Field) -> bool {
        self.draft.get(field) != self.saved.get(field)
    }

    /// Whether the unsaved changes invalidate the stored credentials.
    pub fn needs_reauth(&self) -> bool {
        Field::ALL
            .into_iter()
            .filter(|f| f.affects_credentials())
            .any(|f| self.is_field_dirty(f))
    }

    pub fn status(&self) -> Option<(StatusKind, &str)> {
        self.status.as_ref().map(|(kind, msg)| (*kind, msg.as_str()))
    }

    pub fn set_status(&mut self, kind: StatusKind, message: impl Into<String>) {
        self.status = Some((kind, message.into()));
    }

    /// Adopt values that were written to disk elsewhere (a save, or a reauth
    /// that rewrote the file), clearing every unsaved marker.
    pub fn adopt(&mut self, account: &AccountConfig, preferences: &Preferences) {
        self.draft = Draft::from_config(account, preferences);
        self.saved = self.draft.clone();
        self.account_id = account.account_id.clone();
    }

    /// Discard every unsaved change.
    pub fn revert(&mut self) {
        self.draft = self.saved.clone();
    }

    pub fn to_config(&self) -> Result<(AccountConfig, Preferences), (Field, String)> {
        self.draft.to_config(&self.account_id)
    }

    /// Move the cursor to a field and report why, used when a save is refused.
    pub fn focus_invalid(&mut self, field: Field, message: String) {
        if let Some(index) = self
            .rows
            .iter()
            .position(|r| *r == Row::Setting(field))
        {
            self.cursor = index;
        }
        self.set_status(StatusKind::Error, message);
    }

    fn move_up(&mut self) {
        let Some(next) = self.rows[..self.cursor]
            .iter()
            .rposition(|r| r.is_selectable())
        else {
            return;
        };
        self.cursor = next;
    }

    fn move_down(&mut self) {
        let Some(offset) = self.rows[self.cursor + 1..]
            .iter()
            .position(|r| r.is_selectable())
        else {
            return;
        };
        self.cursor = self.cursor + 1 + offset;
    }

    /// Handle one key press and report any side effect the caller must run.
    ///
    /// Raw keys come in and are mapped once, here, so the standalone
    /// `unsubscribe config` screen and the Settings panel inside the app
    /// answer to exactly the same bindings.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        match keys::action(key, self.captures_text()) {
            Some(action) => self.on_action(action),
            None => Action::None,
        }
    }

    /// Whether a field is taking free text right now.
    #[must_use]
    pub fn captures_text(&self) -> bool {
        match &self.mode {
            Mode::Editing { .. } => true,
            Mode::Folders(picker) => picker.free_text.is_some(),
            _ => false,
        }
    }

    pub fn on_action(&mut self, action: Key) -> Action {
        match &self.mode {
            Mode::Browse => self.on_action_browse(action),
            Mode::Editing { .. } => self.on_action_editing(action),
            Mode::Folders(_) => self.on_action_folders(action),
            Mode::ConfirmQuit => self.on_action_confirm_quit(action),
        }
    }

    /// The actions this screen answers, for the footer and the `?` overlay.
    #[must_use]
    pub fn actions(&self) -> Vec<Key> {
        match &self.mode {
            Mode::Editing { .. } => vec![Key::Activate, Key::Back],
            Mode::Folders(picker) if picker.free_text.is_some() => {
                vec![Key::Activate, Key::Back]
            }
            Mode::Folders(_) => keys::list_actions(&[Key::Toggle, Key::Activate]),
            Mode::ConfirmQuit => vec![Key::Mnemonic('y'), Key::Mnemonic('n')],
            Mode::Browse => keys::list_actions(&[
                Key::Activate,
                Key::Mnemonic('w'),
                Key::Mnemonic('x'),
            ]),
        }
    }

    fn on_action_browse(&mut self, action: Key) -> Action {
        // The rows are not a flat list -- headers are skipped -- so the screen
        // steps for itself, as many rows as the key is worth, rather than
        // using the helper's index arithmetic.
        if let Some(steps) = keys::steps(action) {
            for _ in 0..steps {
                if keys::is_backwards(action) {
                    self.move_up();
                } else {
                    self.move_down();
                }
            }
            return Action::None;
        }
        match action {
            Key::First => {
                self.cursor = self
                    .rows
                    .iter()
                    .position(|row| row.is_selectable())
                    .unwrap_or_default();
                return Action::None;
            }
            Key::Last => {
                self.cursor = self
                    .rows
                    .iter()
                    .rposition(|row| row.is_selectable())
                    .unwrap_or_default();
                return Action::None;
            }
            _ => {}
        }
        match action {
            Key::Back => {
                if self.is_dirty() {
                    self.mode = Mode::ConfirmQuit;
                    Action::None
                } else {
                    Action::Quit
                }
            }
            Key::Mnemonic('w') => Action::Save,
            Key::Mnemonic('x') => {
                if self.is_dirty() {
                    self.revert();
                    self.set_status(StatusKind::Info, "Reverted to the saved settings.");
                }
                Action::None
            }
            Key::Activate | Key::Toggle => self.activate(),
            _ => Action::None,
        }
    }

    /// Act on the row under the cursor.
    fn activate(&mut self) -> Action {
        match self.rows.get(self.cursor) {
            Some(Row::Reauthenticate) => Action::Reauthenticate,
            Some(Row::Setting(Field::Folders)) => Action::OpenFolderPicker,
            Some(Row::Setting(field)) if field.choices().is_some() => {
                let field = *field;
                self.draft.cycle(field);
                self.status = None;
                Action::None
            }
            Some(Row::Setting(field)) => {
                let field = *field;
                self.mode = Mode::Editing {
                    field,
                    buffer: self.draft.get(field),
                    error: None,
                };
                self.status = None;
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_action_editing(&mut self, action: Key) -> Action {
        let Mode::Editing { field, buffer, .. } = &mut self.mode else {
            return Action::None;
        };
        let field = *field;

        match action {
            Key::Back => self.mode = Mode::Browse,
            Key::Type(c) => buffer.push(c),
            Key::Erase => {
                buffer.pop();
            }
            Key::Activate => {
                // Validate against a copy so a rejected value never lands in
                // the draft and never counts as an unsaved change.
                let candidate = buffer.clone();
                let mut probe = self.draft.clone();
                probe.set(field, candidate.clone());
                match probe.validate(field) {
                    Ok(()) => {
                        self.draft.set(field, candidate);
                        self.mode = Mode::Browse;
                    }
                    Err(message) => {
                        if let Mode::Editing { error, .. } = &mut self.mode {
                            *error = Some(message);
                        }
                    }
                }
            }
            _ => {}
        }
        Action::None
    }

    fn on_action_folders(&mut self, action: Key) -> Action {
        let Mode::Folders(picker) = &mut self.mode else {
            return Action::None;
        };

        // Free-text mode is a single-line editor; the list mode is a checklist.
        if let Some(text) = &mut picker.free_text {
            match action {
                Key::Back => self.mode = Mode::Browse,
                Key::Type(c) => text.push(c),
                Key::Erase => {
                    text.pop();
                }
                Key::Activate => self.commit_folders(),
                _ => {}
            }
            return Action::None;
        }

        if let Some(steps) = keys::steps(action) {
            for _ in 0..steps {
                if keys::is_backwards(action) {
                    picker.move_up();
                } else {
                    picker.move_down();
                }
            }
            return Action::None;
        }
        match action {
            Key::Back => self.mode = Mode::Browse,
            Key::First => picker.cursor = 0,
            Key::Last => picker.cursor = picker.entries.len().saturating_sub(1),
            Key::Toggle => picker.toggle(),
            Key::Activate => self.commit_folders(),
            _ => {}
        }
        Action::None
    }

    fn commit_folders(&mut self) {
        let Mode::Folders(picker) = &self.mode else {
            return;
        };
        let selection = picker.selection();
        if selection.is_empty() {
            if let Mode::Folders(picker) = &mut self.mode {
                picker.notice = Some("Select at least one folder.".to_string());
            }
            return;
        }
        self.draft.folders = selection;
        self.mode = Mode::Browse;
    }

    fn on_action_confirm_quit(&mut self, action: Key) -> Action {
        // The same answer keys as every other confirmation in the app.
        match action {
            Key::Mnemonic('y') | Key::Activate => Action::Quit,
            _ => {
                self.mode = Mode::Browse;
                Action::None
            }
        }
    }

    /// Open the folder picker with the folders a provider offered.
    pub fn open_folder_picker(&mut self, available: &[String], notice: Option<String>) {
        self.mode = Mode::Folders(FolderPicker::new(
            available,
            &self.draft.folders,
            notice,
        ));
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Run the settings screen until the user saves and quits, or quits without
/// saving.
pub fn run(
    account: &AccountConfig,
    preferences: &Preferences,
    io_ops: &dyn SettingsIo,
) -> Result<()> {
    let mut app = SettingsApp::new(account, preferences, io_ops.credential_location());

    let (guard, mut terminal) = TerminalGuard::enter()?;

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match app.on_key(key) {
            Action::None => {}
            Action::Quit => break,
            Action::Save => save(&mut app, io_ops),
            Action::OpenFolderPicker => {
                // Fetched only now, so a slow or unreachable server never
                // delays the screen opening.
                terminal.draw(|f| draw_loading(f, "Loading folders…"))?;
                match io_ops.list_folders() {
                    Ok(folders) if folders.is_empty() => app.open_folder_picker(
                        &[],
                        Some(
                            "This provider has no folder list — enter folders separated by commas."
                                .to_string(),
                        ),
                    ),
                    Ok(folders) => app.open_folder_picker(&folders, None),
                    Err(e) => app.open_folder_picker(
                        &[],
                        Some(format!("Could not list folders ({e}) — enter them manually.")),
                    ),
                }
            }
            Action::Reauthenticate => {
                if app.is_dirty() {
                    app.set_status(
                        StatusKind::Warning,
                        "Save your changes before re-authenticating.",
                    );
                    continue;
                }
                // The reauth flow prompts on stdin, so hand the terminal back
                // to it and take it again afterwards.
                let outcome = suspended(&mut terminal, || io_ops.reauthenticate())?;
                match outcome {
                    Ok((account, preferences)) => {
                        app.adopt(&account, &preferences);
                        app.set_status(StatusKind::Info, "Re-authenticated.");
                    }
                    Err(e) => app.set_status(StatusKind::Error, format!("Re-authentication failed: {e}")),
                }
            }
        }
    }

    drop(guard);
    Ok(())
}

pub(crate) fn save(app: &mut SettingsApp, io_ops: &dyn SettingsIo) {
    match app.to_config() {
        Err((field, message)) => {
            app.focus_invalid(field, format!("{}: {message}", field.label()));
        }
        Ok((account, preferences)) => match io_ops.save(&account, &preferences) {
            Ok(()) => {
                app.adopt(&account, &preferences);
                app.set_status(StatusKind::Info, "Saved.");
            }
            Err(e) => app.set_status(StatusKind::Error, format!("Save failed: {e}")),
        },
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const LABEL_WIDTH: usize = 22;

fn draw_loading(f: &mut Frame, message: &str) {
    let block = Paragraph::new(format!(" {message}"))
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(block, f.area());
}

/// Draw the whole screen, standalone: title, body, and its own help line.
fn draw(f: &mut Frame, app: &mut SettingsApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(5),    // body + status
            Constraint::Length(2), // help
        ])
        .split(f.area());

    let title = Paragraph::new("Settings")
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

/// Draw the screen's body into `area`: the fields (or the folder picker) and
/// the status line under them. Used by the app shell, which supplies its own
/// header and footer.
pub(crate) fn render(f: &mut Frame, area: Rect, app: &mut SettingsApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    match &mut app.mode {
        Mode::Folders(picker) => draw_folder_picker(f, chunks[0], picker),
        _ => draw_settings(f, chunks[0], app),
    }

    draw_status(f, chunks[1], app);
}

fn draw_settings(f: &mut Frame, area: Rect, app: &mut SettingsApp) {
    let visible_height = (area.height as usize).saturating_sub(2);

    // Keep the cursor visible, including the section header above it.
    let scroll_target = app
        .cursor
        .saturating_sub(usize::from(app.cursor > 0 && !app.rows[app.cursor - 1].is_selectable()));
    if scroll_target < app.scroll_offset {
        app.scroll_offset = scroll_target;
    } else if app.cursor >= app.scroll_offset + visible_height {
        app.scroll_offset = app.cursor - visible_height + 1;
    }

    let editing = match &app.mode {
        Mode::Editing { field, buffer, error } => Some((*field, buffer.clone(), error.clone())),
        _ => None,
    };

    let mut lines: Vec<Line> = Vec::new();
    for index in app.scroll_offset..app.rows.len().min(app.scroll_offset + visible_height) {
        let is_cursor = index == app.cursor && editing.is_none();
        match app.rows[index] {
            Row::Header(label) => lines.push(Line::styled(
                label,
                Style::default().fg(Color::Yellow).bold(),
            )),
            Row::Spacer => lines.push(Line::raw("")),
            Row::Credentials => lines.push(Line::styled(
                format!("   {:<LABEL_WIDTH$}{}", "Credentials", app.credential_location),
                Style::default().fg(Color::DarkGray),
            )),
            Row::Reauthenticate => {
                let style = if index == app.cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                lines.push(Line::styled("   [ Re-authenticate ]", style));
            }
            Row::Setting(field) => {
                let is_editing = editing.as_ref().is_some_and(|(f, _, _)| *f == field);
                let (value, error) = match &editing {
                    Some((_, buffer, error)) if is_editing => {
                        (format!("{buffer}▏"), error.clone())
                    }
                    _ => (app.draft.get(field), None),
                };
                let marker = if app.is_field_dirty(field) { "*" } else { " " };
                let style = if is_editing {
                    Style::default().fg(Color::Yellow)
                } else if is_cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else if app.is_field_dirty(field) {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };
                lines.push(Line::styled(
                    format!(" {marker} {:<LABEL_WIDTH$}{value}", field.label()),
                    style,
                ));
                if let Some(message) = error {
                    lines.push(Line::styled(
                        format!("   {:<LABEL_WIDTH$}{message}", ""),
                        Style::default().fg(Color::Red),
                    ));
                }
            }
        }
    }

    let title = if app.is_dirty() {
        " Settings (unsaved changes) "
    } else {
        " Settings "
    };
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_folder_picker(f: &mut Frame, area: Rect, picker: &mut FolderPicker) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(notice) = &picker.notice {
        lines.push(Line::styled(
            format!(" {notice}"),
            Style::default().fg(Color::Yellow),
        ));
        lines.push(Line::raw(""));
    }

    match &picker.free_text {
        Some(text) => lines.push(Line::styled(
            format!(" {text}▏"),
            Style::default().fg(Color::White),
        )),
        None => {
            let visible_height = (area.height as usize)
                .saturating_sub(2 + lines.len());
            if picker.cursor < picker.scroll_offset {
                picker.scroll_offset = picker.cursor;
            } else if visible_height > 0 && picker.cursor >= picker.scroll_offset + visible_height {
                picker.scroll_offset = picker.cursor - visible_height + 1;
            }

            let end = picker
                .entries
                .len()
                .min(picker.scroll_offset + visible_height.max(1));
            for index in picker.scroll_offset..end {
                let entry = &picker.entries[index];
                let checkbox = if entry.selected { "[x]" } else { "[ ]" };
                let suffix = if entry.on_server { "" } else { "  (not on server)" };
                let style = if index == picker.cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else if entry.on_server {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                lines.push(Line::styled(
                    format!(" {checkbox} {}{suffix}", entry.name),
                    style,
                ));
            }
        }
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Folders to scan "),
        ),
        area,
    );
}

fn draw_status(f: &mut Frame, area: Rect, app: &SettingsApp) {
    let (style, text) = match &app.mode {
        Mode::ConfirmQuit => (
            Style::default().fg(Color::Yellow),
            " Discard unsaved changes and quit? [y/N]".to_string(),
        ),
        _ => match app.status() {
            Some((kind, message)) => {
                let color = match kind {
                    StatusKind::Info => Color::Green,
                    StatusKind::Warning => Color::Yellow,
                    StatusKind::Error => Color::Red,
                };
                (Style::default().fg(color), format!(" {message}"))
            }
            None if app.needs_reauth() => (
                Style::default().fg(Color::Yellow),
                " Provider, username, or auth type changed — re-authenticate after saving."
                    .to_string(),
            ),
            None if app.is_dirty() => (
                Style::default().fg(Color::Yellow),
                " Unsaved changes. Press s to save.".to_string(),
            ),
            None => (
                Style::default().fg(Color::DarkGray),
                format!(" Editing {}", app.account_id),
            ),
        },
    };

    f.render_widget(
        Paragraph::new(text)
            .style(style)
            .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use std::cell::RefCell;
    use unsubscribe_core::{AuthType, ProviderType};

    // ─── fixtures ───────────────────────────────────────────────────────────

    fn imap_account() -> AccountConfig {
        AccountConfig {
            account_id: "user@example.com".to_string(),
            provider_type: ProviderType::Imap,
            host: Some("imap.example.com".to_string()),
            port: Some(993),
            username: "user@example.com".to_string(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".to_string(), "Promotions".to_string()],
            archive_folder: "Unsubscribed".to_string(),
            smtp_host: None,
            smtp_port: None,
        }
    }

    fn gmail_account() -> AccountConfig {
        AccountConfig {
            account_id: "user@gmail.com".to_string(),
            provider_type: ProviderType::Gmail,
            host: None,
            port: None,
            username: "user@gmail.com".to_string(),
            auth_type: AuthType::OAuth,
            scan_folders: vec!["INBOX".to_string()],
            archive_folder: "Unsubscribed".to_string(),
            smtp_host: None,
            smtp_port: None,
        }
    }

    /// Deliberately not the defaults, so a field mix-up is visible.
    fn preferences() -> Preferences {
        Preferences {
            min_emails: 5,
            stale_after_months: 6,
            cache_max_age_days: 21,
            grace_period_days: 14,
        }
    }

    fn app() -> SettingsApp {
        SettingsApp::new(&imap_account(), &preferences(), "OS keychain".to_string())
    }

    /// Records what the screen asked to have saved, and can be told to fail.
    struct FakeIo {
        saved: RefCell<Vec<(AccountConfig, Preferences)>>,
        fails: bool,
        folders: Vec<String>,
    }

    impl FakeIo {
        fn new() -> Self {
            Self {
                saved: RefCell::new(Vec::new()),
                fails: false,
                folders: Vec::new(),
            }
        }

        fn failing() -> Self {
            Self {
                fails: true,
                ..Self::new()
            }
        }
    }

    impl SettingsIo for FakeIo {
        fn save(&self, account: &AccountConfig, preferences: &Preferences) -> Result<()> {
            if self.fails {
                return Err(anyhow::anyhow!("the disk is full"));
            }
            self.saved.borrow_mut().push((account.clone(), *preferences));
            Ok(())
        }

        fn list_folders(&self) -> Result<Vec<String>> {
            Ok(self.folders.clone())
        }

        fn reauthenticate(&self) -> Result<(AccountConfig, Preferences)> {
            Ok((imap_account(), preferences()))
        }

        fn credential_location(&self) -> String {
            "OS keychain".to_string()
        }
    }

    // ─── driving the screen ─────────────────────────────────────────────────

    fn press(app: &mut SettingsApp, code: KeyCode) -> Action {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn press_ctrl(app: &mut SettingsApp, code: KeyCode) -> Action {
        app.on_key(KeyEvent::new(code, KeyModifiers::CONTROL))
    }

    fn type_chars(app: &mut SettingsApp, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    fn row_index(app: &SettingsApp, row: Row) -> usize {
        app.rows
            .iter()
            .position(|r| *r == row)
            .unwrap_or_else(|| panic!("{row:?} is not on the screen"))
    }

    /// Put the cursor on a row directly, so a navigation bug cannot make an
    /// editing or validation test fail for the wrong reason.
    fn focus(app: &mut SettingsApp, field: Field) {
        app.cursor = row_index(app, Row::Setting(field));
    }

    /// Open a text field's editor, replace its contents, and accept.
    fn edit(app: &mut SettingsApp, field: Field, text: &str) {
        focus(app, field);
        press(app, KeyCode::Enter);
        assert!(is_editing(app), "{field:?} did not open an editor");
        for _ in 0..app.draft.get(field).chars().count() {
            press(app, KeyCode::Backspace);
        }
        type_chars(app, text);
        press(app, KeyCode::Enter);
    }

    fn is_editing(app: &SettingsApp) -> bool {
        matches!(app.mode, Mode::Editing { .. })
    }

    fn is_browsing(app: &SettingsApp) -> bool {
        matches!(app.mode, Mode::Browse)
    }

    fn editor_error(app: &SettingsApp) -> Option<String> {
        match &app.mode {
            Mode::Editing { error, .. } => error.clone(),
            _ => None,
        }
    }

    fn status_kind(app: &SettingsApp) -> Option<StatusKind> {
        app.status().map(|(kind, _)| kind)
    }

    // ─── navigation ─────────────────────────────────────────────────────────

    /// The rows that accept the cursor, in the order the screen presents them.
    /// Spelled out rather than derived from `rows()`, so a layout change that
    /// swallows a field is a test failure rather than a silent agreement.
    const SELECTABLE_ORDER: [Row; 13] = [
        Row::Setting(Field::Provider),
        Row::Setting(Field::Host),
        Row::Setting(Field::Port),
        Row::Setting(Field::Username),
        Row::Setting(Field::AuthType),
        Row::Reauthenticate,
        Row::Setting(Field::SmtpHost),
        Row::Setting(Field::SmtpPort),
        Row::Setting(Field::Folders),
        Row::Setting(Field::ArchiveFolder),
        Row::Setting(Field::MinEmails),
        Row::Setting(Field::StaleAfterMonths),
        Row::Setting(Field::CacheMaxAgeDays),
    ];

    #[test]
    fn the_cursor_opens_on_the_first_setting() {
        let app = app();
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::Provider));
    }

    #[test]
    fn moving_down_visits_every_selectable_row_in_screen_order() {
        let mut app = app();
        let mut visited = vec![app.rows[app.cursor]];
        for _ in 1..SELECTABLE_ORDER.len() {
            press(&mut app, KeyCode::Down);
            visited.push(app.rows[app.cursor]);
        }
        assert_eq!(visited, SELECTABLE_ORDER);
    }

    #[test]
    fn moving_up_retraces_the_same_rows_in_reverse() {
        let mut app = app();
        focus(&mut app, Field::CacheMaxAgeDays);
        let mut visited = vec![app.rows[app.cursor]];
        for _ in 1..SELECTABLE_ORDER.len() {
            press(&mut app, KeyCode::Up);
            visited.push(app.rows[app.cursor]);
        }
        visited.reverse();
        assert_eq!(visited, SELECTABLE_ORDER);
    }

    #[test]
    fn ctrl_with_an_arrow_jumps_five_settings_and_clamps() {
        let mut app = app();

        press_ctrl(&mut app, KeyCode::Down);
        assert_eq!(app.rows[app.cursor], SELECTABLE_ORDER[5]);
        press_ctrl(&mut app, KeyCode::Up);
        assert_eq!(app.rows[app.cursor], SELECTABLE_ORDER[0]);
        press_ctrl(&mut app, KeyCode::Up);
        assert_eq!(app.rows[app.cursor], SELECTABLE_ORDER[0], "clamped");
    }

    #[test]
    fn a_jump_lands_on_a_setting_rather_than_on_a_section_header() {
        // The rows are not a flat list, so a jump steps five selectable rows
        // rather than five indices.
        let mut app = app();

        press_ctrl(&mut app, KeyCode::Down);
        press_ctrl(&mut app, KeyCode::Down);

        assert!(app.rows[app.cursor].is_selectable());
        assert_eq!(app.rows[app.cursor], SELECTABLE_ORDER[10]);
    }

    #[test]
    fn g_and_shift_g_reach_the_first_and_last_setting() {
        let mut app = app();

        press(&mut app, KeyCode::End);
        assert_eq!(
            app.rows[app.cursor],
            SELECTABLE_ORDER[SELECTABLE_ORDER.len() - 1]
        );
        press(&mut app, KeyCode::Home);
        assert_eq!(app.rows[app.cursor], SELECTABLE_ORDER[0]);
    }

    #[test]
    fn moving_up_from_the_first_setting_stays_put() {
        let mut app = app();
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::Provider));
    }

    #[test]
    fn moving_down_from_the_last_setting_stays_put() {
        let mut app = app();
        focus(&mut app, Field::CacheMaxAgeDays);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::CacheMaxAgeDays));
    }

    #[test]
    fn moving_across_a_section_boundary_skips_the_header_and_the_blank_line() {
        let mut app = app();
        focus(&mut app, Field::SmtpPort);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::Folders));
        press(&mut app, KeyCode::Up);
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::SmtpPort));
    }

    #[test]
    fn the_credentials_line_never_takes_the_cursor() {
        // It shows where credentials live; there is nothing to edit on it.
        let mut app = app();
        for _ in 0..SELECTABLE_ORDER.len() * 2 {
            assert_ne!(app.rows[app.cursor], Row::Credentials);
            press(&mut app, KeyCode::Down);
        }
    }

    #[test]
    fn j_and_k_move_the_cursor_like_the_arrow_keys() {
        let (mut arrows, mut vim) = (app(), app());
        for _ in 0..3 {
            press(&mut arrows, KeyCode::Down);
            press(&mut vim, KeyCode::Char('j'));
        }
        assert_eq!(arrows.cursor, vim.cursor);
        press(&mut arrows, KeyCode::Up);
        press(&mut vim, KeyCode::Char('k'));
        assert_eq!(arrows.cursor, vim.cursor);
    }

    // ─── validation ─────────────────────────────────────────────────────────

    #[test]
    fn a_valid_edit_is_accepted_and_closes_the_editor() {
        let mut app = app();
        edit(&mut app, Field::Host, "imap.other.example.com");
        assert!(is_browsing(&app));
        assert_eq!(app.draft.host, "imap.other.example.com");
    }

    #[test]
    fn a_port_above_the_valid_range_is_rejected_and_the_old_value_kept() {
        let mut app = app();
        edit(&mut app, Field::Port, "70000");
        assert_eq!(app.draft.port, "993", "the rejected value must not land");
        assert!(is_editing(&app), "the editor should stay open for a correction");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn port_zero_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::Port, "0");
        assert_eq!(app.draft.port, "993");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn the_highest_valid_port_is_accepted() {
        let mut app = app();
        edit(&mut app, Field::Port, "65535");
        assert!(is_browsing(&app));
        assert_eq!(app.draft.port, "65535");
    }

    #[test]
    fn a_non_numeric_port_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::Port, "imaps");
        assert_eq!(app.draft.port, "993");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn an_imap_account_may_not_blank_its_port() {
        let mut app = app();
        edit(&mut app, Field::Port, "");
        assert_eq!(app.draft.port, "993");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn an_empty_host_is_rejected_for_an_imap_account() {
        let mut app = app();
        edit(&mut app, Field::Host, "   ");
        assert_eq!(app.draft.host, "imap.example.com");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn an_empty_username_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::Username, "");
        assert_eq!(app.draft.username, "user@example.com");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn an_empty_archive_folder_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "");
        assert_eq!(app.draft.archive_folder, "Unsubscribed");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn a_blank_smtp_host_is_allowed_because_it_is_derived_from_the_imap_host() {
        let mut app = app();
        edit(&mut app, Field::SmtpHost, "");
        assert!(is_browsing(&app));
        assert_eq!(app.draft.smtp_host, "");
    }

    #[test]
    fn a_non_numeric_preference_is_rejected_with_a_message_naming_the_key() {
        let mut app = app();
        edit(&mut app, Field::MinEmails, "lots");
        assert_eq!(app.draft.min_emails, "5");
        let message = editor_error(&app).expect("expected an inline error");
        assert!(message.contains("min_emails"), "got: {message}");
        assert!(message.contains("whole number"), "got: {message}");
    }

    #[test]
    fn a_negative_preference_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::MinEmails, "-1");
        assert_eq!(app.draft.min_emails, "5");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn zero_months_is_rejected_with_the_range_it_broke() {
        let mut app = app();
        edit(&mut app, Field::StaleAfterMonths, "0");
        assert_eq!(app.draft.stale_after_months, "6");
        let message = editor_error(&app).expect("expected an inline error");
        assert!(message.contains("between 1 and 1200"), "got: {message}");
    }

    #[test]
    fn a_cache_age_past_the_upper_bound_is_rejected() {
        let mut app = app();
        edit(&mut app, Field::CacheMaxAgeDays, "3651");
        assert_eq!(app.draft.cache_max_age_days, "21");
        assert!(editor_error(&app).is_some());
    }

    #[test]
    fn zero_minimum_emails_is_accepted_because_it_disables_the_filter() {
        let mut app = app();
        edit(&mut app, Field::MinEmails, "0");
        assert!(is_browsing(&app));
        assert_eq!(app.draft.min_emails, "0");
    }

    #[test]
    fn escape_abandons_an_edit_without_touching_the_draft() {
        let mut app = app();
        focus(&mut app, Field::Host);
        press(&mut app, KeyCode::Enter);
        type_chars(&mut app, "-typo");
        press(&mut app, KeyCode::Esc);
        assert!(is_browsing(&app));
        assert_eq!(app.draft.host, "imap.example.com");
    }

    #[test]
    fn correcting_a_rejected_value_in_place_is_accepted() {
        let mut app = app();
        focus(&mut app, Field::Port);
        press(&mut app, KeyCode::Enter);
        for _ in 0..3 {
            press(&mut app, KeyCode::Backspace);
        }
        type_chars(&mut app, "70000");
        press(&mut app, KeyCode::Enter);
        assert!(is_editing(&app), "70000 should have been refused");

        press(&mut app, KeyCode::Backspace);
        press(&mut app, KeyCode::Enter);
        assert!(is_browsing(&app), "7000 should have been accepted");
        assert_eq!(app.draft.port, "7000");
    }

    #[test]
    fn a_fixed_choice_field_cycles_instead_of_opening_an_editor() {
        let mut app = app();
        focus(&mut app, Field::Provider);
        press(&mut app, KeyCode::Enter);
        assert!(is_browsing(&app), "a choice field has nothing to type into");
        assert_eq!(app.draft.provider, "gmail");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.draft.provider, "imap", "the choices should wrap");
    }

    #[test]
    fn the_auth_type_cycles_between_its_two_values() {
        let mut app = app();
        focus(&mut app, Field::AuthType);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.draft.auth_type, "oauth");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.draft.auth_type, "password");
    }

    #[test]
    fn switching_to_gmail_makes_a_blank_host_acceptable() {
        // Gmail talks to an API, so there is no host to require.
        let mut app = app();
        focus(&mut app, Field::Provider);
        press(&mut app, KeyCode::Enter);
        edit(&mut app, Field::Host, "");
        assert!(is_browsing(&app));
        assert_eq!(app.draft.host, "");
    }

    #[test]
    fn a_gmail_account_converts_without_a_host_or_port() {
        let app = SettingsApp::new(&gmail_account(), &preferences(), "keychain".to_string());
        let (account, _) = app.to_config().expect("gmail needs neither host nor port");
        assert_eq!(account.host, None);
        assert_eq!(account.port, None);
        assert_eq!(account.provider_type, ProviderType::Gmail);
        assert_eq!(account.auth_type, AuthType::OAuth);
    }

    #[test]
    fn the_untouched_draft_converts_back_to_the_config_it_came_from() {
        let app = app();
        let (account, prefs) = app.to_config().unwrap();
        assert_eq!(account.host, imap_account().host);
        assert_eq!(account.port, imap_account().port);
        assert_eq!(account.username, imap_account().username);
        assert_eq!(account.scan_folders, imap_account().scan_folders);
        assert_eq!(account.archive_folder, imap_account().archive_folder);
        assert_eq!(prefs, preferences());
    }

    // ─── dirty tracking ─────────────────────────────────────────────────────

    #[test]
    fn a_freshly_opened_screen_has_nothing_unsaved() {
        let app = app();
        assert!(!app.is_dirty());
        assert!(Field::ALL.into_iter().all(|f| !app.is_field_dirty(f)));
    }

    #[test]
    fn an_accepted_edit_marks_the_screen_and_the_field_unsaved() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        assert!(app.is_dirty());
        assert!(app.is_field_dirty(Field::ArchiveFolder));
        assert!(!app.is_field_dirty(Field::Host), "only the edited field");
    }

    #[test]
    fn editing_a_field_back_to_its_original_value_is_not_a_change() {
        let mut app = app();
        edit(&mut app, Field::Host, "imap.elsewhere.example.com");
        assert!(app.is_dirty());
        edit(&mut app, Field::Host, "imap.example.com");
        assert!(!app.is_dirty(), "the value matches the file again");
        assert!(!app.is_field_dirty(Field::Host));
    }

    #[test]
    fn cycling_a_choice_field_back_around_is_not_a_change() {
        let mut app = app();
        focus(&mut app, Field::Provider);
        press(&mut app, KeyCode::Enter);
        assert!(app.is_dirty());
        press(&mut app, KeyCode::Enter);
        assert!(!app.is_dirty(), "back to the stored provider");
    }

    #[test]
    fn a_rejected_edit_leaves_the_screen_clean() {
        let mut app = app();
        edit(&mut app, Field::Port, "70000");
        press(&mut app, KeyCode::Esc);
        assert!(!app.is_dirty(), "a refused value is not an unsaved change");
    }

    #[test]
    fn revert_discards_every_pending_change() {
        let mut app = app();
        edit(&mut app, Field::Host, "imap.elsewhere.example.com");
        edit(&mut app, Field::MinEmails, "1");
        press(&mut app, KeyCode::Char('x'));

        assert!(!app.is_dirty());
        assert_eq!(app.draft.host, "imap.example.com");
        assert_eq!(app.draft.min_emails, "5");
        assert_eq!(status_kind(&app), Some(StatusKind::Info));
    }

    #[test]
    fn revert_on_a_clean_screen_says_nothing() {
        let mut app = app();
        press(&mut app, KeyCode::Char('x'));
        assert_eq!(app.status(), None, "there was nothing to revert");
    }

    // ─── saving ─────────────────────────────────────────────────────────────

    #[test]
    fn w_asks_the_event_loop_to_save() {
        let mut app = app();
        assert_eq!(press(&mut app, KeyCode::Char('w')), Action::Save);
    }

    #[test]
    fn a_successful_save_hands_over_the_edited_values_and_clears_the_unsaved_state() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        edit(&mut app, Field::MinEmails, "1");

        let io = FakeIo::new();
        save(&mut app, &io);

        let saved = io.saved.borrow();
        assert_eq!(saved.len(), 1, "exactly one write");
        assert_eq!(saved[0].0.archive_folder, "Archive");
        assert_eq!(saved[0].1.min_emails, 1);
        assert_eq!(
            saved[0].1.cache_max_age_days, 21,
            "untouched preferences go along unchanged"
        );
        assert!(!app.is_dirty());
        assert_eq!(status_kind(&app), Some(StatusKind::Info));
    }

    #[test]
    fn a_save_refused_by_validation_never_reaches_the_store() {
        let mut app = app();
        // Set directly: the editor would have refused this on the way in, and
        // the point here is that `save` refuses it too.
        app.draft.username = String::new();

        let io = FakeIo::new();
        save(&mut app, &io);

        assert!(io.saved.borrow().is_empty(), "an invalid config was written");
        assert_eq!(app.rows[app.cursor], Row::Setting(Field::Username));
        assert_eq!(status_kind(&app), Some(StatusKind::Error));
    }

    #[test]
    fn a_failed_save_keeps_the_changes_and_reports_the_failure() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");

        save(&mut app, &FakeIo::failing());

        assert!(app.is_dirty(), "the edit must survive a failed write");
        assert_eq!(app.draft.archive_folder, "Archive");
        assert_eq!(status_kind(&app), Some(StatusKind::Error));
    }

    #[test]
    fn adopting_values_written_elsewhere_clears_the_unsaved_markers() {
        // The path a reauth takes: the file changed underneath the screen.
        let mut app = app();
        edit(&mut app, Field::Host, "imap.stale.example.com");

        let mut account = imap_account();
        account.host = Some("imap.fresh.example.com".to_string());
        app.adopt(&account, &preferences());

        assert!(!app.is_dirty());
        assert_eq!(app.draft.host, "imap.fresh.example.com");
    }

    // ─── quitting ───────────────────────────────────────────────────────────

    #[test]
    fn leaving_a_clean_screen_needs_no_confirmation() {
        let mut app = app();
        assert_eq!(press(&mut app, KeyCode::Esc), Action::Quit);
    }

    #[test]
    fn q_is_never_back_here_so_it_does_nothing() {
        let mut app = app();
        assert_eq!(press(&mut app, KeyCode::Char('q')), Action::None);
    }

    #[test]
    fn quitting_with_unsaved_changes_asks_first() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        assert_eq!(press(&mut app, KeyCode::Esc), Action::None);
        assert!(matches!(app.mode, Mode::ConfirmQuit));
    }

    #[test]
    fn confirming_the_prompt_quits_and_discards() {
        // The same answer keys as every other confirmation in the app.
        for confirm in [KeyCode::Char('y'), KeyCode::Enter] {
            let mut app = app();
            edit(&mut app, Field::ArchiveFolder, "Archive");
            press(&mut app, KeyCode::Esc);
            assert_eq!(
                press(&mut app, confirm),
                Action::Quit,
                "{confirm:?} should confirm"
            );
        }
    }

    #[test]
    fn any_other_key_at_the_prompt_returns_to_editing_with_the_changes_intact() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        press(&mut app, KeyCode::Esc);

        assert_eq!(press(&mut app, KeyCode::Char('n')), Action::None);
        assert!(is_browsing(&app));
        assert!(app.is_dirty(), "declining must not discard the edit");
        assert_eq!(app.draft.archive_folder, "Archive");
    }

    #[test]
    fn quitting_after_a_save_needs_no_confirmation_again() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        save(&mut app, &FakeIo::new());
        assert_eq!(press(&mut app, KeyCode::Esc), Action::Quit);
    }

    #[test]
    fn quitting_after_a_failed_save_still_asks() {
        let mut app = app();
        edit(&mut app, Field::ArchiveFolder, "Archive");
        save(&mut app, &FakeIo::failing());
        assert_eq!(press(&mut app, KeyCode::Esc), Action::None);
        assert!(matches!(app.mode, Mode::ConfirmQuit));
    }

    // ─── re-authentication warning ──────────────────────────────────────────

    #[test]
    fn an_unedited_screen_does_not_warn_about_re_authentication() {
        assert!(!app().needs_reauth());
    }

    #[test]
    fn changing_the_username_warns_about_re_authentication() {
        let mut app = app();
        edit(&mut app, Field::Username, "someone.else@example.com");
        assert!(app.needs_reauth());
    }

    #[test]
    fn changing_the_provider_warns_about_re_authentication() {
        let mut app = app();
        focus(&mut app, Field::Provider);
        press(&mut app, KeyCode::Enter);
        assert!(app.needs_reauth());
    }

    #[test]
    fn changing_the_auth_type_warns_about_re_authentication() {
        let mut app = app();
        focus(&mut app, Field::AuthType);
        press(&mut app, KeyCode::Enter);
        assert!(app.needs_reauth());
    }

    #[test]
    fn changing_a_field_the_credentials_do_not_depend_on_raises_no_warning() {
        for (field, value) in [
            (Field::Host, "imap.elsewhere.example.com"),
            (Field::Port, "143"),
            (Field::SmtpHost, "smtp.elsewhere.example.com"),
            (Field::SmtpPort, "587"),
            (Field::ArchiveFolder, "Archive"),
            (Field::MinEmails, "1"),
            (Field::StaleAfterMonths, "3"),
            (Field::CacheMaxAgeDays, "1"),
        ] {
            let mut app = app();
            edit(&mut app, field, value);
            assert!(app.is_dirty(), "{field:?} should have changed");
            assert!(!app.needs_reauth(), "{field:?} should not need a reauth");
        }
    }

    #[test]
    fn changing_the_scanned_folders_raises_no_warning() {
        let mut app = app();
        app.open_folder_picker(&["INBOX".to_string(), "Promotions".to_string()], None);
        press(&mut app, KeyCode::Char(' '));
        press(&mut app, KeyCode::Enter);
        assert!(app.is_dirty());
        assert!(!app.needs_reauth());
    }

    #[test]
    fn putting_a_credential_field_back_withdraws_the_warning() {
        let mut app = app();
        edit(&mut app, Field::Username, "someone.else@example.com");
        assert!(app.needs_reauth());
        edit(&mut app, Field::Username, "user@example.com");
        assert!(!app.needs_reauth());
    }

    #[test]
    fn the_reauthenticate_row_hands_the_work_to_the_event_loop() {
        let mut app = app();
        app.cursor = row_index(&app, Row::Reauthenticate);
        assert_eq!(press(&mut app, KeyCode::Enter), Action::Reauthenticate);
    }

    // ─── folder picker ──────────────────────────────────────────────────────

    fn names(strings: &[&str]) -> Vec<String> {
        strings.iter().map(|s| s.to_string()).collect()
    }

    fn picker(app: &SettingsApp) -> &FolderPicker {
        match &app.mode {
            Mode::Folders(picker) => picker,
            other => panic!("expected the folder picker, found {other:?}"),
        }
    }

    #[test]
    fn the_folders_row_asks_the_event_loop_to_fetch_the_folder_list() {
        let mut app = app();
        focus(&mut app, Field::Folders);
        assert_eq!(press(&mut app, KeyCode::Enter), Action::OpenFolderPicker);
    }

    #[test]
    fn the_picker_preselects_exactly_the_configured_folders() {
        let picker = FolderPicker::new(
            &names(&["INBOX", "Promotions", "Archive"]),
            &names(&["INBOX", "Archive"]),
            None,
        );
        assert_eq!(picker.selection(), names(&["INBOX", "Archive"]));
        assert!(
            picker.entries.iter().all(|e| e.on_server),
            "every entry came from the server"
        );
    }

    #[test]
    fn a_configured_folder_the_server_did_not_list_is_kept_and_stays_selected() {
        // A rename or a permissions blip must not silently drop a folder.
        let picker = FolderPicker::new(
            &names(&["INBOX"]),
            &names(&["INBOX", "Vanished"]),
            None,
        );
        let vanished = picker
            .entries
            .iter()
            .find(|e| e.name == "Vanished")
            .expect("the configured folder was dropped");
        assert!(vanished.selected);
        assert!(!vanished.on_server, "it should be flagged as off-server");
        assert_eq!(picker.selection(), names(&["INBOX", "Vanished"]));
    }

    #[test]
    fn the_selection_follows_the_servers_order_with_missing_folders_last() {
        let picker = FolderPicker::new(
            &names(&["Archive", "INBOX"]),
            &names(&["Ghost", "INBOX", "Archive"]),
            None,
        );
        assert_eq!(picker.selection(), names(&["Archive", "INBOX", "Ghost"]));
    }

    #[test]
    fn an_empty_server_list_falls_back_to_free_text_seeded_with_the_configuration() {
        let picker = FolderPicker::new(&[], &names(&["INBOX", "Promotions"]), None);
        assert_eq!(picker.free_text.as_deref(), Some("INBOX, Promotions"));
        assert_eq!(picker.selection(), names(&["INBOX", "Promotions"]));
        assert!(picker.notice.is_some(), "the fallback should explain itself");
    }

    #[test]
    fn a_supplied_notice_survives_the_fallback_to_free_text() {
        let picker = FolderPicker::new(&[], &names(&["INBOX"]), Some("server said no".into()));
        assert_eq!(picker.notice.as_deref(), Some("server said no"));
    }

    #[test]
    fn toggling_flips_only_the_entry_under_the_cursor() {
        let mut picker = FolderPicker::new(
            &names(&["INBOX", "Promotions"]),
            &names(&["INBOX"]),
            None,
        );
        picker.move_down();
        picker.toggle();
        assert_eq!(picker.selection(), names(&["INBOX", "Promotions"]));
        picker.toggle();
        assert_eq!(picker.selection(), names(&["INBOX"]));
    }

    #[test]
    fn the_picker_cursor_stops_at_both_ends() {
        let mut picker = FolderPicker::new(&names(&["a", "b"]), &[], None);
        picker.move_up();
        assert_eq!(picker.cursor, 0);
        picker.move_down();
        picker.move_down();
        picker.move_down();
        assert_eq!(picker.cursor, 1);
    }

    #[test]
    fn a_committed_selection_round_trips_into_scan_folders() {
        let mut app = app();
        app.open_folder_picker(&names(&["INBOX", "Promotions", "Receipts"]), None);

        press(&mut app, KeyCode::Down); // Promotions
        press(&mut app, KeyCode::Char(' ')); // deselect it
        press(&mut app, KeyCode::Down); // Receipts
        press(&mut app, KeyCode::Char(' ')); // select it
        press(&mut app, KeyCode::Enter);

        assert!(is_browsing(&app));
        assert_eq!(app.draft.folders, names(&["INBOX", "Receipts"]));
        let (account, _) = app.to_config().unwrap();
        assert_eq!(account.scan_folders, names(&["INBOX", "Receipts"]));
    }

    #[test]
    fn a_folder_missing_from_the_server_survives_a_save() {
        let mut app = app(); // configured: INBOX, Promotions
        app.open_folder_picker(&names(&["INBOX"]), None); // the server lost one
        press(&mut app, KeyCode::Enter);

        assert_eq!(app.draft.folders, names(&["INBOX", "Promotions"]));
        assert!(!app.is_dirty(), "an untouched list is not a change");

        let io = FakeIo::new();
        save(&mut app, &io);
        assert_eq!(
            io.saved.borrow()[0].0.scan_folders,
            names(&["INBOX", "Promotions"]),
        );
    }

    #[test]
    fn committing_an_empty_selection_is_refused_and_says_so() {
        let mut app = app();
        app.open_folder_picker(&names(&["INBOX", "Promotions"]), None);

        press(&mut app, KeyCode::Char(' ')); // deselect INBOX
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char(' ')); // deselect Promotions
        press(&mut app, KeyCode::Enter);

        assert!(picker(&app).notice.is_some(), "no reason was given");
        assert_eq!(
            app.draft.folders,
            names(&["INBOX", "Promotions"]),
            "the draft must be left alone",
        );
    }

    #[test]
    fn escaping_the_picker_leaves_the_folders_as_they_were() {
        let mut app = app();
        app.open_folder_picker(&names(&["INBOX", "Promotions"]), None);
        press(&mut app, KeyCode::Char(' ')); // deselect INBOX
        press(&mut app, KeyCode::Esc);

        assert!(is_browsing(&app));
        assert_eq!(app.draft.folders, names(&["INBOX", "Promotions"]));
        assert!(!app.is_dirty());
    }

    #[test]
    fn free_text_entry_replaces_the_folder_list() {
        let mut app = app();
        app.open_folder_picker(&[], None); // no list to pick from

        let seeded = picker(&app).free_text.clone().unwrap().chars().count();
        for _ in 0..seeded {
            press(&mut app, KeyCode::Backspace);
        }
        type_chars(&mut app, " Bulk , Junk ,");
        press(&mut app, KeyCode::Enter);

        assert!(is_browsing(&app));
        assert_eq!(
            app.draft.folders,
            names(&["Bulk", "Junk"]),
            "whitespace and trailing separators should be dropped",
        );
    }

    #[test]
    fn free_text_holding_only_separators_is_refused() {
        let mut app = app();
        app.open_folder_picker(&[], None);

        let seeded = picker(&app).free_text.clone().unwrap().chars().count();
        for _ in 0..seeded {
            press(&mut app, KeyCode::Backspace);
        }
        type_chars(&mut app, " , , ");
        press(&mut app, KeyCode::Enter);

        assert!(picker(&app).notice.is_some());
        assert_eq!(app.draft.folders, names(&["INBOX", "Promotions"]));
    }

    #[test]
    fn q_is_typed_into_the_free_text_field_rather_than_closing_it() {
        let mut app = app();
        app.open_folder_picker(&[], None);
        press(&mut app, KeyCode::Char('q'));
        assert!(
            picker(&app).free_text.as_deref().unwrap().ends_with('q'),
            "a folder name may contain a q",
        );
    }
}
