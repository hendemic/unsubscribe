//! Settings screen behind `unsubscribe config`.
//!
//! Navigation, editing, validation, and dirty-state tracking live in
//! [`SettingsApp`] and [`Draft`], which never touch a terminal. [`run`] owns
//! the event loop and drawing, and delegates every side effect (saving,
//! listing folders, re-authenticating) to a [`SettingsIo`] implementation.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io;

use unsubscribe_core::{AccountConfig, AuthType, PreferenceField, Preferences, ProviderType};

use super::{TerminalGuard, Tui};

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

/// One editable setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Provider,
    Host,
    Port,
    Username,
    AuthType,
    SmtpHost,
    SmtpPort,
    Folders,
    ArchiveFolder,
    MinEmails,
    StaleAfterMonths,
    CacheMaxAgeDays,
}

impl Field {
    /// Every field, in the order they appear on screen.
    pub const ALL: [Field; 12] = [
        Field::Provider,
        Field::Host,
        Field::Port,
        Field::Username,
        Field::AuthType,
        Field::SmtpHost,
        Field::SmtpPort,
        Field::Folders,
        Field::ArchiveFolder,
        Field::MinEmails,
        Field::StaleAfterMonths,
        Field::CacheMaxAgeDays,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Field::Provider => "Provider",
            Field::Host => "Host",
            Field::Port => "Port",
            Field::Username => "Username",
            Field::AuthType => "Auth type",
            Field::SmtpHost => "SMTP host",
            Field::SmtpPort => "SMTP port",
            Field::Folders => "Folders",
            Field::ArchiveFolder => "Archive folder",
            Field::MinEmails => "Minimum emails",
            Field::StaleAfterMonths => "Stale after (months)",
            Field::CacheMaxAgeDays => "Cache max age (days)",
        }
    }

    /// Fields with a fixed set of values cycle through them instead of
    /// accepting free text, so they can never hold something unparseable.
    const fn choices(self) -> Option<&'static [&'static str]> {
        match self {
            Field::Provider => Some(&["imap", "gmail"]),
            Field::AuthType => Some(&["password", "oauth"]),
            _ => None,
        }
    }

    /// Whether changing this field invalidates the stored credentials.
    const fn affects_credentials(self) -> bool {
        matches!(self, Field::Provider | Field::Username | Field::AuthType)
    }
}

// ---------------------------------------------------------------------------
// Draft
// ---------------------------------------------------------------------------

/// The settings as text, which is what the user is actually editing.
///
/// Numbers are held as strings so a half-typed or invalid value survives until
/// the user corrects it, rather than being silently coerced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub provider: String,
    pub host: String,
    pub port: String,
    pub username: String,
    pub auth_type: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub folders: Vec<String>,
    pub archive_folder: String,
    pub min_emails: String,
    pub stale_after_months: String,
    pub cache_max_age_days: String,
}

impl Draft {
    pub fn from_config(account: &AccountConfig, preferences: &Preferences) -> Self {
        Self {
            provider: match account.provider_type {
                ProviderType::Gmail => "gmail".to_string(),
                ProviderType::Imap => "imap".to_string(),
            },
            host: account.host.clone().unwrap_or_default(),
            port: account.port.map(|p| p.to_string()).unwrap_or_default(),
            username: account.username.clone(),
            auth_type: match account.auth_type {
                AuthType::OAuth => "oauth".to_string(),
                AuthType::Password => "password".to_string(),
            },
            smtp_host: account.smtp_host.clone().unwrap_or_default(),
            smtp_port: account.smtp_port.map(|p| p.to_string()).unwrap_or_default(),
            folders: account.scan_folders.clone(),
            archive_folder: account.archive_folder.clone(),
            min_emails: preferences.min_emails.to_string(),
            stale_after_months: preferences.stale_after_months.to_string(),
            cache_max_age_days: preferences.cache_max_age_days.to_string(),
        }
    }

    /// The field's value as editable/displayable text.
    pub fn get(&self, field: Field) -> String {
        match field {
            Field::Provider => self.provider.clone(),
            Field::Host => self.host.clone(),
            Field::Port => self.port.clone(),
            Field::Username => self.username.clone(),
            Field::AuthType => self.auth_type.clone(),
            Field::SmtpHost => self.smtp_host.clone(),
            Field::SmtpPort => self.smtp_port.clone(),
            Field::Folders => self.folders.join(", "),
            Field::ArchiveFolder => self.archive_folder.clone(),
            Field::MinEmails => self.min_emails.clone(),
            Field::StaleAfterMonths => self.stale_after_months.clone(),
            Field::CacheMaxAgeDays => self.cache_max_age_days.clone(),
        }
    }

    pub fn set(&mut self, field: Field, value: String) {
        match field {
            Field::Provider => self.provider = value,
            Field::Host => self.host = value,
            Field::Port => self.port = value,
            Field::Username => self.username = value,
            Field::AuthType => self.auth_type = value,
            Field::SmtpHost => self.smtp_host = value,
            Field::SmtpPort => self.smtp_port = value,
            Field::Folders => self.folders = split_folders(&value),
            Field::ArchiveFolder => self.archive_folder = value,
            Field::MinEmails => self.min_emails = value,
            Field::StaleAfterMonths => self.stale_after_months = value,
            Field::CacheMaxAgeDays => self.cache_max_age_days = value,
        }
    }

    /// Advance a fixed-choice field to its next value. No-op for text fields.
    pub fn cycle(&mut self, field: Field) {
        let Some(choices) = field.choices() else {
            return;
        };
        let current = self.get(field);
        let next = choices
            .iter()
            .position(|c| *c == current)
            .map_or(0, |i| (i + 1) % choices.len());
        self.set(field, choices[next].to_string());
    }

    fn is_gmail(&self) -> bool {
        self.provider == "gmail"
    }

    /// Check one field, returning a message suitable for display next to it.
    pub fn validate(&self, field: Field) -> Result<(), String> {
        let value = self.get(field);
        match field {
            // Fixed-choice fields can only hold a value they were cycled to.
            Field::Provider | Field::AuthType => Ok(()),
            // Gmail talks to an API rather than a host, so a blank host is fine there.
            Field::Host if self.is_gmail() => Ok(()),
            Field::Host => require_non_empty(&value, "Host"),
            Field::Username => require_non_empty(&value, "Username"),
            Field::ArchiveFolder => require_non_empty(&value, "Archive folder"),
            Field::Port if self.is_gmail() => optional_port(&value, "Port"),
            Field::Port => require_non_empty(&value, "Port").and(optional_port(&value, "Port")),
            Field::SmtpHost => Ok(()),
            Field::SmtpPort => optional_port(&value, "SMTP port"),
            Field::Folders => {
                if self.folders.is_empty() {
                    Err("At least one folder is required".to_string())
                } else {
                    Ok(())
                }
            }
            Field::MinEmails => preference(&value, PreferenceField::MinEmails).map(|_| ()),
            Field::StaleAfterMonths => {
                preference(&value, PreferenceField::StaleAfterMonths).map(|_| ())
            }
            Field::CacheMaxAgeDays => {
                preference(&value, PreferenceField::CacheMaxAgeDays).map(|_| ())
            }
        }
    }

    /// The first field that fails validation, if any.
    pub fn first_invalid(&self) -> Option<(Field, String)> {
        Field::ALL
            .into_iter()
            .find_map(|field| self.validate(field).err().map(|msg| (field, msg)))
    }

    /// Convert to the shapes the config store writes, or report the first
    /// field that is not usable yet.
    pub fn to_config(&self, account_id_hint: &str) -> Result<(AccountConfig, Preferences), (Field, String)> {
        if let Some(problem) = self.first_invalid() {
            return Err(problem);
        }

        let provider_type = if self.is_gmail() {
            ProviderType::Gmail
        } else {
            ProviderType::Imap
        };
        let auth_type = if self.auth_type == "oauth" {
            AuthType::OAuth
        } else {
            AuthType::Password
        };

        let account = AccountConfig {
            // The username is the account id; the hint only matters when a
            // future multi-account layout keys accounts by something else.
            account_id: if self.username.is_empty() {
                account_id_hint.to_string()
            } else {
                self.username.clone()
            },
            provider_type,
            host: optional_text(&self.host),
            port: self.port.trim().parse().ok(),
            username: self.username.trim().to_string(),
            auth_type,
            scan_folders: self.folders.clone(),
            archive_folder: self.archive_folder.trim().to_string(),
            smtp_host: optional_text(&self.smtp_host),
            smtp_port: self.smtp_port.trim().parse().ok(),
        };

        let preferences = Preferences {
            min_emails: preference(&self.min_emails, PreferenceField::MinEmails)
                .map_err(|e| (Field::MinEmails, e))?,
            stale_after_months: preference(
                &self.stale_after_months,
                PreferenceField::StaleAfterMonths,
            )
            .map_err(|e| (Field::StaleAfterMonths, e))?,
            cache_max_age_days: preference(
                &self.cache_max_age_days,
                PreferenceField::CacheMaxAgeDays,
            )
            .map_err(|e| (Field::CacheMaxAgeDays, e))?,
        };

        Ok((account, preferences))
    }
}

fn optional_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn require_non_empty(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

/// Ports are optional here; a blank one falls back to the protocol default.
fn optional_port(value: &str, label: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    match trimmed.parse::<u32>() {
        Ok(port) if (1..=65535).contains(&port) => Ok(()),
        _ => Err(format!("{label} must be a number between 1 and 65535")),
    }
}

fn preference(value: &str, field: PreferenceField) -> Result<u32, String> {
    let parsed: u32 = value
        .trim()
        .parse()
        .map_err(|_| format!("`{}` must be a whole number", field.key()))?;
    field.validate(parsed)?;
    Ok(parsed)
}

fn split_folders(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

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
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        match &self.mode {
            Mode::Browse => self.on_key_browse(key),
            Mode::Editing { .. } => self.on_key_editing(key),
            Mode::Folders(_) => self.on_key_folders(key),
            Mode::ConfirmQuit => self.on_key_confirm_quit(key),
        }
    }

    fn on_key_browse(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.is_dirty() {
                    self.mode = Mode::ConfirmQuit;
                    Action::None
                } else {
                    Action::Quit
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_up();
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_down();
                Action::None
            }
            KeyCode::Char('s') => Action::Save,
            KeyCode::Char('r') => {
                if self.is_dirty() {
                    self.revert();
                    self.set_status(StatusKind::Info, "Reverted to the saved settings.");
                }
                Action::None
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
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

    fn on_key_editing(&mut self, key: KeyEvent) -> Action {
        let Mode::Editing { field, buffer, .. } = &mut self.mode else {
            return Action::None;
        };
        let field = *field;

        match key.code {
            KeyCode::Esc => self.mode = Mode::Browse,
            KeyCode::Char(c) => buffer.push(c),
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Enter => {
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

    fn on_key_folders(&mut self, key: KeyEvent) -> Action {
        let Mode::Folders(picker) = &mut self.mode else {
            return Action::None;
        };

        // Free-text mode is a single-line editor; the list mode is a checklist.
        if let Some(text) = &mut picker.free_text {
            match key.code {
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Char(c) => text.push(c),
                KeyCode::Backspace => {
                    text.pop();
                }
                KeyCode::Enter => self.commit_folders(),
                _ => {}
            }
            return Action::None;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Browse,
            KeyCode::Up | KeyCode::Char('k') => picker.move_up(),
            KeyCode::Down | KeyCode::Char('j') => picker.move_down(),
            KeyCode::Char(' ') => picker.toggle(),
            KeyCode::Enter => self.commit_folders(),
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

    fn on_key_confirm_quit(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => Action::Quit,
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

fn save(app: &mut SettingsApp, io_ops: &dyn SettingsIo) {
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

/// Leave the alternate screen for the duration of `f`, then take it back.
///
/// The outer `Result` covers restoring the terminal; the inner one is `f`'s.
fn suspended<T>(terminal: &mut Tui, f: impl FnOnce() -> Result<T>) -> Result<Result<T>> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;

    let result = f();

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(result)
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

fn draw(f: &mut Frame, app: &mut SettingsApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(5),    // body
            Constraint::Length(3), // status
            Constraint::Length(2), // help
        ])
        .split(f.area());

    let title = Paragraph::new("Settings")
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    match &mut app.mode {
        Mode::Folders(picker) => draw_folder_picker(f, chunks[1], picker),
        _ => draw_settings(f, chunks[1], app),
    }

    draw_status(f, chunks[2], app);

    let hints = match &app.mode {
        Mode::Browse => " Enter: edit | s: save | r: revert | j/k: move | q: quit",
        Mode::Editing { .. } => " Enter: accept | Esc: cancel",
        Mode::Folders(picker) if picker.free_text.is_some() => " Enter: accept | Esc: cancel",
        Mode::Folders(_) => " Space: toggle | Enter: accept | j/k: move | Esc: cancel",
        Mode::ConfirmQuit => " y: discard changes and quit | any other key: keep editing",
    };
    f.render_widget(
        Paragraph::new(hints).style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
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
