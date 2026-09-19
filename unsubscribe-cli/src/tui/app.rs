//! The app shell: one event loop, one terminal, a stack of screens.
//!
//! Screens answer keys with a [`Nav`] and never perform I/O. Anything that
//! needs the network, a store, or the real stdin comes back as an [`Effect`]
//! for the shell to carry out, which is what keeps every screen drivable from
//! a test and keeps decisions out of the UI.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    annotate_senders, load_cached_senders, record_resumptions, AccountConfig, ConfigStore,
    Credential, DataStore, Preferences, RunPlan, RunPolicy, SenderInfo,
};
use unsubscribe_persistence::{
    FileDataStore, SqliteCacheStore, SqliteHistoryStore, TomlConfigStore,
};

use super::components::{
    render_dialog, render_help, render_status, Dialog, DialogOutcome, StatusMessage,
};
use super::config::{SettingsApp, SettingsIo};
use super::home::{HomeScreen, HomeStats};
use super::select::{App as SelectScreen, SelectAction};
use super::warnings::WarningsScreen;
use super::worker::{self, SelectionContext};
use super::{config, home, select, suspended, warnings, TerminalGuard, Tui};
use crate::commands::config::ConfigIo;
use crate::commands::load_history;
use crate::progress::{CliRunObserver, CliWarningsOnly};
use crate::time::{age_secs_since, format_relative_age, now_unix_secs, utc_to_local_display};

/// How long the loop waits for a key before redrawing anyway.
///
/// Short enough that a transient status message disappears on time and a
/// background worker's progress is never more than a frame stale.
const TICK: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// Shell context
// ---------------------------------------------------------------------------

/// Everything the shell needs to carry out an effect.
///
/// The screens never see this: they are handed the data they display and give
/// back an [`Effect`] when they want something done.
pub struct Context {
    pub config_dir: PathBuf,
    pub account: AccountConfig,
    pub credential: Credential,
    pub preferences: Preferences,
    pub data: FileDataStore,
    pub cache: SqliteCacheStore,
    /// Absent when the history database could not be opened. The app still
    /// runs; it just shows no verdicts.
    pub history: Option<SqliteHistoryStore>,
}

impl Context {
    /// Open the stores and resolve the account, exactly as the CLI does.
    fn load(config_dir: &Path) -> Result<Self> {
        let (account, credential) = crate::load_account(config_dir)?;
        let preferences = TomlConfigStore::new(config_dir).read_preferences()?;
        let cache = SqliteCacheStore::open_default().with_context(|| {
            format!(
                "Failed to open the scan cache at {}.\n\n\
                 The cache is disposable: deleting that file is safe and the next scan rebuilds it.",
                SqliteCacheStore::default_path().display()
            )
        })?;
        // The history is enrichment, not a prerequisite -- the app opens
        // without it and simply shows nothing about past unsubscribes.
        let history = SqliteHistoryStore::open_default().ok();

        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            account,
            credential,
            preferences,
            data: FileDataStore::new(),
            cache,
            history,
        })
    }

    /// The policy the screens judge senders under.
    fn policy(&self, dry_run: bool) -> RunPolicy {
        RunPolicy {
            min_emails: self.preferences.min_emails,
            stale_after_months: self.preferences.stale_after_months,
            grace_period_days: self.preferences.grace_period_days,
            dry_run,
        }
    }

    fn history_store(&self) -> Option<&dyn unsubscribe_core::HistoryStore> {
        self.history
            .as_ref()
            .map(|store| store as &dyn unsubscribe_core::HistoryStore)
    }

    /// Re-read the account and preferences from disk, after something else
    /// rewrote them (a save, a reauth).
    fn reload_account(&mut self) -> Result<()> {
        let (account, credential) = crate::load_account(&self.config_dir)?;
        self.account = account;
        self.credential = credential;
        self.preferences = TomlConfigStore::new(&self.config_dir).read_preferences()?;
        Ok(())
    }

    /// What Home shows, recomputed from the cache and the history.
    fn home_stats(&self) -> HomeStats {
        let cached = load_cached_senders(
            &self.cache,
            &self.account.account_id,
            self.preferences.min_emails,
            &CliWarningsOnly,
        );
        let history = load_history(self.history_store(), &self.account.account_id);
        HomeStats::gather(
            &self.account.account_id,
            cached,
            &history.attempts,
            &history.resumptions,
            &self.policy(false),
            now_unix_secs(),
            self.data.read_warnings().map(|w| w.len()).unwrap_or(0),
        )
    }
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/// What a screen wants the shell to do next.
pub enum Nav {
    /// Nothing; the screen handled the key itself.
    Stay,
    Push(Screen),
    Pop,
    /// Replace the top of the stack, for a screen that hands over rather than
    /// nests (scan \u{2192} selection).
    Replace(Screen),
    Quit,
    /// Something only the shell can do.
    Effect(Effect),
}

/// A side effect the shell performs on a screen's behalf.
pub enum Effect {
    /// Scan the mailbox, ignoring any cached scan.
    Scan,
    /// Review the senders, using the cache when it is worth using.
    Review,
    /// The selection screen was confirmed: ask before anything is sent.
    ConfirmRun,
    OpenHistory,
    OpenWarnings,
    OpenSettings,
    /// Suspend the app and run the `reauth` flow.
    Reauthenticate,
    /// The settings screen asked to persist its draft.
    SettingsSave,
    /// The settings screen asked for the provider's folder list.
    SettingsFolders,
    /// The settings screen asked to re-authenticate.
    SettingsReauth,
}

/// One screen in the stack.
pub enum Screen {
    Home(HomeScreen),
    Select {
        app: Box<SelectScreen>,
        /// The history the selection was annotated against, needed to plan.
        history: Box<SelectionContext>,
    },
    Settings {
        app: Box<SettingsApp>,
        io: Box<ConfigIo>,
    },
    Warnings(WarningsScreen),
}

impl Screen {
    /// The name in the header, and in the help overlay's title.
    fn title(&self) -> &'static str {
        match self {
            Self::Home(_) => "Home",
            Self::Select { .. } => "Review senders",
            Self::Settings { .. } => "Settings",
            Self::Warnings(_) => "Scan warnings",
        }
    }

    fn hints(&self) -> &str {
        match self {
            Self::Home(screen) => screen.hints(),
            Self::Select { app, .. } => app.hints(),
            Self::Settings { app, .. } => config::hints(app),
            Self::Warnings(screen) => screen.hints(),
        }
    }

    /// The keys the help overlay lists for this screen.
    fn keys(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Home(screen) => screen.keys(),
            Self::Select { .. } => vec![
                ("Space", "select or deselect the sender"),
                ("a / n", "select all / none"),
                ("j / k / \u{2191}\u{2193}", "move"),
                ("Ctrl+\u{2191}\u{2193}", "jump five rows"),
                ("g / G", "first / last row"),
                ("Enter", "confirm the selection"),
                ("Esc / q", "back without running"),
            ],
            Self::Settings { .. } => vec![
                ("Enter", "edit the highlighted setting"),
                ("s", "save"),
                ("r", "revert unsaved changes"),
                ("j / k / \u{2191}\u{2193}", "move"),
                ("q / Esc", "back"),
            ],
            Self::Warnings(screen) => screen.keys(),
        }
    }

    /// Whether the screen is taking free text right now, so the shell's own
    /// shortcuts (`?`) must not steal the keystroke.
    fn captures_text(&self) -> bool {
        match self {
            Self::Settings { app, .. } => config::is_editing(app),
            _ => false,
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Nav {
        match self {
            Self::Home(screen) => screen.on_key(key),
            Self::Select { app, .. } => match app.on_key(key) {
                SelectAction::None => Nav::Stay,
                SelectAction::Confirm => Nav::Effect(Effect::ConfirmRun),
                SelectAction::Cancel => Nav::Pop,
            },
            Self::Settings { app, .. } => match app.on_key(key) {
                config::Action::None => Nav::Stay,
                config::Action::Quit => Nav::Pop,
                config::Action::Save => Nav::Effect(Effect::SettingsSave),
                config::Action::OpenFolderPicker => Nav::Effect(Effect::SettingsFolders),
                config::Action::Reauthenticate => Nav::Effect(Effect::SettingsReauth),
            },
            Self::Warnings(screen) => screen.on_key(key),
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect) {
        match self {
            Self::Home(screen) => home::render(f, area, screen),
            Self::Select { app, .. } => select::render(f, area, app),
            Self::Settings { app, .. } => config::render(f, area, app),
            Self::Warnings(screen) => warnings::render(f, area, screen),
        }
    }
}

/// What the shell is waiting for an answer to.
enum Pending {
    /// Confirm before suspending the app to re-authenticate.
    Reauthenticate,
    /// Confirm before a run actually sends anything.
    Run {
        plan: Box<RunPlan>,
    },
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

pub struct Shell {
    ctx: Context,
    stack: Vec<Screen>,
    dialog: Option<Dialog>,
    pending: Option<Pending>,
    status: Option<StatusMessage>,
    help: bool,
    quit: bool,
}

impl Shell {
    fn new(ctx: Context) -> Self {
        let home = HomeScreen::new(ctx.home_stats());
        Self {
            ctx,
            stack: vec![Screen::Home(home)],
            dialog: None,
            pending: None,
            status: None,
            help: false,
            quit: false,
        }
    }

    fn top(&mut self) -> &mut Screen {
        self.stack.last_mut().expect("the stack always holds Home")
    }

    fn title(&self) -> &'static str {
        self.stack
            .last()
            .map(Screen::title)
            .unwrap_or("unsubscribe")
    }

    /// Recompute Home's numbers, for after something changed them.
    fn refresh_home(&mut self) {
        let stats = self.ctx.home_stats();
        if let Some(Screen::Home(home)) = self.stack.first_mut() {
            home.stats = stats;
        }
    }

    fn set_status(&mut self, status: StatusMessage) {
        self.status = Some(status);
    }

    fn fail(&mut self, title: &str, error: &anyhow::Error) {
        self.dialog = Some(Dialog::error(title, format!("{error:#}")));
    }

    // -- the loop ---------------------------------------------------------

    fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        while !self.quit {
            if self.status.as_ref().is_some_and(StatusMessage::expired) {
                self.status = None;
            }
            terminal.draw(|f| self.render(f))?;

            if !event::poll(TICK)? {
                continue;
            }
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    self.on_key(key, terminal)?;
                }
                // Resize redraws on the next pass, which is the next statement.
                _ => {}
            }
        }
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent, terminal: &mut Tui) -> Result<()> {
        // Ctrl-C always leaves, whatever is on screen.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return Ok(());
        }

        if self.help {
            self.help = false;
            return Ok(());
        }

        if let Some(dialog) = self.dialog.as_mut() {
            match dialog.on_key(key) {
                DialogOutcome::Open => {}
                DialogOutcome::Confirmed => {
                    let toggled = dialog.toggled();
                    self.dialog = None;
                    if let Some(pending) = self.pending.take() {
                        self.resolve(pending, toggled, terminal)?;
                    }
                }
                DialogOutcome::Dismissed => {
                    self.dialog = None;
                    self.pending = None;
                }
            }
            return Ok(());
        }

        if key.code == KeyCode::Char('?') && !self.top().captures_text() {
            self.help = true;
            return Ok(());
        }

        match self.top().on_key(key) {
            Nav::Stay => {}
            Nav::Push(screen) => self.stack.push(screen),
            Nav::Pop => {
                // Home is the floor: popping it would leave nothing to draw.
                if self.stack.len() > 1 {
                    self.stack.pop();
                    self.refresh_home();
                }
            }
            Nav::Replace(screen) => {
                self.stack.pop();
                self.stack.push(screen);
            }
            Nav::Quit => self.quit = true,
            Nav::Effect(effect) => self.perform(effect, terminal)?,
        }
        Ok(())
    }

    // -- effects ----------------------------------------------------------

    fn perform(&mut self, effect: Effect, terminal: &mut Tui) -> Result<()> {
        match effect {
            // Until the in-app scan and run screens exist, both hand off to
            // the command that already does this, with the app suspended.
            Effect::Scan => self.handoff_run(terminal, true)?,
            Effect::Review => self.review(terminal)?,
            Effect::ConfirmRun => self.confirm_run(),
            Effect::OpenHistory => {
                self.dialog = Some(Dialog::notice(
                    "History",
                    ["The History screen arrives with the next release.".to_string()],
                ));
            }
            Effect::OpenWarnings => match self.ctx.data.read_warnings() {
                Ok(warnings) => self
                    .stack
                    .push(Screen::Warnings(WarningsScreen::new(warnings))),
                Err(e) => self.fail("Could not read warnings", &e),
            },
            Effect::OpenSettings => self.open_settings(),
            Effect::Reauthenticate => {
                self.pending = Some(Pending::Reauthenticate);
                self.dialog = Some(Dialog::confirm(
                    "Re-authenticate",
                    [
                        format!("Replace the stored credentials for {}?", self.ctx.account.username),
                        String::new(),
                        "The app closes while you sign in, then reopens.".to_string(),
                    ],
                ));
            }
            Effect::SettingsSave => self.settings_save(),
            Effect::SettingsFolders => self.settings_folders(terminal)?,
            Effect::SettingsReauth => self.settings_reauth(terminal)?,
        }
        Ok(())
    }

    fn resolve(&mut self, pending: Pending, toggled: bool, terminal: &mut Tui) -> Result<()> {
        match pending {
            Pending::Run { plan } => self.start_run(*plan, toggled, terminal)?,
            Pending::Reauthenticate => {
                let config_dir = self.ctx.config_dir.clone();
                let outcome = suspended(terminal, || {
                    crate::commands::setup::cmd_reauth(&config_dir)?;
                    press_enter_to_return()
                })?;
                match outcome.and_then(|()| self.ctx.reload_account()) {
                    Ok(()) => {
                        self.refresh_home();
                        self.set_status(StatusMessage::success("Re-authenticated."));
                    }
                    Err(e) => self.fail("Re-authentication failed", &e),
                }
            }
        }
        Ok(())
    }

    /// Open the selection screen on the cached scan.
    ///
    /// With nothing cached there is nothing to review, so this falls through
    /// to a scan. The grouping and the verdicts come from `annotate_senders`,
    /// and what it observes is recorded before the screen opens -- seeing a
    /// sender ignore an unsubscribe is evidence whether or not the user then
    /// cancels.
    fn review(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(cached) = load_cached_senders(
            &self.ctx.cache,
            &self.ctx.account.account_id,
            self.ctx.preferences.min_emails,
            &CliWarningsOnly,
        ) else {
            return self.handoff_run(terminal, true);
        };

        let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
        let policy = self.ctx.policy(false);
        let annotated = annotate_senders(
            &self.ctx.account.account_id,
            cached.senders,
            &stored.attempts,
            &stored.resumptions,
            &policy,
            now_unix_secs(),
        );
        record_resumptions(&annotated, self.ctx.history_store(), &policy, &CliWarningsOnly);

        let history = SelectionContext {
            attempts: stored.attempts,
            resumptions: stored
                .resumptions
                .into_iter()
                .chain(annotated.new_resumptions.iter().cloned())
                .collect(),
        };

        // The shell's header already carries the scan age, so the screen's
        // own timestamp line stays off inside the app.
        let mut app = SelectScreen::new(annotated, self.ctx.preferences);
        app.scan_timestamp = None;

        self.stack.push(Screen::Select {
            app: Box::new(app),
            history: Box::new(history),
        });
        Ok(())
    }

    /// Turn the selection into a plan and ask before anything is sent.
    fn confirm_run(&mut self) {
        let Some(Screen::Select { app, history }) = self.stack.pop() else {
            return;
        };
        let selected: Vec<SenderInfo> = app
            .into_results()
            .into_iter()
            .filter(|(_, selected)| *selected)
            .map(|(sender, _)| sender)
            .collect();

        if selected.is_empty() {
            self.set_status(StatusMessage::warning("Nothing selected."));
            return;
        }

        let plan = worker::plan(
            selected,
            &history,
            &self.ctx.policy(false),
            now_unix_secs(),
        );
        self.dialog = Some(
            Dialog::confirm("Confirm run", plan_summary(&plan)).with_toggle("Dry run", false),
        );
        self.pending = Some(Pending::Run {
            plan: Box::new(plan),
        });
    }

    /// Carry out a confirmed plan.
    ///
    /// Suspended for now, so the existing reporting still shows what happened;
    /// the run screen takes this over.
    fn start_run(&mut self, plan: RunPlan, dry_run: bool, terminal: &mut Tui) -> Result<()> {
        let policy = worker::policy(&self.ctx.preferences, dry_run);
        let account = self.ctx.account.clone();
        let credential = self.ctx.credential.clone();
        let log_path = unsubscribe_persistence::data_dir().join("unsubscribe_log.csv");
        let observer = CliRunObserver::new(dry_run, &account.archive_folder, log_path);

        let outcome = {
            let cache = &self.ctx.cache;
            let history = self.ctx.history_store();
            suspended(terminal, || {
                let outcome = worker::execute(
                    &account,
                    &credential,
                    cache,
                    history,
                    &plan,
                    &policy,
                    &observer,
                )?;
                press_enter_to_return()?;
                Ok(outcome)
            })?
        };

        match outcome {
            Ok(outcome) => {
                self.refresh_home();
                self.set_status(StatusMessage::success(format!(
                    "{} succeeded, {} failed, {} archived.",
                    outcome.succeeded(),
                    outcome.failed(),
                    outcome.archived
                )));
            }
            Err(e) => self.fail("Run failed", &e),
        }
        Ok(())
    }

    /// Suspend the app and run the existing `run` command end to end.
    ///
    /// The interim wiring for the first sub-issue: the app can already reach
    /// the whole flow, and the screens that bring it inside replace this.
    fn handoff_run(&mut self, terminal: &mut Tui, rescan: bool) -> Result<()> {
        let account = self.ctx.account.clone();
        let credential = self.ctx.credential.clone();
        let preferences = self.ctx.preferences;
        let data = FileDataStore::new();
        let outcome = {
            let cache = &self.ctx.cache;
            let history = self.ctx.history_store();
            suspended(terminal, || {
                crate::commands::run::cmd_run(
                    &account,
                    &credential,
                    &data,
                    cache,
                    history,
                    &preferences,
                    false,
                    false,
                    rescan,
                )?;
                press_enter_to_return()
            })?
        };
        match outcome {
            Ok(()) => self.refresh_home(),
            Err(e) => self.fail("Run failed", &e),
        }
        Ok(())
    }

    fn open_settings(&mut self) {
        let io = ConfigIo::new(&self.ctx.config_dir, &self.ctx.account);
        let app = SettingsApp::new(
            &self.ctx.account,
            &self.ctx.preferences,
            io.credential_location(),
        );
        self.stack.push(Screen::Settings {
            app: Box::new(app),
            io: Box::new(io),
        });
    }

    /// The settings screen's own save path, so the app and `unsubscribe
    /// config` persist a draft the same way.
    fn settings_save(&mut self) {
        let Some(Screen::Settings { app, io }) = self.stack.last_mut() else {
            return;
        };
        config::save(app, io.as_ref());
        // The account the rest of the app works from is now the saved one.
        if let Err(e) = self.ctx.reload_account() {
            self.fail("Saved, but the config could not be re-read", &e);
        }
        self.refresh_home();
    }

    fn settings_folders(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(Screen::Settings { io, .. }) = self.stack.last() else {
            return Ok(());
        };
        // Fetched only now, so a slow or unreachable server never delays the
        // screen opening.
        let folders = io.list_folders();
        terminal.draw(|f| {
            let area = f.area();
            f.render_widget(Clear, area);
        })?;
        let Some(Screen::Settings { app, .. }) = self.stack.last_mut() else {
            return Ok(());
        };
        match folders {
            Ok(folders) if folders.is_empty() => app.open_folder_picker(
                &[],
                Some(
                    "This provider has no folder list \u{2014} enter folders separated by commas."
                        .to_string(),
                ),
            ),
            Ok(folders) => app.open_folder_picker(&folders, None),
            Err(e) => app.open_folder_picker(
                &[],
                Some(format!("Could not list folders ({e}) \u{2014} enter them manually.")),
            ),
        }
        Ok(())
    }

    fn settings_reauth(&mut self, terminal: &mut Tui) -> Result<()> {
        let dirty = matches!(
            self.stack.last(),
            Some(Screen::Settings { app, .. }) if app.is_dirty()
        );
        if dirty {
            self.set_status(StatusMessage::warning(
                "Save your changes before re-authenticating.",
            ));
            return Ok(());
        }
        let config_dir = self.ctx.config_dir.clone();
        let outcome = suspended(terminal, || {
            crate::commands::setup::cmd_reauth(&config_dir)?;
            press_enter_to_return()
        })?;
        match outcome.and_then(|()| self.ctx.reload_account()) {
            Ok(()) => {
                let (account, preferences) = (self.ctx.account.clone(), self.ctx.preferences);
                if let Some(Screen::Settings { app, .. }) = self.stack.last_mut() {
                    app.adopt(&account, &preferences);
                }
                self.set_status(StatusMessage::success("Re-authenticated."));
            }
            Err(e) => self.fail("Re-authentication failed", &e),
        }
        Ok(())
    }

    // -- rendering --------------------------------------------------------

    fn render(&mut self, f: &mut Frame) {
        let has_status = self.status.is_some();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),                                // header
                Constraint::Min(5),                                   // screen
                Constraint::Length(u16::from(has_status)),            // status
                Constraint::Length(1),                                // footer
            ])
            .split(f.area());

        f.render_widget(self.header(), chunks[0]);

        let title = self.title();
        let hints = self.stack.last().map(Screen::hints).unwrap_or("").to_string();
        let keys = self.stack.last().map(Screen::keys).unwrap_or_default();

        if let Some(screen) = self.stack.last_mut() {
            screen.render(f, chunks[1]);
        }

        if let Some(status) = &self.status {
            render_status(f, chunks[2], status);
        }

        let footer = match (&self.dialog, self.help) {
            (Some(dialog), _) => dialog.hints().to_string(),
            (None, true) => " any key: close help".to_string(),
            (None, false) => hints,
        };
        f.render_widget(
            Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
            chunks[3],
        );

        if self.help {
            render_help(f, title, &keys);
        }
        if let Some(dialog) = &self.dialog {
            render_dialog(f, dialog);
        }
    }

    /// Account and scan age, on every screen.
    fn header(&self) -> Paragraph<'static> {
        let scan = match self
            .stack
            .first()
            .and_then(|screen| match screen {
                Screen::Home(home) => home.stats.scanned_at.as_deref(),
                _ => None,
            }) {
            None => Span::styled("no scan yet", Style::default().fg(Color::DarkGray)),
            Some(ts) => {
                let when = utc_to_local_display(ts).unwrap_or_else(|| ts.to_string());
                let age = age_secs_since(ts)
                    .map(format_relative_age)
                    .map(|age| format!(" ({age})"))
                    .unwrap_or_default();
                Span::styled(
                    format!("last scan {when}{age}"),
                    Style::default().fg(Color::DarkGray),
                )
            }
        };

        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" unsubscribe", Style::default().fg(Color::Cyan).bold()),
                Span::raw("  "),
                Span::styled(
                    self.ctx.account.username.clone(),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  \u{2014}  "),
                scan,
            ]),
            Line::styled(
                format!(" {}", self.breadcrumb()),
                Style::default().fg(Color::Yellow),
            ),
        ])
    }

    /// Where the user is, as a trail from Home.
    fn breadcrumb(&self) -> String {
        self.stack
            .iter()
            .map(Screen::title)
            .collect::<Vec<_>>()
            .join(" \u{203a} ")
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Whether the app can run here: both halves of the terminal must be real.
#[must_use]
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Launch the app.
///
/// With no config file, the existing `init` wizard runs first -- on the real
/// terminal, before the alternate screen is entered -- and the app opens on
/// whatever it wrote.
pub fn launch(config_dir: &Path) -> Result<()> {
    if !is_interactive() {
        bail!(
            "The app needs an interactive terminal.\n\n\
             Use a subcommand (`unsubscribe run`, `unsubscribe scan`) for scripted runs."
        );
    }
    if !config_dir.join("config.toml").exists() {
        crate::commands::setup::cmd_init(config_dir)?;
    }

    let ctx = Context::load(config_dir)?;
    let mut shell = Shell::new(ctx);

    let (guard, mut terminal) = TerminalGuard::enter()?;
    let result = shell.run(&mut terminal);
    drop(guard);
    result
}

/// What the confirmation dialog says the run will do.
///
/// Three destinations, named the way the plan names them: senders that get an
/// unsubscribe attempt, stale ones that are only archived, and ones with
/// nothing left to try.
fn plan_summary(plan: &RunPlan) -> Vec<String> {
    let mut lines = Vec::new();
    if !plan.to_unsubscribe.is_empty() {
        lines.push(format!(
            "Unsubscribe from {} sender(s) ({} emails).",
            plan.to_unsubscribe.len(),
            plan.unsubscribe_emails()
        ));
    }
    if !plan.archive_only.is_empty() {
        lines.push(format!(
            "Archive {} stale sender(s) without asking ({} emails).",
            plan.archive_only.len(),
            plan.archive_only_emails()
        ));
    }
    if !plan.exhausted.is_empty() {
        lines.push(format!(
            "Archive {} sender(s) with no method left ({} emails).",
            plan.exhausted.len(),
            plan.exhausted_emails()
        ));
    }
    lines.push(String::new());
    lines.push(format!("{} emails in total.", plan.total_emails()));
    lines
}

/// Hold the restored terminal until the user has read what a suspended flow
/// printed. A closed stdin just carries on.
fn press_enter_to_return() -> Result<()> {
    eprint!("\nPress Enter to return to the app... ");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    Ok(())
}
