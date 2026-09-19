//! The app shell: one event loop, one terminal, a nav beside a working area.
//!
//! The left column is the nav; the right is whatever the highlighted section
//! has to show. Focus moves in with `Enter` and out with `Esc`, one level at a
//! time, and the state machine for that lives in [`super::nav::Navigator`] --
//! terminal-free, so the whole model is drivable from a test.
//!
//! Panels answer a [`keys::Action`] with a [`Nav`] and never perform I/O.
//! Anything that needs the network, a store, or the real stdin comes back as
//! an [`Effect`], and [`Shell::apply`] -- the pure half -- is what turns a
//! `Nav` into one. Only [`Shell::perform`] ever sees the terminal.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::sender_histories;
use unsubscribe_core::{
    annotate_senders, decide_scan_action, event_log, load_cached_senders, record_resumptions,
    AccountConfig, CachedScanSummary, ConfigStore, Credential, DataStore, ObtainedSenders,
    Preferences, RunPlan, RunPolicy, ScanAction, SenderInfo,
};
use unsubscribe_persistence::{
    FileDataStore, SqliteCacheStore, SqliteHistoryStore, TomlConfigStore,
};

use super::components::{
    render_dialog, render_help, render_status, Dialog, DialogOutcome, StatusMessage,
};
use super::config::{SettingsApp, SettingsIo};
use super::history::{DetailScreen, HistoryScreen};
use super::keys::{self, Action};
use super::logs::LogsPanel;
use super::nav::{Back, NavOutcome, Navigator, Section};
use super::run::{PlanCounts, RunScreen};
use super::run_panel::{RunPanel, RunStats};
use super::scan::{ScanEnded, ScanScreen};
use super::select::{App as SelectScreen, SelectAction};
use super::warnings::WarningsScreen;
use super::worker::{self, RunShared, ScanShared, SelectionContext};
use super::{
    config, history, logs, run, run_panel, scan, select, suspended, warnings, TerminalGuard, Tui,
};
use crate::commands::config::ConfigIo;
use crate::commands::load_history;
use crate::progress::CliWarningsOnly;
use crate::time::{age_secs_since, format_relative_age, now_unix_secs, scan_max_age_secs,
    utc_to_local_display};

/// How long the loop waits for a key before redrawing anyway.
///
/// Short enough that a transient status message disappears on time and a
/// background worker's progress is never more than a frame stale.
const TICK: Duration = Duration::from_millis(200);

/// Width of the nav column, when there is room for it.
const NAV_WIDTH: u16 = 22;

/// Below this width the two columns do not both fit, so only the focused one
/// is drawn rather than squeezing both into unreadable slivers.
const NARROW: u16 = 56;

// ---------------------------------------------------------------------------
// Shell context
// ---------------------------------------------------------------------------

/// Everything the shell needs to carry out an effect.
///
/// The panels never see this: they are handed the data they display and give
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

    /// The policy the panels judge senders under.
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

    fn cached_senders(&self) -> Option<ObtainedSenders> {
        load_cached_senders(
            &self.cache,
            &self.account.account_id,
            self.preferences.min_emails,
            &CliWarningsOnly,
        )
    }

    /// What core says about the cached scan when a caller demands it.
    ///
    /// The same [`decide_scan_action`] the `run` command asks, so "unsubscribe
    /// from the last scan" is offered exactly when a scripted run would have
    /// found a cache to work from.
    fn cache_action(&self, cached: Option<&ObtainedSenders>) -> ScanAction {
        let summary = cached.map(|cache| CachedScanSummary {
            sender_count: cache.senders.len(),
            age_secs: age_secs_since(&cache.scanned_at),
        });
        decide_scan_action(
            summary,
            true,
            false,
            true,
            scan_max_age_secs(self.preferences.cache_max_age_days),
        )
    }

    /// What the Run panel shows, recomputed from the cache and the history.
    fn run_stats(&self) -> RunStats {
        let cached = self.cached_senders();
        let cache = self.cache_action(cached.as_ref());
        let history = load_history(self.history_store(), &self.account.account_id);
        RunStats::gather(
            &self.account.account_id,
            cached,
            &history.attempts,
            &history.resumptions,
            &self.policy(false),
            now_unix_secs(),
            self.data.read_warnings().map(|w| w.len()).unwrap_or(0),
            cache,
        )
    }
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/// What a panel wants the shell to do next.
pub enum Nav {
    /// Nothing; the panel handled the key itself.
    Stay,
    Push(SubView),
    /// One level back: a sub-view closes, or the nav takes focus again.
    Pop,
    Quit,
    /// Something only the shell can do.
    Effect(Effect),
}

/// A side effect the shell performs on a panel's behalf.
pub enum Effect {
    /// Scan the mailbox, ignoring any cached scan.
    Scan,
    /// Review the senders, using the cache when it is worth using.
    Review,
    /// The selection was confirmed: ask before anything is sent.
    ConfirmRun,
    /// The scan worker reported; act on how it ended.
    ScanEnded,
    /// The run worker reported; refresh what the ending changed.
    RunEnded,
    /// Esc during a scan or a run: ask before stopping.
    ConfirmCancelScan,
    ConfirmCancelRun,
    /// The settings panel asked to persist its draft.
    SettingsSave,
    /// The settings panel asked for the provider's folder list.
    SettingsFolders,
    /// The settings panel asked to re-authenticate.
    SettingsReauth,
    /// A resumed sender's timeline asked for another go at it.
    RunFromHistory,
}

/// A view stacked on top of a section's panel, inside the working area.
///
/// The nav stays on screen throughout, dimmed: a scan or a run is a step of
/// the Run section, not a place of its own.
pub enum SubView {
    Scan(Box<ScanScreen>),
    Select {
        app: Box<SelectScreen>,
        /// The history the selection was annotated against, needed to plan.
        history: Box<SelectionContext>,
    },
    Running(Box<RunScreen>),
    SenderHistory(Box<DetailScreen>),
}

impl SubView {
    /// The name the working area is titled with while this is on top.
    fn title(&self) -> String {
        match self {
            Self::Scan(screen) => format!("Scan \u{2014} {}", screen.state_label()),
            Self::Select { .. } => "Select senders".to_string(),
            Self::Running(screen) => format!("Run \u{2014} {}", screen.state_label()),
            Self::SenderHistory(_) => "Sender timeline".to_string(),
        }
    }

    /// The section this view belongs under, for the nav highlight.
    fn section(&self) -> Section {
        match self {
            Self::SenderHistory(_) => Section::List,
            _ => Section::Run,
        }
    }

    /// Poll a background worker, if this view has one. Called once a frame.
    fn tick(&mut self) -> Nav {
        match self {
            Self::Scan(screen) => screen.tick(),
            Self::Running(screen) => screen.tick(),
            _ => Nav::Stay,
        }
    }

    fn on_action(&mut self, action: Action) -> Nav {
        match self {
            Self::Scan(screen) => screen.on_action(action),
            Self::Running(screen) => screen.on_action(action),
            Self::Select { app, .. } => match app.on_action(action) {
                SelectAction::None => Nav::Stay,
                SelectAction::Confirm => Nav::Effect(Effect::ConfirmRun),
                SelectAction::Cancel => Nav::Pop,
            },
            Self::SenderHistory(screen) => screen.on_action(action),
        }
    }

    fn actions(&self) -> Vec<Action> {
        match self {
            Self::Scan(screen) => screen.actions(),
            Self::Running(screen) => screen.actions(),
            Self::Select { app, .. } => app.actions(),
            Self::SenderHistory(screen) => screen.actions(),
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect) {
        match self {
            Self::Scan(screen) => scan::render(f, area, screen),
            Self::Running(screen) => run::render(f, area, screen),
            Self::Select { app, .. } => select::render(f, area, app),
            Self::SenderHistory(screen) => history::render_detail(f, area, screen),
        }
    }
}

/// The panel behind each section, built on first use and kept.
///
/// Rebuilt only when something it shows has changed, so moving the nav cursor
/// previews a section without touching a store every frame.
#[derive(Default)]
struct Panels {
    run: RunPanel,
    list: Option<Box<HistoryScreen>>,
    warnings: Option<WarningsScreen>,
    logs: Option<Box<LogsPanel>>,
    settings: Option<(Box<SettingsApp>, Box<ConfigIo>)>,
}

/// What the shell is waiting for an answer to.
enum Pending {
    /// Confirm before a run actually sends anything.
    Run {
        plan: Box<RunPlan>,
        counts: Box<PlanCounts>,
    },
    /// The cache-or-rescan question: yes reuses the cached scan, no rescans.
    UseCachedScan {
        cached: Box<ObtainedSenders>,
    },
    CancelScan,
    CancelRun,
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

pub struct Shell {
    ctx: Context,
    nav: Navigator,
    panels: Panels,
    /// Views stacked on the panel of [`Self::stack_section`]. A scan or a run
    /// keeps running while the user looks at another section, so the stack
    /// remembers which section it belongs to rather than being thrown away.
    stack: Vec<SubView>,
    stack_section: Section,
    dialog: Option<Dialog>,
    pending: Option<Pending>,
    status: Option<StatusMessage>,
    quit: bool,
}

impl Shell {
    fn new(ctx: Context) -> Self {
        let run = RunPanel::new(ctx.run_stats());
        Self {
            ctx,
            nav: Navigator::default(),
            panels: Panels {
                run,
                ..Panels::default()
            },
            stack: Vec::new(),
            stack_section: Section::Run,
            dialog: None,
            pending: None,
            status: None,
            quit: false,
        }
    }

    // -- where the keys go ------------------------------------------------

    /// The sub-view on top of the section the nav is highlighting, if any.
    fn active_sub_view(&self) -> Option<&SubView> {
        (self.nav.section() == self.stack_section)
            .then(|| self.stack.last())
            .flatten()
    }

    fn active_sub_view_mut(&mut self) -> Option<&mut SubView> {
        (self.nav.section() == self.stack_section)
            .then(|| self.stack.last_mut())
            .flatten()
    }

    /// How many levels `Esc` has to climb before it reaches the nav.
    fn depth(&self) -> usize {
        if self.nav.section() == self.stack_section {
            self.stack.len()
        } else {
            0
        }
    }

    /// Whether whatever has focus is taking free text right now, so the
    /// shell's own shortcuts (`?`, `q`) must not steal the keystroke.
    fn captures_text(&self) -> bool {
        if self.nav.nav_has_focus() {
            return false;
        }
        match self.active_sub_view() {
            Some(_) => false,
            None => match self.nav.section() {
                Section::List => self
                    .panels
                    .list
                    .as_ref()
                    .is_some_and(|list| list.captures_text()),
                Section::Logs => self
                    .panels
                    .logs
                    .as_ref()
                    .is_some_and(|logs| logs.captures_text()),
                Section::Settings => self
                    .panels
                    .settings
                    .as_ref()
                    .is_some_and(|(app, _)| app.captures_text()),
                _ => false,
            },
        }
    }

    /// The actions whatever has focus answers, for the footer and the `?`
    /// overlay. Both are generated from this, so they cannot disagree.
    fn focus_actions(&self) -> Vec<Action> {
        if self.nav.nav_has_focus() {
            return vec![
                Action::MoveUp,
                Action::MoveDown,
                Action::Activate,
                Action::Help,
                Action::Quit,
            ];
        }
        if let Some(view) = self.active_sub_view() {
            return view.actions();
        }
        match self.nav.section() {
            Section::Run => self.panels.run.actions(),
            Section::List => self
                .panels
                .list
                .as_ref()
                .map(|list| list.actions())
                .unwrap_or_default(),
            Section::Warnings => self
                .panels
                .warnings
                .as_ref()
                .map(WarningsScreen::actions)
                .unwrap_or_default(),
            Section::Logs => self
                .panels
                .logs
                .as_ref()
                .map(|logs| logs.actions())
                .unwrap_or_default(),
            Section::Settings => self
                .panels
                .settings
                .as_ref()
                .map(|(app, _)| app.actions())
                .unwrap_or_default(),
            Section::Quit => Vec::new(),
        }
    }

    /// The title of the working area: the sub-view on top, or the section.
    fn panel_title(&self) -> String {
        self.active_sub_view()
            .map(SubView::title)
            .unwrap_or_else(|| self.nav.section().label().to_string())
    }

    // -- panel loading -----------------------------------------------------

    /// Build the highlighted section's panel if it has not been built yet.
    ///
    /// Lazy so that opening the app never reads the history, and cached so
    /// that walking the nav does not re-read it on every keypress.
    fn ensure_panel(&mut self, section: Section) {
        match section {
            Section::List if self.panels.list.is_none() => {
                self.panels.list = Some(Box::new(HistoryScreen::new(self.sender_views())));
            }
            Section::Warnings if self.panels.warnings.is_none() => {
                let warnings = self.ctx.data.read_warnings().unwrap_or_default();
                self.panels.warnings = Some(WarningsScreen::new(warnings));
            }
            Section::Logs if self.panels.logs.is_none() => {
                let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
                self.panels.logs = Some(Box::new(LogsPanel::new(event_log(
                    &stored.attempts,
                    &stored.resumptions,
                ))));
            }
            Section::Settings if self.panels.settings.is_none() => {
                let io = ConfigIo::new(&self.ctx.config_dir, &self.ctx.account);
                let app = SettingsApp::new(
                    &self.ctx.account,
                    &self.ctx.preferences,
                    io.credential_location(),
                );
                self.panels.settings = Some((Box::new(app), Box::new(io)));
            }
            _ => {}
        }
    }

    /// One view per sender, reduced in core.
    ///
    /// Loaded in one go rather than queried as the user scrolls: the reduction
    /// is pure and a few thousand attempts collapse to one row per sender.
    fn sender_views(&self) -> Vec<unsubscribe_core::SenderHistoryView> {
        let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
        let scanned = self
            .ctx
            .cached_senders()
            .map(|cached| cached.senders)
            .unwrap_or_default();
        sender_histories(
            &stored.attempts,
            &stored.resumptions,
            &scanned,
            now_unix_secs(),
            self.ctx.preferences.grace_period_days,
        )
    }

    /// Recompute everything a completed run changed.
    fn refresh(&mut self) {
        self.panels.run.stats = self.ctx.run_stats();
        // The history-backed panels are stale now; they rebuild on next use.
        self.panels.list = None;
        self.panels.logs = None;
        self.panels.warnings = None;
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
            self.ensure_panel(self.nav.section());
            // Workers report between frames, so the screen is never more than
            // one tick behind what the pipeline has done -- and they report
            // even while the user is looking at another section.
            let nav = self
                .stack
                .last_mut()
                .map(SubView::tick)
                .unwrap_or(Nav::Stay);
            self.dispatch(nav, terminal)?;

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
        // Ctrl-C always leaves, whatever is on screen. Answered before the
        // key map so that no panel and no text field can swallow it.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return Ok(());
        }

        if self.nav.help {
            self.nav.help = false;
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

        let Some(action) = keys::action(key, self.captures_text()) else {
            return Ok(());
        };
        if action == Action::Help {
            self.nav.help = true;
            return Ok(());
        }

        let nav = self.dispatch_action(action);
        self.dispatch(nav, terminal)
    }

    /// Hand one action to whatever has focus.
    fn dispatch_action(&mut self, action: Action) -> Nav {
        if self.nav.nav_has_focus() {
            return match self.nav.on_action(action) {
                NavOutcome::Stay => Nav::Stay,
                NavOutcome::Quit => Nav::Quit,
                NavOutcome::Help => {
                    self.nav.help = true;
                    Nav::Stay
                }
                NavOutcome::Entered(section) => {
                    self.ensure_panel(section);
                    Nav::Stay
                }
            };
        }

        // Inside the working area, Left is the same one-level step as Esc.
        let action = match action {
            Action::FocusOut => Action::Back,
            other => other,
        };
        if let Some(view) = self.active_sub_view_mut() {
            return view.on_action(action);
        }
        match self.nav.section() {
            Section::Run => self.panels.run.on_action(action),
            Section::List => self
                .panels
                .list
                .as_mut()
                .map(|list| list.on_action(action))
                .unwrap_or(Nav::Stay),
            Section::Warnings => self
                .panels
                .warnings
                .as_mut()
                .map(|screen| screen.on_action(action))
                .unwrap_or(Nav::Stay),
            Section::Logs => self
                .panels
                .logs
                .as_mut()
                .map(|logs| logs.on_action(action))
                .unwrap_or(Nav::Stay),
            Section::Settings => self
                .panels
                .settings
                .as_mut()
                .map(|(app, _)| match app.on_action(action) {
                    config::Action::None => Nav::Stay,
                    config::Action::Quit => Nav::Pop,
                    config::Action::Save => Nav::Effect(Effect::SettingsSave),
                    config::Action::OpenFolderPicker => Nav::Effect(Effect::SettingsFolders),
                    config::Action::Reauthenticate => Nav::Effect(Effect::SettingsReauth),
                })
                .unwrap_or(Nav::Stay),
            Section::Quit => Nav::Stay,
        }
    }

    fn dispatch(&mut self, nav: Nav, terminal: &mut Tui) -> Result<()> {
        match self.apply(nav) {
            Some(effect) => self.perform(effect, terminal),
            None => Ok(()),
        }
    }

    /// The pure half of carrying out what a panel asked for.
    ///
    /// Everything that only moves state happens here; what is left is the
    /// effect the shell has to run against the world, which is the only part
    /// that needs a terminal.
    fn apply(&mut self, nav: Nav) -> Option<Effect> {
        match nav {
            Nav::Stay => None,
            Nav::Push(view) => {
                self.push(view);
                None
            }
            Nav::Pop => {
                self.back();
                None
            }
            Nav::Quit => {
                self.quit = true;
                None
            }
            Nav::Effect(effect) => Some(effect),
        }
    }

    /// Open a sub-view inside its section's working area.
    fn push(&mut self, view: SubView) {
        let section = view.section();
        if self.stack_section != section {
            // A stack belongs to one section; opening a view under another
            // replaces it rather than interleaving two stories.
            self.stack.clear();
            self.stack_section = section;
        }
        self.stack.push(view);
        self.nav.enter_panel(section);
    }

    /// One level back, and never past the nav.
    fn back(&mut self) {
        match self.nav.back(self.depth()) {
            Back::PopSubView => {
                self.stack.pop();
                self.dismiss_dialog();
                self.refresh();
            }
            Back::ToNav => {
                self.nav.focus_nav();
                self.dismiss_dialog();
            }
            Back::Nothing => {}
        }
    }

    /// Close whatever was being asked, because what it was about has gone.
    fn dismiss_dialog(&mut self) {
        self.dialog = None;
        self.pending = None;
    }

    // -- effects ----------------------------------------------------------

    fn perform(&mut self, effect: Effect, terminal: &mut Tui) -> Result<()> {
        match effect {
            Effect::Scan => self.start_scan(),
            Effect::Review => self.review(),
            Effect::ConfirmRun => self.confirm_run(),
            Effect::ScanEnded => self.scan_ended(),
            Effect::RunEnded => {
                self.refresh();
                // The screen keeps its summary; a failure also gets a modal,
                // because an archive that did not happen is not a detail.
                let failure = match self.stack.last() {
                    Some(SubView::Running(screen)) => screen.failure().map(str::to_string),
                    _ => None,
                };
                if let Some(message) = failure {
                    self.dialog = Some(Dialog::error("Run failed", message));
                }
            }
            Effect::ConfirmCancelScan => {
                self.pending = Some(Pending::CancelScan);
                self.dialog = Some(Dialog::confirm(
                    "Cancel the scan",
                    [
                        "Stop scanning and throw away what has been read?".to_string(),
                        String::new(),
                        "The last complete scan stays in the cache, untouched.".to_string(),
                    ],
                ));
            }
            Effect::ConfirmCancelRun => {
                self.pending = Some(Pending::CancelRun);
                self.dialog = Some(Dialog::confirm(
                    "Cancel the run",
                    [
                        "Stop after the sender being attempted now?".to_string(),
                        String::new(),
                        "Attempts already made stay recorded, and the senders \
                         already handled are still archived."
                            .to_string(),
                    ],
                ));
            }
            Effect::RunFromHistory => self.run_from_history(),
            Effect::SettingsSave => self.settings_save(),
            Effect::SettingsFolders => self.settings_folders(terminal)?,
            Effect::SettingsReauth => self.settings_reauth(terminal)?,
        }
        Ok(())
    }

    fn resolve(&mut self, pending: Pending, toggled: bool, terminal: &mut Tui) -> Result<()> {
        let _ = terminal;
        match pending {
            Pending::Run { plan, counts } => self.start_run(*plan, *counts, toggled),
            Pending::UseCachedScan { cached } => self.open_selection(*cached),
            Pending::CancelScan => {
                if let Some(SubView::Scan(screen)) = self.stack.last_mut() {
                    screen.request_cancel();
                }
            }
            Pending::CancelRun => {
                if let Some(SubView::Running(screen)) = self.stack.last_mut() {
                    screen.request_cancel();
                }
            }
        }
        Ok(())
    }

    /// Decide between the cached scan and a fresh one, then act on it.
    ///
    /// The decision is [`decide_scan_action`] in core -- the same function the
    /// `run` command asks -- so the app and a scripted run never disagree
    /// about when a cache is too old to trust.
    fn review(&mut self) {
        let usable = self.ctx.cached_senders();
        let summary = usable.as_ref().map(|cache| CachedScanSummary {
            sender_count: cache.senders.len(),
            age_secs: age_secs_since(&cache.scanned_at),
        });
        let action = decide_scan_action(
            summary,
            false,
            false,
            true,
            scan_max_age_secs(self.ctx.preferences.cache_max_age_days),
        );

        match action {
            ScanAction::UseCache => {
                self.open_selection(usable.expect("UseCache implies a usable cache"));
            }
            // Nothing cached, or the caller demanded a cache that is not
            // there; either way the mailbox is the only source left.
            ScanAction::Rescan | ScanAction::CacheUnavailable => self.start_scan(),
            ScanAction::Ask { default_cached } => {
                let cached = usable.expect("Ask implies a usable cache");
                let age = age_secs_since(&cached.scanned_at)
                    .map(format_relative_age)
                    .map(|age| format!(" ({age})"))
                    .unwrap_or_default();
                let when = utc_to_local_display(&cached.scanned_at)
                    .unwrap_or_else(|| cached.scanned_at.clone());
                self.dialog = Some(
                    Dialog::confirm(
                        "Use the cached scan?",
                        [
                            format!("Last scan {when}{age}."),
                            format!("{} senders with unsubscribe links.", cached.senders.len()),
                            String::new(),
                            if default_cached {
                                "Recent enough to reuse.".to_string()
                            } else {
                                "Older than your cache_max_age_days \u{2014} a rescan is suggested."
                                    .to_string()
                            },
                        ],
                    )
                    .with_hints(" y: use the cached scan | n/Esc: scan the mailbox again"),
                );
                self.pending = Some(Pending::UseCachedScan {
                    cached: Box::new(cached),
                });
            }
        }
    }

    /// Start a scan on a worker thread and show it.
    fn start_scan(&mut self) {
        let shared = ScanShared::new();
        let outcome = worker::spawn_scan(
            self.ctx.account.clone(),
            self.ctx.credential.clone(),
            self.ctx.preferences,
            Arc::clone(&shared),
        );
        self.push(SubView::Scan(Box::new(ScanScreen::new(shared, outcome))));
    }

    /// Act on how a scan ended.
    fn scan_ended(&mut self) {
        let Some(SubView::Scan(screen)) = self.stack.pop() else {
            return;
        };
        self.dismiss_dialog();
        match screen.into_ended() {
            ScanEnded::Done(obtained) => {
                if obtained.senders.is_empty() {
                    self.refresh();
                    self.set_status(StatusMessage::warning(
                        "No senders with unsubscribe links found.",
                    ));
                    return;
                }
                self.open_selection(*obtained);
            }
            ScanEnded::Cancelled => {
                self.refresh();
                self.set_status(StatusMessage::warning(
                    "Scan cancelled \u{2014} the previous scan is untouched.",
                ));
            }
            ScanEnded::Failed(message) => {
                self.refresh();
                self.dialog = Some(Dialog::error("Scan failed", message));
            }
        }
    }

    /// Annotate senders against the history and open the selection sub-view.
    ///
    /// Observe, then judge: what the annotation reveals is recorded before the
    /// view opens, because seeing a sender ignore an unsubscribe is evidence
    /// whether or not the user then cancels -- and it is what makes the
    /// ignored rung spent when the plan is built.
    fn open_selection(&mut self, obtained: ObtainedSenders) {
        let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
        let policy = self.ctx.policy(false);
        let annotated = annotate_senders(
            &self.ctx.account.account_id,
            obtained.senders,
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

        // The Run panel behind this already carries the scan age, so the
        // view's own timestamp line stays off inside the app.
        let mut app = SelectScreen::new(annotated, self.ctx.preferences);
        app.scan_timestamp = None;

        self.push(SubView::Select {
            app: Box::new(app),
            history: Box::new(history),
        });
    }

    /// Turn the selection into a plan and ask before anything is sent.
    ///
    /// The selection view stays up: the question is asked over it, so
    /// declining leaves every tick where the user put it.
    fn confirm_run(&mut self) {
        let Some(SubView::Select { app, history }) = self.stack.last() else {
            return;
        };
        let selected: Vec<SenderInfo> = app.selected_senders();

        if selected.is_empty() {
            self.set_status(StatusMessage::warning("Nothing selected."));
            return;
        }

        let plan = worker::plan(selected, history, &self.ctx.policy(false), now_unix_secs());
        let counts = PlanCounts::of(&plan);
        self.dialog = Some(
            Dialog::confirm("Confirm run", plan_summary(&plan)).with_toggle("Dry run", false),
        );
        self.pending = Some(Pending::Run {
            plan: Box::new(plan),
            counts: Box::new(counts),
        });
    }

    /// Carry out a confirmed plan on a worker thread.
    ///
    /// The selection view goes now rather than at confirmation time: its
    /// senders are in the plan, and coming back to it would offer a second run
    /// over mail that has just been archived.
    fn start_run(&mut self, plan: RunPlan, counts: PlanCounts, dry_run: bool) {
        if matches!(self.stack.last(), Some(SubView::Select { .. })) {
            self.stack.pop();
        }
        let policy = worker::policy(&self.ctx.preferences, dry_run);
        let shared = RunShared::new();
        let result = worker::spawn_run(
            self.ctx.account.clone(),
            self.ctx.credential.clone(),
            plan,
            policy,
            Arc::clone(&shared),
        );
        self.push(SubView::Running(Box::new(RunScreen::new(
            shared, result, counts, dry_run,
        ))));
    }

    /// Send one sender from its timeline straight to the run confirmation.
    ///
    /// Only reachable for a resumed sender that is in the current scan, which
    /// is the only case where there is mail to act on and a rung to climb to.
    fn run_from_history(&mut self) {
        let Some(SubView::SenderHistory(detail)) = self.stack.last() else {
            return;
        };
        let (email, list_id) = detail.sender();
        let (email, list_id) = (email.to_string(), list_id.map(str::to_string));

        let sender = self.ctx.cached_senders().and_then(|cached| {
            cached.senders.into_iter().find(|sender| {
                sender.email.eq_ignore_ascii_case(&email) && sender.list_id == list_id
            })
        });
        let Some(sender) = sender else {
            self.set_status(StatusMessage::warning(
                "That sender is no longer in the cached scan \u{2014} scan again first.",
            ));
            return;
        };

        let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
        let history = SelectionContext {
            attempts: stored.attempts,
            resumptions: stored.resumptions,
        };
        let plan = worker::plan(
            vec![sender],
            &history,
            &self.ctx.policy(false),
            now_unix_secs(),
        );
        let counts = PlanCounts::of(&plan);
        self.dialog = Some(
            Dialog::confirm("Confirm run", plan_summary(&plan)).with_toggle("Dry run", false),
        );
        self.pending = Some(Pending::Run {
            plan: Box::new(plan),
            counts: Box::new(counts),
        });
    }

    /// The settings panel's own save path, so the app and `unsubscribe
    /// config` persist a draft the same way.
    fn settings_save(&mut self) {
        let Some((app, io)) = self.panels.settings.as_mut() else {
            return;
        };
        config::save(app, io.as_ref());
        // The account the rest of the app works from is now the saved one.
        if let Err(e) = self.ctx.reload_account() {
            self.fail("Saved, but the config could not be re-read", &e);
        }
        self.panels.run.stats = self.ctx.run_stats();
    }

    fn settings_folders(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some((_, io)) = self.panels.settings.as_ref() else {
            return Ok(());
        };
        // Fetched only now, so a slow or unreachable server never delays the
        // panel opening.
        let folders = io.list_folders();
        terminal.draw(|f| {
            let area = f.area();
            f.render_widget(Clear, area);
        })?;
        let Some((app, _)) = self.panels.settings.as_mut() else {
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
        let dirty = self
            .panels
            .settings
            .as_ref()
            .is_some_and(|(app, _)| app.is_dirty());
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
                if let Some((app, _)) = self.panels.settings.as_mut() {
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
                Constraint::Length(1),                     // header
                Constraint::Min(5),                        // nav + working area
                Constraint::Length(u16::from(has_status)), // status
                Constraint::Length(1),                     // footer
            ])
            .split(f.area());

        f.render_widget(self.header(), chunks[0]);
        self.render_columns(f, chunks[1]);

        if let Some(status) = &self.status {
            render_status(f, chunks[2], status);
        }

        let actions = self.focus_actions();
        let footer = match (&self.dialog, self.nav.help) {
            (Some(dialog), _) => dialog.hints().to_string(),
            (None, true) => " any key: close help".to_string(),
            (None, false) => keys::hints(&actions),
        };
        f.render_widget(
            Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
            chunks[3],
        );

        if self.nav.help {
            let title = if self.nav.nav_has_focus() {
                "Navigation".to_string()
            } else {
                self.panel_title()
            };
            render_help(f, &title, &keys::help_rows(&actions));
        }
        if let Some(dialog) = &self.dialog {
            render_dialog(f, dialog);
        }
    }

    /// The nav on the left, the working area on the right.
    ///
    /// On a narrow terminal the two do not both fit, so only the pane with
    /// focus is drawn; nothing is squeezed into an unreadable sliver.
    fn render_columns(&mut self, f: &mut Frame, area: Rect) {
        if area.width < NARROW {
            if self.nav.nav_has_focus() {
                self.render_nav(f, area);
            } else {
                self.render_panel(f, area);
            }
            return;
        }

        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(NAV_WIDTH), Constraint::Min(20)])
            .split(area);

        self.render_nav(f, columns[0]);
        self.render_panel(f, columns[1]);
    }

    fn render_nav(&self, f: &mut Frame, area: Rect) {
        let focused = self.nav.nav_has_focus();
        let warnings = self.panels.run.stats.warnings;

        let rows: Vec<Line> = Section::ALL
            .iter()
            .enumerate()
            .flat_map(|(index, section)| {
                let badge = match (section, warnings) {
                    (Section::Warnings, 0) => String::new(),
                    (Section::Warnings, n) => format!(" ({n})"),
                    _ => String::new(),
                };
                let marker = if index == self.nav.cursor() { ">" } else { " " };
                let style = match (index == self.nav.cursor(), focused) {
                    (true, true) => Style::default().bg(Color::DarkGray).fg(Color::White).bold(),
                    (true, false) => Style::default().fg(Color::Cyan),
                    _ => Style::default().fg(Color::Gray),
                };
                // Quit sits apart: it is a way out, not a place to look at.
                let spacer = (*section == Section::Quit).then(|| Line::raw(""));
                spacer.into_iter().chain([Line::styled(
                    format!(" {marker} {}{badge}", section.label()),
                    style,
                )])
            })
            .collect();

        f.render_widget(
            Paragraph::new(rows).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style(focused)),
            ),
            area,
        );
    }

    /// The working area: a title line in the focus colour, then the content.
    ///
    /// No box of its own -- several panels draw their own, and a border around
    /// a border reads as a frame rather than as focus. Focus shows in the
    /// title's colour, in the nav's border, and in the cursor highlight, which
    /// only the focused pane draws.
    fn render_panel(&mut self, f: &mut Frame, area: Rect) {
        let focused = !self.nav.nav_has_focus();
        let title = self.panel_title();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(area);
        f.render_widget(
            Paragraph::new(Line::styled(
                format!(" {title}"),
                if focused {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            )),
            chunks[0],
        );

        let inner = chunks[1];
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        if let Some(view) = self.active_sub_view_mut() {
            view.render(f, inner);
            return;
        }
        match self.nav.section() {
            Section::Run => run_panel::render(f, inner, &self.panels.run, focused),
            Section::List => match self.panels.list.as_mut() {
                Some(list) => history::render_list(f, inner, list),
                None => {}
            },
            Section::Warnings => match self.panels.warnings.as_mut() {
                Some(screen) => warnings::render(f, inner, screen),
                None => {}
            },
            Section::Logs => match self.panels.logs.as_mut() {
                Some(panel) => logs::render(f, inner, panel, focused),
                None => {}
            },
            Section::Settings => match self.panels.settings.as_mut() {
                Some((app, _)) => config::render(f, inner, app),
                None => {}
            },
            Section::Quit => f.render_widget(
                Paragraph::new(vec![
                    Line::raw(""),
                    Line::styled(" Leave the app.", Style::default().fg(Color::DarkGray)),
                ]),
                inner,
            ),
        }
    }

    /// One line: what this is, and whose mailbox it is looking at.
    fn header(&self) -> Paragraph<'static> {
        Paragraph::new(Line::from(vec![
            Span::styled(" Unsubscribe", Style::default().fg(Color::Cyan).bold()),
            Span::styled(" \u{00b7} ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                self.ctx.account.username.clone(),
                Style::default().fg(Color::White),
            ),
        ]))
    }
}

/// Cyan for the pane with focus, dim grey for the other.
fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use unsubscribe_core::{
        annotate_senders, FolderMessage, MessageId, NextStep, PlannedSender, SenderHistoryView,
        TimelineEvent, UnsubscribeMethod,
    };

    /// What a `Nav` is, for asserting on without a shell.
    fn nav_name(nav: &Nav) -> &'static str {
        match nav {
            Nav::Stay => "stay",
            Nav::Push(_) => "push",
            Nav::Pop => "pop",
            Nav::Quit => "quit",
            Nav::Effect(Effect::ConfirmRun) => "confirm run",
            Nav::Effect(_) => "other effect",
        }
    }

    fn sender(email: &str, count: u32) -> SenderInfo {
        SenderInfo {
            display_name: "Acme News".to_string(),
            email: email.to_string(),
            domain: "acme.example.com".to_string(),
            unsubscribe_urls: vec!["https://acme.example.com/unsub".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: true,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: count,
            messages: vec![FolderMessage {
                folder: unsubscribe_core::Folder::new("INBOX"),
                message_id: MessageId::new("INBOX:1"),
            }],
            last_seen: None,
        }
    }

    fn policy() -> RunPolicy {
        RunPolicy {
            min_emails: 1,
            stale_after_months: 12,
            grace_period_days: 14,
            dry_run: false,
        }
    }

    fn selection_view() -> SubView {
        let annotated = annotate_senders(
            "user@example.com",
            vec![sender("one@acme.example.com", 3)],
            &[],
            &[],
            &policy(),
            0,
        );
        SubView::Select {
            app: Box::new(SelectScreen::new(annotated, Preferences::default())),
            history: Box::new(SelectionContext::default()),
        }
    }

    fn timeline_view() -> SenderHistoryView {
        SenderHistoryView {
            sender_email: "one@acme.example.com".to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: None,
            last_attempt_at: 0,
            last_method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            outcome: None,
            violation_count: 0,
            next_step: None,
            timeline: Vec::<TimelineEvent>::new(),
        }
    }

    /// One sub-view of each kind the shell can open without a store.
    fn sub_views() -> Vec<SubView> {
        let (_, scan_rx) = mpsc::channel();
        let (_, run_rx) = mpsc::channel();
        vec![
            SubView::Scan(Box::new(ScanScreen::new(ScanShared::new(), scan_rx))),
            SubView::Running(Box::new(RunScreen::new(
                RunShared::new(),
                run_rx,
                PlanCounts::default(),
                false,
            ))),
            selection_view(),
            SubView::SenderHistory(Box::new(DetailScreen::new(timeline_view()))),
        ]
    }

    // -- the sub-view contract ----------------------------------------------

    #[test]
    fn every_sub_view_names_itself_for_the_working_areas_title() {
        for view in sub_views() {
            assert!(!view.title().is_empty());
        }
    }

    #[test]
    fn every_sub_view_offers_a_footer_hint_and_a_help_listing() {
        for view in sub_views() {
            let actions = view.actions();
            assert!(!actions.is_empty(), "{}", view.title());
            assert!(!keys::hints(&actions).trim().is_empty(), "{}", view.title());
            assert!(!keys::help_rows(&actions).is_empty(), "{}", view.title());
        }
    }

    #[test]
    fn a_sub_view_with_no_worker_has_nothing_to_report_each_frame() {
        for mut view in sub_views() {
            let title = view.title();
            match view {
                // These two do poll a worker; the rest must stay quiet.
                SubView::Scan(_) | SubView::Running(_) => {}
                _ => assert_eq!(nav_name(&view.tick()), "stay", "{title}"),
            }
        }
    }

    #[test]
    fn a_scan_belongs_to_run_and_a_timeline_to_the_unsubscribe_list() {
        for view in sub_views() {
            let expected = match view {
                SubView::SenderHistory(_) => Section::List,
                _ => Section::Run,
            };
            assert_eq!(view.section(), expected, "{}", view.title());
        }
    }

    // -- key dispatch --------------------------------------------------------

    #[test]
    fn confirming_the_selection_asks_the_shell_before_anything_is_sent() {
        let mut view = selection_view();

        assert_eq!(nav_name(&view.on_action(Action::Activate)), "confirm run");
    }

    #[test]
    fn backing_out_of_the_selection_closes_only_that_sub_view() {
        let mut view = selection_view();

        assert_eq!(nav_name(&view.on_action(Action::Back)), "pop");
    }

    #[test]
    fn moving_inside_the_selection_asks_the_shell_for_nothing() {
        let mut view = selection_view();

        assert_eq!(nav_name(&view.on_action(Action::MoveDown)), "stay");
        assert_eq!(nav_name(&view.on_action(Action::Toggle)), "stay");
    }

    #[test]
    fn q_is_never_back_inside_a_sub_view() {
        for mut view in sub_views() {
            let title = view.title();
            assert_eq!(nav_name(&view.on_action(Action::Quit)), "stay", "{title}");
        }
    }

    #[test]
    fn esc_backs_out_of_a_sub_view_and_asks_first_while_work_is_running() {
        for mut view in sub_views() {
            let title = view.title();
            let expected = match view {
                // The running views ask before throwing work away.
                SubView::Scan(_) | SubView::Running(_) => "other effect",
                _ => "pop",
            };
            assert_eq!(nav_name(&view.on_action(Action::Back)), expected, "{title}");
        }
    }

    // -- the run confirmation ------------------------------------------------

    fn planned(email: &str, count: u32) -> PlannedSender {
        PlannedSender {
            sender: sender(email, count),
            step: NextStep::FirstAttempt,
        }
    }

    #[test]
    fn the_confirmation_names_each_destination_with_its_own_counts() {
        let plan = RunPlan {
            to_unsubscribe: vec![planned("one@acme.example.com", 3)],
            archive_only: vec![sender("stale@acme.example.com", 4)],
            exhausted: vec![sender("spent@acme.example.com", 5)],
        };

        let lines = plan_summary(&plan);

        assert!(lines.iter().any(|l| l.contains("Unsubscribe from 1 sender(s) (3 emails)")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Archive 1 stale sender(s)") && l.contains("(4 emails)")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("no method left") && l.contains("(5 emails)")), "{lines:?}");
        assert_eq!(lines.last().map(String::as_str), Some("12 emails in total."));
    }

    #[test]
    fn the_confirmation_leaves_out_the_destinations_a_plan_does_not_use() {
        let plan = RunPlan {
            to_unsubscribe: vec![planned("one@acme.example.com", 3)],
            ..RunPlan::default()
        };

        let lines = plan_summary(&plan);

        assert!(!lines.iter().any(|l| l.contains("stale")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.contains("no method left")), "{lines:?}");
        assert_eq!(lines.last().map(String::as_str), Some("3 emails in total."));
    }

    #[test]
    fn an_empty_plan_still_says_how_much_it_would_touch() {
        let lines = plan_summary(&RunPlan::default());

        assert_eq!(lines.last().map(String::as_str), Some("0 emails in total."));
    }


    // -----------------------------------------------------------------------
    // The narrow-terminal rule
    // -----------------------------------------------------------------------
    //
    // The decision itself lives inline in `Shell::render_columns`
    // (`if area.width < NARROW`), so it cannot be exercised without a frame.
    // What can be pinned is that the threshold is consistent with the split it
    // guards: above it, both columns must still be worth drawing.

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_narrow_threshold_leaves_room_for_both_columns_when_it_is_cleared() {
        const MIN_PANEL: u16 = 20; // the Min() the horizontal split uses

        assert!(
            NARROW >= NAV_WIDTH + MIN_PANEL,
            "at {NARROW} columns the panel would be squeezed below {MIN_PANEL}"
        );
    }

    // =======================================================================
    // The shell's navigation state machine
    // =======================================================================
    //
    // `Shell::on_key` cannot be driven from a test: it takes `&mut Tui`
    // (= `Terminal<CrosstermBackend<Stdout>>`) purely so it can forward two
    // settings effects, and `Terminal::new` asks the backend for a size, which
    // fails when the test harness's stdout is a pipe. Everything below the
    // preamble is reachable, so these tests drive `dispatch_action` (which
    // picks the focus and hands it the action) and `apply` (the pure half of
    // carrying the answer out) -- between them, every transition the user can
    // make with a key that is not `Ctrl-C` or `?`.

    mod state_machine {
        use super::*;
        use std::sync::OnceLock;
        use unsubscribe_core::{AuthType, ProviderType};

        /// One temporary home for every store the shell tests open, so no test
        /// ever reads the real config dir, data dir or databases.
        fn sandbox() -> &'static tempfile::TempDir {
            static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
            DIR.get_or_init(|| {
                let dir = tempfile::tempdir().expect("a temp dir");
                // `FileDataStore` resolves its directory from the environment
                // at construction, and offers no other way to point it
                // somewhere else.
                unsafe { std::env::set_var("XDG_DATA_HOME", dir.path()) };
                dir
            })
        }

        fn account() -> AccountConfig {
            AccountConfig {
                account_id: "user@example.com".to_string(),
                provider_type: ProviderType::Imap,
                host: Some("imap.example.com".to_string()),
                port: Some(993),
                username: "user@example.com".to_string(),
                auth_type: AuthType::Password,
                scan_folders: vec!["INBOX".to_string()],
                archive_folder: "Unsubscribed".to_string(),
                smtp_host: None,
                smtp_port: None,
            }
        }

        /// A shell over empty stores in a sandbox, with no panel built yet.
        pub(super) fn shell() -> Shell {
            let dir = sandbox().path();
            let stamp = format!("{:?}", std::thread::current().id());
            let ctx = Context {
                config_dir: dir.to_path_buf(),
                account: account(),
                credential: Credential::Password("secret".to_string()),
                preferences: Preferences::default(),
                data: FileDataStore::new(),
                cache: SqliteCacheStore::open(dir.join(format!("cache-{stamp}.db")))
                    .expect("a cache in the sandbox"),
                history: SqliteHistoryStore::open(dir.join(format!("history-{stamp}.db"))).ok(),
            };
            Shell::new(ctx)
        }

        /// Press one key's worth of action and carry out the pure half of the
        /// answer, the way the event loop does.
        pub(super) fn press(shell: &mut Shell, action: Action) -> Option<&'static str> {
            let nav = shell.dispatch_action(action);
            let name = nav_name(&nav);
            shell.apply(nav).map(|_| name)
        }

        pub(super) fn section(shell: &Shell) -> Section {
            shell.nav.section()
        }

        /// Walk the nav highlight onto `target` and move focus into it.
        pub(super) fn open(shell: &mut Shell, target: Section) {
            while section(shell) != target {
                press(shell, Action::MoveDown);
            }
            press(shell, Action::Activate);
            assert!(!shell.nav.nav_has_focus(), "{target:?} should take focus");
        }

        /// The sections with a working area to focus.
        pub(super) fn panels() -> impl Iterator<Item = Section> {
            Section::ALL.into_iter().filter(|s| s.has_panel())
        }

        // -- where focus starts ---------------------------------------------

        #[test]
        fn the_app_opens_on_run_with_the_nav_in_focus_and_nothing_stacked() {
            let shell = shell();

            assert_eq!(section(&shell), Section::Run);
            assert!(shell.nav.nav_has_focus());
            assert_eq!(shell.depth(), 0);
            assert!(!shell.quit);
        }

        #[test]
        fn walking_the_nav_previews_a_section_without_giving_it_focus() {
            let mut shell = shell();

            press(&mut shell, Action::MoveDown);

            assert_eq!(section(&shell), Section::List);
            assert!(shell.nav.nav_has_focus(), "the preview is read-only");
        }

        #[test]
        fn enter_and_right_both_move_focus_into_every_section_that_has_a_panel() {
            for target in panels() {
                for enter in [Action::Activate, Action::FocusIn] {
                    let mut shell = shell();
                    while section(&shell) != target {
                        press(&mut shell, Action::MoveDown);
                    }
                    press(&mut shell, enter);

                    assert!(!shell.nav.nav_has_focus(), "{target:?} via {enter:?}");
                    assert_eq!(section(&shell), target);
                }
            }
        }

        // -- Esc climbs exactly one level, and never past the nav ------------

        #[test]
        fn esc_at_a_panels_top_level_returns_focus_to_the_nav() {
            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);

                press(&mut shell, Action::Back);

                assert!(shell.nav.nav_has_focus(), "{target:?}");
                assert_eq!(section(&shell), target, "the highlight stays put");
                assert!(!shell.quit);
            }
        }

        #[test]
        fn left_at_a_panels_top_level_is_the_same_one_level_step_as_esc() {
            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);

                press(&mut shell, Action::FocusOut);

                assert!(shell.nav.nav_has_focus(), "{target:?}");
            }
        }

        #[test]
        fn esc_climbs_one_level_per_press_from_the_bottom_of_a_stack() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            shell.apply(Nav::Push(selection_view()));
            assert_eq!(shell.depth(), 2);

            press(&mut shell, Action::Back);
            assert_eq!(shell.depth(), 1, "one sub-view closed, not both");
            assert!(!shell.nav.nav_has_focus());

            press(&mut shell, Action::Back);
            assert_eq!(shell.depth(), 0);
            assert!(!shell.nav.nav_has_focus(), "the panel's top level");

            press(&mut shell, Action::Back);
            assert!(shell.nav.nav_has_focus());
        }

        #[test]
        fn esc_at_the_nav_does_nothing_at_all_however_often_it_is_pressed() {
            let mut shell = shell();

            for _ in 0..20 {
                press(&mut shell, Action::Back);
            }

            assert!(!shell.quit, "Esc is never a way out of the app");
            assert!(shell.nav.nav_has_focus());
            assert_eq!(section(&shell), Section::Run);
        }

        #[test]
        fn esc_at_the_nav_leaves_a_stack_that_is_still_running_alone() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Back); // back to the panel
            press(&mut shell, Action::Back); // back to the nav

            press(&mut shell, Action::Back);

            assert!(shell.nav.nav_has_focus());
            assert!(!shell.quit);
        }

        // -- q, and only at the nav -----------------------------------------

        #[test]
        fn q_quits_from_the_nav() {
            let mut shell = shell();

            press(&mut shell, Action::Quit);

            assert!(shell.quit);
        }

        #[test]
        fn q_does_nothing_at_all_inside_any_panel() {
            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);

                press(&mut shell, Action::Quit);

                assert!(!shell.quit, "q quit from {target:?}");
                assert!(!shell.nav.nav_has_focus(), "q acted as back in {target:?}");
                assert_eq!(shell.depth(), 0, "q opened or closed something");
            }
        }

        #[test]
        fn q_does_nothing_inside_a_sub_view_either() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            press(&mut shell, Action::Quit);

            assert!(!shell.quit);
            assert_eq!(shell.depth(), 1, "still in the selection");
        }

        #[test]
        fn the_quit_section_is_the_one_place_enter_leaves_the_app() {
            let mut shell = shell();
            while section(&shell) != Section::Quit {
                press(&mut shell, Action::MoveDown);
            }

            press(&mut shell, Action::Activate);

            assert!(shell.quit);
        }

        // -- the sub-view stack belongs to a section ------------------------

        #[test]
        fn a_pushed_sub_view_highlights_and_focuses_the_section_it_belongs_to() {
            let mut shell = shell();

            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert_eq!(section(&shell), Section::List, "a timeline is a List view");
            assert!(!shell.nav.nav_has_focus());
            assert_eq!(shell.depth(), 1);
        }

        #[test]
        #[ignore = "no key reaches the nav without unwinding the sub-view -- see the report"]
        fn runs_sub_view_stack_survives_walking_the_nav_away_and_back() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            // Esc is the only key that leaves the working area, and inside a
            // sub-view it closes that sub-view first -- so this sequence
            // throws the selection away instead of parking it.
            press(&mut shell, Action::Back); // meant: to the panel
            press(&mut shell, Action::Back); // meant: to the nav
            press(&mut shell, Action::MoveDown); // preview the list
            press(&mut shell, Action::Activate); // and look at it
            press(&mut shell, Action::Back);
            press(&mut shell, Action::MoveUp); // back to Run
            press(&mut shell, Action::Activate);

            assert_eq!(shell.depth(), 1, "the selection is still open");
            assert_eq!(
                shell.active_sub_view().map(SubView::title).as_deref(),
                Some("Select senders"),
                "and it is the same one"
            );
        }

        #[test]
        fn esc_inside_a_sub_view_closes_it_rather_than_parking_it_at_the_nav() {
            // What the key sequence above actually does today. Pinned so the
            // shape of the gap is recorded rather than only its absence.
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            press(&mut shell, Action::Back);

            assert_eq!(shell.depth(), 0, "the selection was thrown away");
            assert!(!shell.nav.nav_has_focus(), "and focus is still in Run");
        }

        #[test]
        #[ignore = "a running scan answers Esc with a cancel question, so the nav is unreachable -- see the report"]
        fn the_nav_is_reachable_while_a_scan_is_running() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (_tx, rx) = mpsc::channel();
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));

            // Esc asks whether to cancel; answering no leaves focus where it
            // was, and there is no other key that reaches the nav.
            press(&mut shell, Action::Back);

            assert!(shell.nav.nav_has_focus(), "the scan should keep running");
            assert_eq!(shell.depth(), 0, "and stay on Run's stack");
        }

        #[test]
        fn a_stack_belonging_to_another_section_is_out_of_reach_of_the_keys() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            // Parked without a key: Esc would close it (see the ignored test
            // above), and this is the state the shell's own transitions --
            // a worker finishing while the user is elsewhere -- produce.
            shell.nav.focus_nav();
            open(&mut shell, Section::Logs);

            assert_eq!(shell.depth(), 0, "the Logs panel has no sub-view");
            assert!(
                shell.active_sub_view().is_none(),
                "Run's selection must not answer keys while Logs has focus"
            );
            // And Esc here backs out of Logs, not out of Run's selection.
            press(&mut shell, Action::Back);
            assert!(shell.nav.nav_has_focus());
            assert_eq!(shell.stack.len(), 1, "Run's stack is untouched");
        }

        #[test]
        fn opening_a_view_under_another_section_replaces_the_stack_rather_than_interleaving_it() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            shell.apply(Nav::Push(selection_view()));

            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert_eq!(shell.stack_section, Section::List);
            assert_eq!(shell.depth(), 1, "only the timeline is left");
        }

        // -- text fields ----------------------------------------------------

        #[test]
        fn the_nav_never_reports_a_text_field_even_while_a_panel_is_searching() {
            let mut shell = shell();
            open(&mut shell, Section::Logs);
            press(&mut shell, Action::Search);
            assert!(shell.captures_text());

            press(&mut shell, Action::Back); // Esc leaves the field
            press(&mut shell, Action::Back); // and then the panel

            assert!(shell.nav.nav_has_focus());
            assert!(!shell.captures_text(), "the nav takes no free text");
        }

        #[test]
        fn a_sub_view_never_reports_a_text_field_even_over_a_searching_panel() {
            let mut shell = shell();
            open(&mut shell, Section::List);
            press(&mut shell, Action::Search);
            assert!(shell.captures_text());

            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert!(
                !shell.captures_text(),
                "the timeline on top has no field of its own"
            );
        }

        #[test]
        fn a_search_field_types_the_letters_that_would_otherwise_act() {
            for target in [Section::List, Section::Logs] {
                let mut shell = shell();
                open(&mut shell, target);
                press(&mut shell, Action::Search);

                for c in ['q', 'j', 'k', 'g', '?', '/', 's'] {
                    let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
                    let action = keys::action(key, shell.captures_text()).expect("a key");
                    assert_eq!(action, Action::Type(c), "{c} in {target:?}");
                    press(&mut shell, action);
                }

                assert!(!shell.quit, "a typed q quit the app in {target:?}");
                assert!(shell.captures_text(), "the field closed in {target:?}");
                assert_eq!(shell.depth(), 0);
            }
        }

        // -- what the footer and the overlay advertise ----------------------

        #[test]
        fn the_nav_is_the_only_focus_that_advertises_quit() {
            assert!(shell().focus_actions().contains(&Action::Quit));

            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);

                assert!(
                    !shell.focus_actions().contains(&Action::Quit),
                    "{target:?} advertises q"
                );
            }
        }

        #[test]
        fn every_focus_advertises_a_way_to_see_the_keys_and_a_way_back() {
            assert!(shell().focus_actions().contains(&Action::Help));

            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);
                let actions = shell.focus_actions();

                assert!(actions.contains(&Action::Help), "{target:?} hides ?");
                assert!(actions.contains(&Action::Back), "{target:?} hides Esc");
                assert!(!keys::hints(&actions).trim().is_empty(), "{target:?}");
            }
        }

        #[test]
        fn the_working_area_is_titled_by_the_sub_view_on_top_and_otherwise_by_the_section() {
            let mut shell = shell();
            open(&mut shell, Section::List);
            assert_eq!(shell.panel_title(), "Unsubscribe List");

            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert_eq!(shell.panel_title(), "Sender timeline");
        }

        // -- questions are about what is on screen --------------------------

        #[test]
        fn closing_a_sub_view_dismisses_the_question_that_was_about_it() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            shell.dialog = Some(Dialog::confirm("Confirm run", ["anything".to_string()]));
            shell.pending = Some(Pending::CancelRun);

            press(&mut shell, Action::Back);

            assert!(shell.dialog.is_none(), "the question outlived its subject");
            assert!(shell.pending.is_none());
        }

        #[test]
        fn leaving_a_panel_for_the_nav_dismisses_its_question_too() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.dialog = Some(Dialog::confirm("Use the cached scan?", ["x".to_string()]));

            press(&mut shell, Action::Back);

            assert!(shell.dialog.is_none());
            assert!(shell.pending.is_none());
        }
    }


    // =======================================================================
    // The key contract, run over every focus the app has
    // =======================================================================
    //
    // One table, every panel and every sub-view: the reserved keys must mean
    // the same thing wherever they are pressed. A per-panel test can only say
    // that one screen got it right; this says no screen got it wrong.

    mod key_contract {
        use super::state_machine::{open, shell};
        use super::*;

        /// Every place a key can land: each section's panel, and each
        /// sub-view, stacked on the section it belongs to.
        fn focuses() -> Vec<(&'static str, Box<dyn Fn() -> Shell>)> {
            let mut places: Vec<(&'static str, Box<dyn Fn() -> Shell>)> = Vec::new();
            for target in Section::ALL.into_iter().filter(|s| s.has_panel()) {
                places.push((
                    target.label(),
                    Box::new(move || {
                        let mut shell = shell();
                        open(&mut shell, target);
                        shell
                    }),
                ));
            }
            places.push((
                "Select senders",
                Box::new(|| {
                    let mut shell = shell();
                    open(&mut shell, Section::Run);
                    shell.apply(Nav::Push(selection_view()));
                    shell
                }),
            ));
            places.push((
                "Sender timeline",
                Box::new(|| {
                    let mut shell = shell();
                    open(&mut shell, Section::List);
                    shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                        DetailScreen::new(timeline_view()),
                    ))));
                    shell
                }),
            ));
            places.push((
                "Scan",
                Box::new(|| {
                    let mut shell = shell();
                    open(&mut shell, Section::Run);
                    let (tx, rx) = mpsc::channel();
                    // Held so the worker channel never reports "disconnected".
                    std::mem::forget(tx);
                    shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                        ScanShared::new(),
                        rx,
                    )))));
                    shell
                }),
            ));
            places.push((
                "Run",
                Box::new(|| {
                    let mut shell = shell();
                    open(&mut shell, Section::Run);
                    let (tx, rx) = mpsc::channel();
                    std::mem::forget(tx);
                    shell.apply(Nav::Push(SubView::Running(Box::new(RunScreen::new(
                        RunShared::new(),
                        rx,
                        PlanCounts::default(),
                        false,
                    )))));
                    shell
                }),
            ));
            places
        }

        /// The keys whose meaning is fixed for the whole app.
        const MOVEMENT: [Action; 8] = keys::LIST_MOVEMENT;

        #[test]
        fn q_never_quits_and_never_goes_back_outside_the_nav() {
            for (name, build) in focuses() {
                let mut shell = build();
                let depth = shell.depth();
                let section = shell.nav.section();

                let nav = shell.dispatch_action(Action::Quit);
                shell.apply(nav);

                assert!(!shell.quit, "q quit from {name}");
                assert!(!shell.nav.nav_has_focus(), "q acted as back in {name}");
                assert_eq!(shell.depth(), depth, "q changed the stack in {name}");
                assert_eq!(shell.nav.section(), section, "q moved the nav in {name}");
            }
        }

        #[test]
        fn esc_never_quits_wherever_it_is_pressed() {
            for (name, build) in focuses() {
                let mut shell = build();

                for _ in 0..5 {
                    let nav = shell.dispatch_action(Action::Back);
                    shell.apply(nav);
                    assert!(!shell.quit, "Esc quit from {name}");
                }
            }
        }

        #[test]
        fn movement_never_quits_never_opens_anything_and_never_changes_section() {
            for (name, build) in focuses() {
                for action in MOVEMENT {
                    let mut shell = build();
                    let depth = shell.depth();
                    let section = shell.nav.section();

                    let nav = shell.dispatch_action(action);
                    let effect = shell.apply(nav);

                    assert!(effect.is_none(), "{action:?} asked for an effect in {name}");
                    assert!(!shell.quit, "{action:?} quit from {name}");
                    assert!(!shell.nav.nav_has_focus(), "{action:?} left {name}");
                    assert_eq!(shell.depth(), depth, "{action:?} changed the stack in {name}");
                    assert_eq!(shell.nav.section(), section, "{action:?} in {name}");
                }
            }
        }

        #[test]
        fn space_and_search_never_quit_and_never_leave_the_working_area() {
            for (name, build) in focuses() {
                for action in [Action::Toggle, Action::Search] {
                    let mut shell = build();
                    let depth = shell.depth();

                    let nav = shell.dispatch_action(action);
                    shell.apply(nav);

                    assert!(!shell.quit, "{action:?} quit from {name}");
                    assert!(!shell.nav.nav_has_focus(), "{action:?} left {name}");
                    assert_eq!(shell.depth(), depth, "{action:?} in {name}");
                }
            }
        }

        #[test]
        fn the_help_key_is_the_shells_and_no_panel_acts_on_it() {
            // The shell answers `?` before the key map reaches a panel; this
            // is what keeps that safe if the interception ever moves.
            for (name, build) in focuses() {
                let mut shell = build();
                let depth = shell.depth();

                let nav = shell.dispatch_action(Action::Help);
                let effect = shell.apply(nav);

                assert!(effect.is_none(), "{name} acted on ?");
                assert!(!shell.quit, "{name}");
                assert_eq!(shell.depth(), depth, "{name}");
                assert!(!shell.nav.nav_has_focus(), "{name}");
            }
        }

        #[test]
        fn the_help_overlay_leaves_the_state_underneath_exactly_as_it_was() {
            for (name, build) in focuses() {
                let mut shell = build();
                let before = (shell.depth(), shell.nav.section(), shell.panel_title());
                let actions = shell.focus_actions();

                shell.nav.help = true;

                assert_eq!(
                    (shell.depth(), shell.nav.section(), shell.panel_title()),
                    before,
                    "{name}"
                );
                assert_eq!(shell.focus_actions(), actions, "{name}");
                assert!(!shell.nav.nav_has_focus(), "{name}");
            }
        }

        #[test]
        fn the_footer_and_the_overlay_say_the_same_thing_about_every_focus() {
            for (name, build) in focuses() {
                let shell = build();
                let actions = shell.focus_actions();
                let footer = keys::hints(&actions);
                let rows = keys::help_rows(&actions);

                assert!(!rows.is_empty(), "{name} lists no keys");
                for (key, what) in rows {
                    assert!(footer.contains(key), "{name}: {key} missing from {footer}");
                    assert!(footer.contains(what), "{name}: {what} missing from {footer}");
                }
            }
        }

        #[test]
        fn no_focus_advertises_a_key_that_has_no_wording() {
            for (name, build) in focuses() {
                let shell = build();

                for action in shell.focus_actions() {
                    let describable = matches!(
                        action,
                        Action::FocusIn | Action::FocusOut | Action::Type(_) | Action::Erase
                    ) || keys::describe(action).is_some();
                    assert!(describable, "{name} advertises {action:?} with no wording");
                }
            }
        }

        #[test]
        fn every_panel_letter_a_focus_advertises_is_one_of_the_apps_letters() {
            for (name, build) in focuses() {
                let shell = build();

                for action in shell.focus_actions() {
                    if let Action::Mnemonic(c) = action {
                        assert!(
                            keys::MNEMONICS
                                .iter()
                                .any(|(letter, _)| letter.chars().next() == Some(c)),
                            "{name} advertises an off-budget letter {c}"
                        );
                    }
                }
            }
        }

        #[test]
        fn a_letter_a_focus_does_not_offer_is_inert_rather_than_borrowed() {
            // Every letter in the budget, pressed in every focus: one that a
            // panel does not offer must do nothing at all, not something else.
            for (name, build) in focuses() {
                let offered: Vec<char> = build()
                    .focus_actions()
                    .into_iter()
                    .filter_map(|action| match action {
                        Action::Mnemonic(c) => Some(c),
                        _ => None,
                    })
                    .collect();

                for (letter, _) in keys::MNEMONICS {
                    let c = letter.chars().next().expect("a letter");
                    if offered.contains(&c) {
                        continue;
                    }
                    let mut shell = build();
                    let depth = shell.depth();

                    let nav = shell.dispatch_action(Action::Mnemonic(c));
                    let effect = shell.apply(nav);

                    assert!(effect.is_none(), "{name} acted on an unoffered {c}");
                    assert!(!shell.quit, "{name}: {c}");
                    assert_eq!(shell.depth(), depth, "{name}: {c}");
                    assert!(!shell.nav.nav_has_focus(), "{name}: {c}");
                }
            }
        }
    }

}
