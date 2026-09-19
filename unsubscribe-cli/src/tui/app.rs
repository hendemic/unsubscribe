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
    /// Leave the working area for the nav with the sub-view stack untouched.
    ///
    /// What `Esc` does inside the Run workflow: a scan or a run keeps going
    /// on its worker, and coming back finds the same screen with the same
    /// state. Only the Run workflow answers this; everywhere else `Esc` is
    /// still one level back.
    Park,
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
    /// `c` during a scan or a run: ask before stopping.
    ConfirmCancelScan,
    ConfirmCancelRun,
    /// `c` over a selection whose ticks have been changed: ask before it goes.
    ConfirmCancelSelection,
    /// `c` over a selection that is still at its defaults: just close it.
    CancelSelection,
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

/// What the Run section has going on, as the nav advertises it.
///
/// A pure reading of the sub-view stack, so the marker can be tested without
/// a frame: the nav has to say that something is waiting behind it, or
/// parking a scan would look exactly like having nothing to come back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunActivity {
    /// Nothing stacked under Run.
    Idle,
    Scanning,
    Unsubscribing,
    /// A sub-view is waiting, with no worker of its own.
    Parked,
}

impl RunActivity {
    /// What the nav appends to the Run row.
    #[must_use]
    pub fn badge(self) -> &'static str {
        match self {
            Self::Idle => "",
            Self::Scanning => " (scanning\u{2026})",
            Self::Unsubscribing => " (unsubscribing\u{2026})",
            Self::Parked => " \u{25cf}",
        }
    }

    /// Whether a worker is still out there for this activity.
    #[must_use]
    pub fn is_working(self) -> bool {
        matches!(self, Self::Scanning | Self::Unsubscribing)
    }
}

impl SubView {
    /// What this view counts as while it sits under Run.
    fn activity(&self) -> RunActivity {
        match self {
            Self::Scan(screen) if screen.is_working() => RunActivity::Scanning,
            Self::Running(screen) if screen.is_working() => RunActivity::Unsubscribing,
            Self::Scan(_) | Self::Running(_) | Self::Select { .. } => RunActivity::Parked,
            // A timeline belongs to the Unsubscribe List, not to Run.
            Self::SenderHistory(_) => RunActivity::Idle,
        }
    }

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
                SelectAction::Park => Nav::Park,
                SelectAction::Cancel => Nav::Effect(Effect::CancelSelection),
                SelectAction::ConfirmCancel => Nav::Effect(Effect::ConfirmCancelSelection),
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

/// One sub-view stack per section that can have them.
///
/// Not one shared stack: a parked Run workflow has to survive the user
/// opening a sender timeline over in the Unsubscribe List, and a worker that
/// is still going must still be polled while they are there.
#[derive(Default)]
struct Stacks {
    run: Vec<SubView>,
    list: Vec<SubView>,
}

impl Stacks {
    fn of(&self, section: Section) -> &[SubView] {
        match section {
            Section::Run => &self.run,
            Section::List => &self.list,
            _ => &[],
        }
    }

    /// `None` for a section that has no sub-views of its own, which is every
    /// section [`SubView::section`] never names.
    fn of_mut(&mut self, section: Section) -> Option<&mut Vec<SubView>> {
        match section {
            Section::Run => Some(&mut self.run),
            Section::List => Some(&mut self.list),
            _ => None,
        }
    }
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
    /// Discard a selection whose ticks have been changed.
    CancelSelection,
    /// Leave the app while a worker is still going.
    Quit,
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

pub struct Shell {
    ctx: Context,
    nav: Navigator,
    panels: Panels,
    /// Views stacked on each section's panel. A scan or a run keeps running
    /// while the user looks at another section, so a stack is parked rather
    /// than thrown away.
    stacks: Stacks,
    dialog: Option<Dialog>,
    pending: Option<Pending>,
    status: Option<StatusMessage>,
    quit: bool,
    /// Quit was confirmed while a worker was still going: the loop tears the
    /// terminal down only once that worker has actually stopped, so a run is
    /// never killed part-way through an attempt.
    quit_when_idle: bool,
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
            stacks: Stacks::default(),
            dialog: None,
            pending: None,
            status: None,
            quit: false,
            quit_when_idle: false,
        }
    }

    // -- where the keys go ------------------------------------------------

    /// The sub-view on top of the section the nav is highlighting, if any.
    fn active_sub_view(&self) -> Option<&SubView> {
        self.stacks.of(self.nav.section()).last()
    }

    fn active_sub_view_mut(&mut self) -> Option<&mut SubView> {
        let section = self.nav.section();
        self.stacks
            .of_mut(section)
            .and_then(|stack| stack.last_mut())
    }

    /// How many levels `Esc` has to climb before it reaches the nav.
    fn depth(&self) -> usize {
        self.stacks.of(self.nav.section()).len()
    }

    /// What Run has going on, whichever section the user is looking at.
    ///
    /// Pure, and read by the nav: the whole point of parking a scan is that
    /// the user can see from anywhere that there is something to come back to.
    #[must_use]
    fn run_activity(&self) -> RunActivity {
        self.stacks
            .run
            .last()
            .map(SubView::activity)
            .unwrap_or(RunActivity::Idle)
    }

    /// Whether a worker is still out there. Only the Run workflow has any.
    #[must_use]
    fn work_in_flight(&self) -> bool {
        self.stacks
            .run
            .iter()
            .any(|view| view.activity().is_working())
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
            // Only the Run workflow has workers, and only its top view owns
            // one -- polled whichever section the user happens to be in.
            let nav = self
                .stacks
                .run
                .last_mut()
                .map(SubView::tick)
                .unwrap_or(Nav::Stay);
            self.dispatch(nav, terminal)?;

            // A confirmed quit waits here rather than at the keypress: the
            // worker was asked to stop cooperatively and is allowed to finish
            // whatever attempt it was making before the terminal goes away.
            if self.quit_when_idle && !self.work_in_flight() {
                self.quit = true;
                continue;
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
        let nav = self.handle_key(key);
        self.dispatch(nav, terminal)
    }

    /// The whole key map, decided without a terminal: translating the raw
    /// key, answering the reserved ones inline, and handing everything else
    /// to whatever has focus.
    ///
    /// Split out of [`Self::on_key`] so this -- Ctrl-C, the help overlay, a
    /// dialog's own y/n, and [`keys::action`]'s text-field gating together --
    /// is exactly what a test drives, rather than only the already-translated
    /// [`Action`] `dispatch_action` takes. `on_key` cannot be driven from a
    /// test on its own (it takes `&mut Tui`), which is exactly the gap that
    /// let a routing bug in this chain go unnoticed before.
    fn handle_key(&mut self, key: KeyEvent) -> Nav {
        // Ctrl-C always leaves, whatever is on screen. Answered before the
        // key map so that no panel and no text field can swallow it. With a
        // worker running it asks first, exactly as `q` does; a second Ctrl-C
        // after that is taken as meaning it, and goes immediately.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.quit_when_idle || matches!(self.pending, Some(Pending::Quit)) {
                self.quit = true;
            } else {
                self.request_quit();
            }
            return Nav::Stay;
        }

        if self.nav.help {
            self.nav.help = false;
            return Nav::Stay;
        }

        if let Some(dialog) = self.dialog.as_mut() {
            match dialog.on_key(key) {
                DialogOutcome::Open => {}
                DialogOutcome::Confirmed => {
                    let toggled = dialog.toggled();
                    self.dialog = None;
                    if let Some(pending) = self.pending.take() {
                        self.resolve(pending, toggled);
                    }
                }
                DialogOutcome::Dismissed => {
                    self.dialog = None;
                    self.pending = None;
                }
            }
            return Nav::Stay;
        }

        let Some(action) = keys::action(key, self.captures_text()) else {
            return Nav::Stay;
        };
        if action == Action::Help {
            self.nav.help = true;
            return Nav::Stay;
        }

        self.dispatch_action(action)
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
            Nav::Park => {
                self.park();
                None
            }
            Nav::Quit => {
                self.request_quit();
                None
            }
            Nav::Effect(effect) => Some(effect),
        }
    }

    /// Open a sub-view inside its section's working area.
    fn push(&mut self, view: SubView) {
        let section = view.section();
        if let Some(stack) = self.stacks.of_mut(section) {
            stack.push(view);
        }
        // Focus is deliberately not moved: a worker that finishes while the
        // user is reading another section must advance the workflow without
        // yanking them out of what they are looking at. A view the user
        // opened themselves is already in the section they are focused on.
    }

    /// One level back, and never past the nav.
    fn back(&mut self) {
        match self.nav.back(self.depth()) {
            Back::PopSubView => {
                let section = self.nav.section();
                if let Some(stack) = self.stacks.of_mut(section) {
                    stack.pop();
                }
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

    /// Hand focus to the nav with the stack left exactly as it is.
    fn park(&mut self) {
        self.nav.focus_nav();
        // Nothing is being asked about the parked view any more; the question
        // would otherwise float over a section it has nothing to do with.
        self.dismiss_dialog();
    }

    /// Leave the app -- asking first if a worker would have to be abandoned.
    fn request_quit(&mut self) {
        if !self.work_in_flight() {
            self.quit = true;
            return;
        }
        self.pending = Some(Pending::Quit);
        self.dialog = Some(Dialog::confirm(
            "Quit",
            [
                "There is still work running. Stop it and leave?".to_string(),
                String::new(),
                "The app waits for the worker to stop cleanly \u{2014} an \
                 attempt in flight is always finished first."
                    .to_string(),
            ],
        ));
    }

    /// Ask every worker to stop, and leave once they have.
    fn quit_after_cancelling(&mut self) {
        for view in &mut self.stacks.run {
            match view {
                SubView::Scan(screen) => screen.request_cancel(),
                SubView::Running(screen) => screen.request_cancel(),
                _ => {}
            }
        }
        self.quit_when_idle = true;
    }

    /// Close whatever was being asked, because what it was about has gone.
    fn dismiss_dialog(&mut self) {
        self.dialog = None;
        self.pending = None;
    }

    // -- effects ----------------------------------------------------------

    fn perform(&mut self, effect: Effect, terminal: &mut Tui) -> Result<()> {
        // Only the two settings flows need the real terminal; everything else
        // just moves state, and lives in the pure half so it can be tested.
        match effect {
            Effect::SettingsFolders => self.settings_folders(terminal),
            Effect::SettingsReauth => self.settings_reauth(terminal),
            other => {
                self.perform_pure(other);
                Ok(())
            }
        }
    }

    /// Every effect that needs nothing but the shell's own state.
    fn perform_pure(&mut self, effect: Effect) {
        match effect {
            Effect::Scan => self.start_scan(),
            Effect::Review => self.review(),
            Effect::ConfirmRun => self.confirm_run(),
            Effect::ScanEnded => self.scan_ended(),
            Effect::RunEnded => {
                self.refresh();
                // The screen keeps its summary; a failure also gets a modal,
                // because an archive that did not happen is not a detail.
                let failure = match self.stacks.run.last() {
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
            Effect::CancelSelection => self.cancel_selection(),
            Effect::ConfirmCancelSelection => {
                self.pending = Some(Pending::CancelSelection);
                self.dialog = Some(Dialog::confirm(
                    "Discard the selection",
                    [
                        "Throw away the senders you have ticked?".to_string(),
                        String::new(),
                        "The scan itself stays in the cache, so the same \
                         senders can be selected again."
                            .to_string(),
                    ],
                ));
            }
            Effect::RunFromHistory => self.run_from_history(),
            Effect::SettingsSave => self.settings_save(),
            // Answered above, where the terminal is still in reach.
            Effect::SettingsFolders | Effect::SettingsReauth => {}
        }
    }

    /// Carry out what a confirmed question asked for.
    ///
    /// Pure, and terminal-free: every answer the shell asks for moves state
    /// and nothing else, which is what makes the confirmation rules testable.
    fn resolve(&mut self, pending: Pending, toggled: bool) {
        match pending {
            Pending::Run { plan, counts } => self.start_run(*plan, *counts, toggled),
            Pending::UseCachedScan { cached } => self.open_selection(*cached),
            Pending::CancelScan => {
                if let Some(SubView::Scan(screen)) = self.stacks.run.last_mut() {
                    screen.request_cancel();
                }
            }
            Pending::CancelRun => {
                if let Some(SubView::Running(screen)) = self.stacks.run.last_mut() {
                    screen.request_cancel();
                }
            }
            Pending::CancelSelection => self.cancel_selection(),
            Pending::Quit => self.quit_after_cancelling(),
        }
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
        let Some(SubView::Scan(screen)) = self.stacks.run.pop() else {
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
        let Some(SubView::Select { app, history }) = self.stacks.run.last() else {
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
        if matches!(self.stacks.run.last(), Some(SubView::Select { .. })) {
            self.stacks.run.pop();
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

    /// Throw the selection away and go back to the Run panel's top level.
    fn cancel_selection(&mut self) {
        if matches!(self.stacks.run.last(), Some(SubView::Select { .. })) {
            self.stacks.run.pop();
            self.refresh();
        }
    }

    /// Send one sender from its timeline straight to the run confirmation.
    ///
    /// Only reachable for a resumed sender that is in the current scan, which
    /// is the only case where there is mail to act on and a rung to climb to.
    fn run_from_history(&mut self) {
        let Some(SubView::SenderHistory(detail)) = self.stacks.list.last() else {
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
        let activity = self.run_activity();

        let rows: Vec<Line> = Section::ALL
            .iter()
            .enumerate()
            .flat_map(|(index, section)| {
                let badge = match (section, warnings) {
                    (Section::Warnings, 0) => String::new(),
                    (Section::Warnings, n) => format!(" ({n})"),
                    // Run says what it has waiting, so a parked scan is
                    // visible from wherever the user walked off to.
                    (Section::Run, _) => activity.badge().to_string(),
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
            Nav::Park => "park",
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
    fn backing_out_of_the_selection_parks_it_with_every_tick_kept() {
        let mut view = selection_view();

        assert_eq!(nav_name(&view.on_action(Action::Back)), "park");
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
    fn esc_parks_every_run_sub_view_and_still_pops_the_timeline() {
        for mut view in sub_views() {
            let title = view.title();
            let expected = match view {
                // Outside the Run workflow nothing changed: one level back.
                SubView::SenderHistory(_) => "pop",
                _ => "park",
            };
            assert_eq!(nav_name(&view.on_action(Action::Back)), expected, "{title}");
        }
    }

    #[test]
    fn c_is_answered_by_every_run_sub_view_and_by_nothing_else() {
        for mut view in sub_views() {
            let title = view.title();
            let answered = !matches!(nav_name(&view.on_action(Action::Mnemonic('c'))), "stay");
            let expected = !matches!(view, SubView::SenderHistory(_));

            assert_eq!(answered, expected, "{title}");
        }
    }

    #[test]
    fn c_is_advertised_by_exactly_the_sub_views_that_answer_it() {
        for view in sub_views() {
            let title = view.title();
            let offered = view.actions().contains(&Action::Mnemonic('c'));

            assert_eq!(
                offered,
                !matches!(view, SubView::SenderHistory(_)),
                "{title}"
            );
        }
    }

    // -- what the nav says Run has waiting -----------------------------------

    #[test]
    fn a_working_scan_or_run_names_itself_in_the_nav() {
        for view in sub_views() {
            let title = view.title();
            let expected = match view {
                SubView::Scan(_) => RunActivity::Scanning,
                SubView::Running(_) => RunActivity::Unsubscribing,
                SubView::Select { .. } => RunActivity::Parked,
                SubView::SenderHistory(_) => RunActivity::Idle,
            };
            assert_eq!(view.activity(), expected, "{title}");
        }
    }

    #[test]
    fn a_scan_that_has_ended_is_parked_rather_than_still_scanning() {
        let (tx, rx) = mpsc::channel();
        tx.send(worker::ScanOutcome::Cancelled).expect("listening");
        let mut view = SubView::Scan(Box::new(ScanScreen::new(ScanShared::new(), rx)));
        view.tick();

        assert_eq!(view.activity(), RunActivity::Parked);
        assert!(!view.activity().is_working());
    }

    #[test]
    fn every_activity_but_idle_leaves_a_mark_the_user_can_see() {
        assert_eq!(RunActivity::Idle.badge(), "");
        for activity in [
            RunActivity::Scanning,
            RunActivity::Unsubscribing,
            RunActivity::Parked,
        ] {
            assert!(!activity.badge().is_empty(), "{activity:?}");
        }
        assert!(RunActivity::Scanning.is_working());
        assert!(RunActivity::Unsubscribing.is_working());
        assert!(!RunActivity::Parked.is_working());
        assert!(!RunActivity::Idle.is_working());
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
    // `Shell::on_key` itself cannot be driven from a test: it takes `&mut Tui`
    // (= `Terminal<CrosstermBackend<Stdout>>`) purely so it can forward two
    // settings effects, and `Terminal::new` asks the backend for a size, which
    // fails when the test harness's stdout is a pipe. `Shell::handle_key`
    // holds everything on-key actually decides -- Ctrl-C, the help overlay, a
    // dialog's own y/n, and the raw-key-to-`Action` translation `keys::action`
    // does -- without touching the terminal, so the `real_keys` tests below
    // drive that directly. Everything else here drives `dispatch_action`
    // (which picks the focus and hands it the action, the way `handle_key`
    // does once a key is already translated) and `apply` (the pure half of
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
            // The loop rebuilds a panel it has invalidated before the next
            // key lands; without this a panel dropped by `refresh` would
            // silently swallow the press that follows it.
            shell.ensure_panel(shell.nav.section());
            let nav = shell.dispatch_action(action);
            let name = nav_name(&nav);
            shell.apply(nav).map(|_| name)
        }

        /// Press a key and carry out the effect it asks for, for the flows
        /// whose whole point is the question the shell then puts up.
        ///
        /// Separate from [`press`] because performing an effect can start a
        /// worker, and most tests want only the state transition.
        pub(super) fn act(shell: &mut Shell, action: Action) {
            shell.ensure_panel(shell.nav.section());
            let nav = shell.dispatch_action(action);
            if let Some(effect) = shell.apply(nav) {
                shell.perform_pure(effect);
            }
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

        /// The senders ticked in the selection waiting under Run.
        pub(super) fn selected_emails(shell: &Shell) -> Vec<String> {
            match shell.stacks.run.last() {
                Some(SubView::Select { app, .. }) => app
                    .selected_senders()
                    .into_iter()
                    .map(|sender| sender.email)
                    .collect(),
                _ => Vec::new(),
            }
        }

        /// What a finished scan hands back.
        pub(super) fn scanned(count: usize) -> Box<ObtainedSenders> {
            Box::new(ObtainedSenders {
                senders: (0..count)
                    .map(|i| sender(&format!("s{i}@acme.example.com"), 3))
                    .collect(),
                warnings: Vec::new(),
                scanned_at: "2026-06-01T09:00:00Z".to_string(),
                from_cache: false,
            })
        }

        /// A shell with a scan running under Run, focused on it.
        pub(super) fn scanning() -> Shell {
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
        }

        /// A shell with a run under way, focused on it.
        pub(super) fn unsubscribing() -> Shell {
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
        }

        /// Answer the open dialog the way the event loop does.
        pub(super) fn answer(shell: &mut Shell, yes: bool) {
            assert!(shell.dialog.is_some(), "nothing was being asked");
            shell.dialog = None;
            let pending = shell.pending.take().expect("a question was asked");
            if yes {
                shell.resolve(pending, false);
            }
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
            // Outside the Run workflow, where Esc still means one level back.
            let mut shell = shell();
            open(&mut shell, Section::List);
            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));
            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));
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
        fn esc_in_the_run_workflow_reaches_the_nav_in_one_press_however_deep_it_is() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            press(&mut shell, Action::Back);

            assert!(shell.nav.nav_has_focus(), "the nav answers keys again");
            assert_eq!(shell.depth(), 1, "and the selection is still standing");
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
            press(&mut shell, Action::Back); // parks it at the nav

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
        fn a_pushed_sub_view_waits_in_its_own_section_without_stealing_focus() {
            // The shell pushes on a worker's behalf too, and a scan that
            // finishes while the user is reading the Logs must not drag them
            // out of it. The view waits on its section's stack instead.
            let mut shell = shell();
            open(&mut shell, Section::Logs);

            shell.apply(Nav::Push(selection_view()));

            assert_eq!(section(&shell), Section::Logs, "the user was left alone");
            assert_eq!(shell.depth(), 0, "the Logs panel has no sub-view");
            assert_eq!(shell.stacks.run.len(), 1, "it is waiting under Run");
        }

        #[test]
        fn runs_sub_view_stack_survives_walking_the_nav_away_and_back() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            // Esc inside the Run workflow parks the selection at the nav.
            press(&mut shell, Action::Back);
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
        fn a_parked_selection_keeps_its_cursor_and_its_ticks() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::MoveDown);
            press(&mut shell, Action::Toggle);
            let chosen = selected_emails(&shell);
            assert!(!chosen.is_empty(), "something was ticked");

            press(&mut shell, Action::Back); // park it
            press(&mut shell, Action::MoveDown); // walk off to the List
            press(&mut shell, Action::Activate);
            press(&mut shell, Action::Back);
            press(&mut shell, Action::MoveUp);
            press(&mut shell, Action::Activate); // and come back

            assert_eq!(selected_emails(&shell), chosen, "the ticks survived");
        }

        #[test]
        fn a_parked_run_workflow_survives_a_timeline_being_opened_elsewhere() {
            // Each section owns its own stack, so looking a sender up in the
            // Unsubscribe List cannot throw a running scan away.
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Back);

            open(&mut shell, Section::List);
            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));
            assert_eq!(shell.depth(), 1, "the timeline is on the List's stack");

            press(&mut shell, Action::Back); // close the timeline
            press(&mut shell, Action::Back); // back to the nav
            press(&mut shell, Action::MoveUp);
            press(&mut shell, Action::Activate);

            assert_eq!(
                shell.active_sub_view().map(SubView::title).as_deref(),
                Some("Select senders")
            );
        }

        #[test]
        fn enter_on_run_returns_to_a_parked_workflow_rather_than_offering_to_start_another() {
            // With something parked there is no way to press Enter on "Scan
            // and unsubscribe": the sub-view is what answers keys.
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (tx, rx) = mpsc::channel();
            std::mem::forget(tx);
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));
            press(&mut shell, Action::Back);

            press(&mut shell, Action::Activate);
            assert!(shell.active_sub_view().is_some(), "back in the scan");

            // Enter now lands on the scan's own Cancel button, not on the Run
            // panel's two start actions -- there is no way to begin a second
            // scan while this one is still there.
            act(&mut shell, Action::Activate);

            assert!(shell.dialog.is_some(), "it offered to stop this scan");
            assert_eq!(shell.stacks.run.len(), 1, "and started nothing new");
        }

        #[test]
        fn the_nav_is_reachable_while_a_scan_is_running() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (_tx, rx) = mpsc::channel();
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));

            // Esc parks the scan: focus goes to the nav and nothing is asked.
            press(&mut shell, Action::Back);

            assert!(shell.nav.nav_has_focus(), "the scan should keep running");
            assert!(shell.dialog.is_none(), "and nothing should be asked");
            assert_eq!(shell.depth(), 1, "and stay on Run's stack");
            assert!(shell.work_in_flight());
        }

        #[test]
        fn a_stack_belonging_to_another_section_is_out_of_reach_of_the_keys() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Back); // park it
            open(&mut shell, Section::Logs);

            assert_eq!(shell.depth(), 0, "the Logs panel has no sub-view");
            assert!(
                shell.active_sub_view().is_none(),
                "Run's selection must not answer keys while Logs has focus"
            );
            // And Esc here backs out of Logs, not out of Run's selection.
            press(&mut shell, Action::Back);
            assert!(shell.nav.nav_has_focus());
            assert_eq!(shell.stacks.run.len(), 1, "Run's stack is untouched");
        }

        #[test]
        fn a_view_opened_under_another_section_joins_that_sections_own_stack() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            shell.apply(Nav::Push(selection_view()));

            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert_eq!(shell.stacks.list.len(), 1, "the timeline is the List's");
            assert_eq!(shell.stacks.run.len(), 2, "and Run keeps both of its own");
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

        // -- cancelling, which is now its own key ---------------------------

        #[test]
        fn c_over_a_running_scan_asks_and_only_then_stops_it() {
            let mut shell = scanning();

            act(&mut shell, Action::Mnemonic('c'));
            assert!(shell.dialog.is_some(), "it asked first");
            assert!(shell.work_in_flight(), "and nothing has stopped yet");

            answer(&mut shell, true);

            assert!(
                matches!(shell.stacks.run.last(), Some(SubView::Scan(_))),
                "the screen stays up until the worker reports"
            );
            assert!(!shell.nav.nav_has_focus(), "focus is still in Run");
        }

        #[test]
        fn declining_the_cancel_question_leaves_the_scan_exactly_as_it_was() {
            let mut shell = scanning();
            act(&mut shell, Action::Mnemonic('c'));

            answer(&mut shell, false);

            assert!(shell.work_in_flight());
            assert_eq!(shell.depth(), 1);
            assert!(shell.dialog.is_none());
        }

        #[test]
        fn c_over_a_running_run_asks_before_stopping_it_too() {
            let mut shell = unsubscribing();

            act(&mut shell, Action::Mnemonic('c'));

            assert!(shell.dialog.is_some());
            assert!(matches!(shell.pending, Some(Pending::CancelRun)));
        }

        #[test]
        fn c_over_an_untouched_selection_closes_it_without_asking() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));

            act(&mut shell, Action::Mnemonic('c'));

            assert!(shell.dialog.is_none(), "nothing was chosen to lose");
            assert_eq!(shell.depth(), 0, "back at the Run panel");
            assert!(!shell.nav.nav_has_focus());
        }

        #[test]
        fn c_over_a_selection_with_ticks_changed_asks_first() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Mnemonic('a')); // tick everything

            act(&mut shell, Action::Mnemonic('c'));
            assert!(shell.dialog.is_some());
            assert_eq!(shell.depth(), 1, "still there while it asks");

            answer(&mut shell, true);
            assert_eq!(shell.depth(), 0, "and gone once it is answered");
        }

        #[test]
        fn declining_that_question_keeps_every_tick() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Mnemonic('a'));
            let chosen = selected_emails(&shell);

            act(&mut shell, Action::Mnemonic('c'));
            answer(&mut shell, false);

            assert_eq!(shell.depth(), 1);
            assert_eq!(selected_emails(&shell), chosen);
        }

        // -- the same thing, through the visible button ---------------------

        #[test]
        fn enter_on_a_scans_button_asks_exactly_what_c_asks() {
            let mut by_key = scanning();
            act(&mut by_key, Action::Mnemonic('c'));
            let mut by_button = scanning();
            act(&mut by_button, Action::Activate);

            assert!(by_button.dialog.is_some());
            assert_eq!(
                by_button.dialog.as_ref().map(|d| d.title.clone()),
                by_key.dialog.as_ref().map(|d| d.title.clone())
            );
        }

        #[test]
        fn enter_on_a_runs_button_asks_exactly_what_c_asks() {
            let mut shell = unsubscribing();

            act(&mut shell, Action::Activate);

            assert!(matches!(shell.pending, Some(Pending::CancelRun)));
        }

        #[test]
        fn enter_on_the_selections_way_out_follows_the_same_confirmation_rule() {
            // Untouched: it just goes. Changed: it asks. Exactly as `c` does.
            let mut clean = shell();
            open(&mut clean, Section::Run);
            clean.apply(Nav::Push(selection_view()));
            press(&mut clean, Action::Last); // onto the way out
            act(&mut clean, Action::Activate);
            assert!(clean.dialog.is_none());
            assert_eq!(clean.depth(), 0);

            let mut dirty = shell();
            open(&mut dirty, Section::Run);
            dirty.apply(Nav::Push(selection_view()));
            press(&mut dirty, Action::Mnemonic('a'));
            press(&mut dirty, Action::Last);
            act(&mut dirty, Action::Activate);
            assert!(dirty.dialog.is_some());
            assert_eq!(dirty.depth(), 1, "still there while it asks");
        }

        #[test]
        fn every_run_sub_view_has_a_button_the_cursor_can_reach() {
            for build in [scanning as fn() -> Shell, unsubscribing] {
                let shell = build();
                let pressable = match shell.stacks.run.last() {
                    Some(SubView::Scan(screen)) => screen.button().enabled,
                    Some(SubView::Running(screen)) => screen.button().enabled,
                    _ => false,
                };
                assert!(pressable, "a Run sub-view with nothing to press");
                assert!(shell.focus_actions().contains(&Action::Activate));
            }
        }

        #[test]
        fn c_is_inert_in_every_panel_outside_the_run_workflow() {
            for target in panels() {
                let mut shell = shell();
                open(&mut shell, target);
                let depth = shell.depth();

                let nav = shell.dispatch_action(Action::Mnemonic('c'));
                let effect = shell.apply(nav);

                assert!(effect.is_none(), "{target:?} acted on c");
                assert!(!shell.quit, "{target:?}");
                assert_eq!(shell.depth(), depth, "{target:?}");
                assert!(!shell.nav.nav_has_focus(), "{target:?}");
                assert!(shell.dialog.is_none(), "{target:?} asked something");
            }
        }

        #[test]
        fn c_is_inert_on_a_sender_timeline_too() {
            let mut shell = shell();
            open(&mut shell, Section::List);
            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            press(&mut shell, Action::Mnemonic('c'));

            assert_eq!(shell.depth(), 1);
            assert!(shell.dialog.is_none());
        }

        // -- what the nav says Run has waiting ------------------------------

        #[test]
        fn the_nav_says_nothing_about_run_until_there_is_something_to_say() {
            assert_eq!(shell().run_activity(), RunActivity::Idle);
            assert_eq!(shell().run_activity().badge(), "");
        }

        #[test]
        fn the_nav_names_a_scan_a_run_and_a_parked_selection_from_any_section() {
            fn parked_selection() -> Shell {
                let mut shell = shell();
                open(&mut shell, Section::Run);
                shell.apply(Nav::Push(selection_view()));
                shell
            }

            let cases: [(RunActivity, fn() -> Shell); 3] = [
                (RunActivity::Scanning, scanning),
                (RunActivity::Unsubscribing, unsubscribing),
                (RunActivity::Parked, parked_selection),
            ];

            for (expected, build) in cases {
                let mut shell = build();
                assert_eq!(shell.run_activity(), expected);

                press(&mut shell, Action::Back); // park it
                open(&mut shell, Section::Logs); // and walk away

                assert_eq!(
                    shell.run_activity(),
                    expected,
                    "the marker must still be there from {:?}",
                    Section::Logs
                );
                assert!(!shell.run_activity().badge().is_empty());
            }
        }

        #[test]
        fn a_timeline_waiting_under_the_list_is_not_something_run_advertises() {
            let mut shell = shell();
            open(&mut shell, Section::List);
            shell.apply(Nav::Push(SubView::SenderHistory(Box::new(
                DetailScreen::new(timeline_view()),
            ))));

            assert_eq!(shell.run_activity(), RunActivity::Idle);
        }

        // -- work that finishes while the user is somewhere else ------------

        #[test]
        fn a_scan_that_ends_while_the_user_is_elsewhere_still_advances_the_workflow() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (tx, rx) = mpsc::channel();
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));
            press(&mut shell, Action::Back); // park the scan
            open(&mut shell, Section::Logs); // and go and read the Logs

            tx.send(worker::ScanOutcome::Done(scanned(2)))
                .expect("the screen is listening");
            let nav = shell.stacks.run.last_mut().map(SubView::tick).expect("a scan");
            let effect = shell.apply(nav).expect("the scan reports its ending");
            shell.perform_pure(effect);

            assert_eq!(section(&shell), Section::Logs, "the user was left alone");
            assert!(
                matches!(shell.stacks.run.last(), Some(SubView::Select { .. })),
                "and the selection is waiting under Run"
            );
            assert_eq!(shell.run_activity(), RunActivity::Parked);
        }

        #[test]
        fn a_scan_that_fails_while_the_user_is_elsewhere_still_says_so() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (tx, rx) = mpsc::channel();
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));
            press(&mut shell, Action::Back);
            open(&mut shell, Section::Settings);

            tx.send(worker::ScanOutcome::Failed("connection refused".to_string()))
                .expect("listening");
            let nav = shell.stacks.run.last_mut().map(SubView::tick).expect("a scan");
            let effect = shell.apply(nav).expect("an ending");
            shell.perform_pure(effect);

            assert!(
                shell.dialog.is_some(),
                "an error must not be lost because the user walked away"
            );
            assert_eq!(shell.stacks.run.len(), 0, "and the scan is gone");
        }

        #[test]
        fn a_worker_that_dies_while_the_user_is_elsewhere_surfaces_rather_than_hanging() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            let (tx, rx) = mpsc::channel::<worker::ScanOutcome>();
            shell.apply(Nav::Push(SubView::Scan(Box::new(ScanScreen::new(
                ScanShared::new(),
                rx,
            )))));
            press(&mut shell, Action::Back);
            drop(tx);

            let nav = shell.stacks.run.last_mut().map(SubView::tick).expect("a scan");
            let effect = shell.apply(nav).expect("an ending");
            shell.perform_pure(effect);

            assert!(shell.dialog.is_some());
        }

        // -- quitting with work in flight -----------------------------------

        #[test]
        fn q_at_the_nav_quits_at_once_when_there_is_nothing_running() {
            let mut shell = shell();

            press(&mut shell, Action::Quit);

            assert!(shell.quit);
            assert!(shell.dialog.is_none());
        }

        #[test]
        fn q_asks_first_while_a_scan_is_running_and_waits_for_it_to_stop() {
            let mut shell = scanning();
            press(&mut shell, Action::Back); // park it at the nav

            press(&mut shell, Action::Quit);
            assert!(shell.dialog.is_some(), "it asked");
            assert!(!shell.quit);

            answer(&mut shell, true);

            assert!(!shell.quit, "the worker has not stopped yet");
            assert!(shell.quit_when_idle, "but the app is on its way out");
            assert!(
                matches!(shell.stacks.run.last(), Some(SubView::Scan(_))),
                "the scan was asked to stop, not abandoned"
            );
        }

        #[test]
        fn declining_the_quit_question_leaves_the_app_and_the_worker_alone() {
            let mut shell = scanning();
            press(&mut shell, Action::Back);

            press(&mut shell, Action::Quit);
            answer(&mut shell, false);

            assert!(!shell.quit);
            assert!(!shell.quit_when_idle);
            assert!(shell.work_in_flight());
        }

        #[test]
        fn q_asks_the_same_question_while_a_run_is_under_way() {
            let mut shell = unsubscribing();
            press(&mut shell, Action::Back);

            press(&mut shell, Action::Quit);

            assert!(matches!(shell.pending, Some(Pending::Quit)));
        }

        #[test]
        fn a_parked_selection_is_not_work_in_flight_so_quitting_is_immediate() {
            let mut shell = shell();
            open(&mut shell, Section::Run);
            shell.apply(Nav::Push(selection_view()));
            press(&mut shell, Action::Back);

            press(&mut shell, Action::Quit);

            assert!(shell.quit, "there is no worker to wait for");
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
        fn esc_reaches_the_nav_from_every_run_focus_without_unwinding_anything() {
            // The Run workflow's whole contract in one table: one press, the
            // nav answers keys, and everything that was open is still open.
            for (name, build) in focuses() {
                let mut shell = build();
                if shell.nav.section() != Section::Run {
                    continue;
                }
                let depth = shell.depth();

                let nav = shell.dispatch_action(Action::Back);
                shell.apply(nav);

                assert!(shell.nav.nav_has_focus(), "{name} did not reach the nav");
                assert_eq!(shell.depth(), depth, "{name} unwound its stack");
                assert!(shell.dialog.is_none(), "{name} asked a question");
                assert_eq!(shell.nav.section(), Section::Run, "{name}");
            }
        }

        #[test]
        fn left_does_the_same_thing_as_esc_in_every_run_focus() {
            for (name, build) in focuses() {
                let mut shell = build();
                if shell.nav.section() != Section::Run {
                    continue;
                }
                let depth = shell.depth();

                let nav = shell.dispatch_action(Action::FocusOut);
                shell.apply(nav);

                assert!(shell.nav.nav_has_focus(), "{name}");
                assert_eq!(shell.depth(), depth, "{name}");
            }
        }

        #[test]
        fn esc_outside_the_run_workflow_still_climbs_exactly_one_level() {
            for (name, build) in focuses() {
                let mut shell = build();
                if shell.nav.section() == Section::Run {
                    continue;
                }
                let depth = shell.depth();

                let nav = shell.dispatch_action(Action::Back);
                shell.apply(nav);

                if depth > 0 {
                    assert_eq!(shell.depth(), depth - 1, "{name}");
                    assert!(!shell.nav.nav_has_focus(), "{name} left the panel too");
                } else {
                    assert!(shell.nav.nav_has_focus(), "{name}");
                }
            }
        }

        #[test]
        fn every_run_focus_advertises_the_cancel_key() {
            for (name, build) in focuses() {
                let shell = build();
                // The Run panel's own top level has nothing to cancel; every
                // sub-view of the workflow above it does.
                if shell.nav.section() != Section::Run || shell.depth() == 0 {
                    continue;
                }

                assert!(
                    shell.focus_actions().contains(&Action::Mnemonic('c')),
                    "{name} hides c"
                );
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

    // =======================================================================
    // Real keys, end to end
    // =======================================================================
    //
    // The tests above drive `dispatch_action` with an already-translated
    // `Action`, which skips `keys::action`'s text-field gating and the
    // Ctrl-C/help/dialog handling `handle_key` does first. These drive raw
    // `KeyEvent`s through `handle_key` itself -- the actual path a keypress
    // takes -- to pin the two bugs seen in Settings: `s` was advertised as
    // save but never wired to it, and `y`/`n` at the "unsaved changes" prompt
    // must actually resolve it rather than only working when the test hands
    // `dispatch_action` the `Action` directly.

    mod real_keys {
        use super::state_machine::{open, shell};
        use super::*;
        use crossterm::event::{KeyCode, KeyModifiers};

        fn key(code: KeyCode) -> KeyEvent {
            KeyEvent::new(code, KeyModifiers::NONE)
        }

        /// Dirty the settings screen the same way a user does: open the
        /// first field's editor and change it.
        fn dirty_settings(shell: &mut Shell) {
            open(shell, Section::Settings);
            for step in [
                KeyCode::Enter,
                KeyCode::Char('-'),
                KeyCode::Char('x'),
                KeyCode::Enter,
            ] {
                let nav = shell.handle_key(key(step));
                shell.apply(nav);
            }
            assert!(
                shell.panels.settings.as_ref().unwrap().0.is_dirty(),
                "the fixture did not dirty the screen"
            );
        }

        #[test]
        fn w_saves_settings_through_the_real_key_path() {
            let mut shell = shell();
            dirty_settings(&mut shell);

            let nav = shell.handle_key(key(KeyCode::Char('w')));

            assert!(
                matches!(nav, Nav::Effect(Effect::SettingsSave)),
                "w should ask the shell to save, got {}",
                nav_name(&nav)
            );
        }

        #[test]
        fn s_does_nothing_to_settings_through_the_real_key_path() {
            // `s` is the sort-order letter elsewhere in the app; Settings
            // never answers it, so it must be inert rather than half-saving.
            let mut shell = shell();
            dirty_settings(&mut shell);

            let nav = shell.handle_key(key(KeyCode::Char('s')));

            assert_eq!(nav_name(&nav), "stay");
            assert!(shell.panels.settings.as_ref().unwrap().0.is_dirty());
        }

        #[test]
        fn y_discards_and_leaves_the_unsaved_changes_prompt_through_the_real_key_path() {
            let mut shell = shell();
            dirty_settings(&mut shell);

            let nav = shell.handle_key(key(KeyCode::Esc));
            shell.apply(nav);
            assert!(
                !shell.nav.nav_has_focus(),
                "Esc should raise the prompt, not leave yet"
            );

            let nav = shell.handle_key(key(KeyCode::Char('y')));
            shell.apply(nav);

            assert!(shell.nav.nav_has_focus(), "y should have left settings");
        }

        #[test]
        fn n_keeps_the_unsaved_changes_and_stays_through_the_real_key_path() {
            let mut shell = shell();
            dirty_settings(&mut shell);

            let nav = shell.handle_key(key(KeyCode::Esc));
            shell.apply(nav);

            let nav = shell.handle_key(key(KeyCode::Char('n')));
            shell.apply(nav);

            assert!(!shell.nav.nav_has_focus(), "n should not have left settings");
            assert!(
                shell.panels.settings.as_ref().unwrap().0.is_dirty(),
                "n must not discard the edit"
            );
        }
    }
}
