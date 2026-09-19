//! The app shell: one event loop, one terminal, a stack of screens.
//!
//! Screens answer keys with a [`Nav`] and never perform I/O. Anything that
//! needs the network, a store, or the real stdin comes back as an [`Effect`]
//! for the shell to carry out, which is what keeps every screen drivable from
//! a test and keeps decisions out of the UI.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::*;
use unsubscribe_core::{
    annotate_senders, decide_scan_action, load_cached_senders, record_resumptions, AccountConfig,
    CachedScanSummary, ConfigStore, Credential, DataStore, ObtainedSenders, Preferences, RunPlan,
    RunPolicy, ScanAction, SenderInfo,
};
use unsubscribe_core::sender_histories;
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
use super::history::{DetailScreen, HistoryScreen};
use super::run::{PlanCounts, RunScreen};
use super::scan::{ScanEnded, ScanScreen};
use super::worker::{self, RunShared, ScanShared, SelectionContext};
use super::{
    config, history, home, run, scan, select, suspended, warnings, TerminalGuard, Tui,
};
use crate::commands::config::ConfigIo;
use crate::commands::load_history;
use crate::progress::CliWarningsOnly;
use crate::time::{
    age_secs_since, format_relative_age, now_unix_secs, scan_max_age_secs, utc_to_local_display,
};

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
    /// The scan worker reported; act on how it ended.
    ScanEnded,
    /// The run worker reported; refresh what the ending changed.
    RunEnded,
    /// Esc during a scan or a run: ask before stopping.
    ConfirmCancelScan,
    ConfirmCancelRun,
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
    /// A resumed sender's timeline asked for another go at it.
    RunFromHistory,
}

/// One screen in the stack.
pub enum Screen {
    Home(HomeScreen),
    Scan(Box<ScanScreen>),
    Run(Box<RunScreen>),
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
    History(Box<HistoryScreen>),
    SenderHistory(Box<DetailScreen>),
}

impl Screen {
    /// The name in the header, and in the help overlay's title.
    fn title(&self) -> &'static str {
        match self {
            Self::Home(_) => "Home",
            Self::Scan(_) => "Scan",
            Self::Run(_) => "Run",
            Self::Select { .. } => "Review senders",
            Self::Settings { .. } => "Settings",
            Self::Warnings(_) => "Scan warnings",
            Self::History(_) => "History",
            Self::SenderHistory(_) => "Sender history",
        }
    }

    fn hints(&self) -> &str {
        match self {
            Self::Home(screen) => screen.hints(),
            Self::Scan(screen) => screen.hints(),
            Self::Run(screen) => screen.hints(),
            Self::Select { app, .. } => app.hints(),
            Self::Settings { app, .. } => config::hints(app),
            Self::Warnings(screen) => screen.hints(),
            Self::History(screen) => screen.hints(),
            Self::SenderHistory(screen) => screen.hints(),
        }
    }

    /// The keys the help overlay lists for this screen.
    fn keys(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Home(screen) => screen.keys(),
            Self::Scan(screen) => screen.keys(),
            Self::Run(screen) => screen.keys(),
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
            Self::History(screen) => screen.keys(),
            Self::SenderHistory(screen) => screen.keys(),
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

    /// Poll a background worker, if the screen has one. Called once a frame.
    fn tick(&mut self) -> Nav {
        match self {
            Self::Scan(screen) => screen.tick(),
            Self::Run(screen) => screen.tick(),
            _ => Nav::Stay,
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Nav {
        match self {
            Self::Home(screen) => screen.on_key(key),
            Self::Scan(screen) => screen.on_key(key),
            Self::Run(screen) => screen.on_key(key),
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
            Self::History(screen) => screen.on_key(key),
            Self::SenderHistory(screen) => screen.on_key(key),
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect) {
        match self {
            Self::Home(screen) => home::render(f, area, screen),
            Self::Scan(screen) => scan::render(f, area, screen),
            Self::Run(screen) => run::render(f, area, screen),
            Self::Select { app, .. } => select::render(f, area, app),
            Self::Settings { app, .. } => config::render(f, area, app),
            Self::Warnings(screen) => warnings::render(f, area, screen),
            Self::History(screen) => history::render_list(f, area, screen),
            Self::SenderHistory(screen) => history::render_detail(f, area, screen),
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
            // Workers report between frames, so the screen is never more
            // than one tick behind what the pipeline has done.
            let nav = self.top().tick();
            self.apply(nav, terminal)?;

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

        let nav = self.top().on_key(key);
        self.apply(nav, terminal)
    }

    /// Carry out what a screen asked for.
    fn apply(&mut self, nav: Nav, terminal: &mut Tui) -> Result<()> {
        match nav {
            Nav::Stay => {}
            Nav::Push(screen) => self.stack.push(screen),
            Nav::Pop => {
                // Home is the floor: popping it would leave nothing to draw.
                if self.stack.len() > 1 {
                    self.stack.pop();
                    self.dismiss_dialog();
                    self.refresh_home();
                }
            }
            Nav::Quit => self.quit = true,
            Nav::Effect(effect) => self.perform(effect, terminal)?,
        }
        Ok(())
    }

    /// Close whatever was being asked, because the screen under it has gone.
    fn dismiss_dialog(&mut self) {
        self.dialog = None;
        self.pending = None;
    }

    // -- effects ----------------------------------------------------------

    fn perform(&mut self, effect: Effect, terminal: &mut Tui) -> Result<()> {
        match effect {
            // Until the in-app scan and run screens exist, both hand off to
            // the command that already does this, with the app suspended.
            Effect::Scan => self.start_scan(),
            Effect::Review => self.review(),
            Effect::ConfirmRun => self.confirm_run(),
            Effect::ScanEnded => self.scan_ended(),
            Effect::RunEnded => {
                self.refresh_home();
                // The screen keeps its summary; a failure also gets a modal,
                // because an archive that did not happen is not a detail.
                let failure = match self.stack.last() {
                    Some(Screen::Run(screen)) => screen.failure().map(str::to_string),
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
                        "Attempts already made stay recorded, and the senders                          already handled are still archived."
                            .to_string(),
                    ],
                ));
            }
            Effect::OpenHistory => self.open_history(),
            Effect::RunFromHistory => self.run_from_history(),
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
            Pending::Run { plan, counts } => self.start_run(*plan, *counts, toggled),
            Pending::UseCachedScan { cached } => self.open_selection(*cached),
            Pending::CancelScan => {
                if let Some(Screen::Scan(screen)) = self.stack.last_mut() {
                    screen.request_cancel();
                }
            }
            Pending::CancelRun => {
                if let Some(Screen::Run(screen)) = self.stack.last_mut() {
                    screen.request_cancel();
                }
            }
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

    /// Decide between the cached scan and a fresh one, then act on it.
    ///
    /// The decision is [`decide_scan_action`] in core -- the same function the
    /// `run` command asks -- so the app and a scripted run never disagree
    /// about when a cache is too old to trust.
    fn review(&mut self) {
        let usable = load_cached_senders(
            &self.ctx.cache,
            &self.ctx.account.account_id,
            self.ctx.preferences.min_emails,
            &CliWarningsOnly,
        );
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
        self.stack
            .push(Screen::Scan(Box::new(ScanScreen::new(shared, outcome))));
    }

    /// Act on how a scan ended.
    fn scan_ended(&mut self) {
        let Some(Screen::Scan(screen)) = self.stack.pop() else {
            return;
        };
        self.dismiss_dialog();
        match screen.into_ended() {
            ScanEnded::Done(obtained) => {
                if obtained.senders.is_empty() {
                    self.refresh_home();
                    self.set_status(StatusMessage::warning(
                        "No senders with unsubscribe links found.",
                    ));
                    return;
                }
                self.open_selection(*obtained);
            }
            ScanEnded::Cancelled => {
                self.refresh_home();
                self.set_status(StatusMessage::warning(
                    "Scan cancelled \u{2014} the previous scan is untouched.",
                ));
            }
            ScanEnded::Failed(message) => {
                self.refresh_home();
                self.dialog = Some(Dialog::error("Scan failed", message));
            }
        }
    }

    /// Annotate senders against the history and open the selection screen.
    ///
    /// Observe, then judge: what the annotation reveals is recorded before the
    /// screen opens, because seeing a sender ignore an unsubscribe is evidence
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

        // The shell's header already carries the scan age, so the screen's
        // own timestamp line stays off inside the app.
        let mut app = SelectScreen::new(annotated, self.ctx.preferences);
        app.scan_timestamp = None;

        self.stack.push(Screen::Select {
            app: Box::new(app),
            history: Box::new(history),
        });
    }

    /// Turn the selection into a plan and ask before anything is sent.
    ///
    /// The selection screen stays on the stack: the question is asked over
    /// it, so declining leaves every tick where the user put it.
    fn confirm_run(&mut self) {
        let Some(Screen::Select { app, history }) = self.stack.last() else {
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
    /// The selection screen goes now rather than at confirmation time: its
    /// senders are in the plan, and coming back to it would offer a second
    /// run over mail that has just been archived.
    fn start_run(&mut self, plan: RunPlan, counts: PlanCounts, dry_run: bool) {
        if matches!(self.stack.last(), Some(Screen::Select { .. })) {
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
        self.stack.push(Screen::Run(Box::new(RunScreen::new(
            shared, result, counts, dry_run,
        ))));
    }

    /// Open the History screen on everything the store holds.
    ///
    /// Loaded once, here, rather than queried as the user scrolls: the
    /// reduction is pure and a few thousand attempts collapse to one row per
    /// sender, so the screen never touches a store again.
    fn open_history(&mut self) {
        let stored = load_history(self.ctx.history_store(), &self.ctx.account.account_id);
        let scanned = load_cached_senders(
            &self.ctx.cache,
            &self.ctx.account.account_id,
            self.ctx.preferences.min_emails,
            &CliWarningsOnly,
        )
        .map(|cached| cached.senders)
        .unwrap_or_default();

        let views = sender_histories(
            &stored.attempts,
            &stored.resumptions,
            &scanned,
            now_unix_secs(),
            self.ctx.preferences.grace_period_days,
        );
        self.stack
            .push(Screen::History(Box::new(HistoryScreen::new(views))));
    }

    /// Send one sender from its timeline straight to the run confirmation.
    ///
    /// Only reachable for a resumed sender that is in the current scan, which
    /// is the only case where there is mail to act on and a rung to climb to.
    fn run_from_history(&mut self) {
        let Some(Screen::SenderHistory(detail)) = self.stack.last() else {
            return;
        };
        let (email, list_id) = detail.sender();
        let (email, list_id) = (email.to_string(), list_id.map(str::to_string));

        let cached = load_cached_senders(
            &self.ctx.cache,
            &self.ctx.account.account_id,
            self.ctx.preferences.min_emails,
            &CliWarningsOnly,
        );
        let sender = cached.and_then(|cached| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use std::sync::mpsc;
    use unsubscribe_core::{
        annotate_senders, FolderMessage, MessageId, NextStep, PlannedSender,
    };

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

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

    fn selection_screen() -> Screen {
        let annotated = annotate_senders(
            "user@example.com",
            vec![sender("one@acme.example.com", 3)],
            &[],
            &[],
            &policy(),
            0,
        );
        Screen::Select {
            app: Box::new(SelectScreen::new(annotated, Preferences::default())),
            history: Box::new(SelectionContext::default()),
        }
    }

    /// One screen of each kind the shell can push without a store.
    fn screens() -> Vec<Screen> {
        let (_, scan_rx) = mpsc::channel();
        let (_, run_rx) = mpsc::channel();
        vec![
            Screen::Home(HomeScreen::new(HomeStats::default())),
            Screen::Scan(Box::new(ScanScreen::new(ScanShared::new(), scan_rx))),
            Screen::Run(Box::new(RunScreen::new(
                RunShared::new(),
                run_rx,
                PlanCounts::default(),
                false,
            ))),
            selection_screen(),
            Screen::Warnings(WarningsScreen::new(Vec::new())),
            Screen::History(Box::new(HistoryScreen::new(Vec::new()))),
        ]
    }

    // -- the screen contract -------------------------------------------------

    #[test]
    fn every_screen_names_itself_for_the_header_and_the_breadcrumb() {
        for screen in screens() {
            assert!(!screen.title().is_empty());
        }
    }

    #[test]
    fn no_two_screens_share_a_name() {
        // The breadcrumb is a trail of these, so duplicates would read as
        // the same place twice.
        let titles: Vec<&str> = screens().iter().map(Screen::title).collect();
        let mut unique = titles.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(unique.len(), titles.len(), "duplicate titles in {titles:?}");
    }

    #[test]
    fn every_screen_offers_a_footer_hint_and_a_help_listing() {
        for screen in screens() {
            assert!(!screen.hints().is_empty(), "{}", screen.title());
            assert!(!screen.keys().is_empty(), "{}", screen.title());
        }
    }

    #[test]
    fn only_a_screen_taking_free_text_keeps_the_shell_from_answering_the_help_key() {
        for screen in screens() {
            assert!(
                !screen.captures_text(),
                "{} takes no free text",
                screen.title()
            );
        }
    }

    #[test]
    fn a_screen_with_no_worker_has_nothing_to_report_each_frame() {
        for mut screen in screens() {
            let title = screen.title();
            match screen {
                // These two do poll a worker; the rest must stay quiet.
                Screen::Scan(_) | Screen::Run(_) => {}
                _ => assert_eq!(nav_name(&screen.tick()), "stay", "{title}"),
            }
        }
    }

    // -- key dispatch --------------------------------------------------------

    #[test]
    fn confirming_the_selection_asks_the_shell_before_anything_is_sent() {
        let mut screen = selection_screen();

        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Enter))), "confirm run");
    }

    #[test]
    fn backing_out_of_the_selection_pops_it_off_the_stack() {
        let mut screen = selection_screen();

        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Esc))), "pop");
    }

    #[test]
    fn moving_inside_the_selection_asks_the_shell_for_nothing() {
        let mut screen = selection_screen();

        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Down))), "stay");
        assert_eq!(nav_name(&screen.on_key(key(KeyCode::Char(' ')))), "stay");
    }

    #[test]
    fn every_nested_screen_offers_a_way_back_and_home_offers_a_way_out() {
        for mut screen in screens() {
            let title = screen.title();
            let expected = match screen {
                Screen::Home(_) => "quit",
                // The running screens ask before throwing work away.
                Screen::Scan(_) | Screen::Run(_) => "other effect",
                _ => "pop",
            };
            assert_eq!(nav_name(&screen.on_key(key(KeyCode::Esc))), expected, "{title}");
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
}
