//! The terminal UI: the full-screen app and the screens it is made of.
//!
//! One binary, two front-ends. Everything interactive lives here; the
//! `commands` module is the scriptable half. No screen decides anything a
//! headless run would decide differently -- the counts, the verdicts and the
//! plan all come from `unsubscribe_core`.
//!
//! This file owns only what every screen shares: the terminal handle, the
//! guard that restores it, and suspending it for a flow that needs the real
//! stdin back.

use anyhow::Result;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use std::io;

pub mod app;
pub mod components;
pub mod config;
pub mod home;
pub mod run;
pub mod scan;
pub mod select;
pub mod warnings;
pub mod worker;

pub use select::select_senders;

/// Terminal handle shared by every screen in this module.
pub(crate) type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// Guard that restores the terminal on drop, even if we panic or return early
pub(crate) struct TerminalGuard;

impl TerminalGuard {
    /// Enter the alternate screen in raw mode.
    ///
    /// The guard is created before the alternate screen is entered so that a
    /// failure part-way through still leaves raw mode behind.
    pub(crate) fn enter() -> Result<(Self, Tui)> {
        enable_raw_mode()?;
        let guard = Self;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok((guard, terminal))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Leave the alternate screen for the duration of `f`, then take it back.
///
/// For the flows that prompt on the real stdin -- `init`, `reauth` -- which
/// cannot run inside the alternate screen. The outer `Result` covers restoring
/// the terminal; the inner one is `f`'s.
pub(crate) fn suspended<T>(terminal: &mut Tui, f: impl FnOnce() -> Result<T>) -> Result<Result<T>> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;

    let result = f();

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(result)
}
