//! CLI subcommand implementations, grouped by coherent area.

pub mod config;
pub mod misc;
pub mod run;
pub mod scan;
pub mod setup;
pub mod update;

use unsubscribe_core::{HistoryStore, UnsubscribeAttempt};

use crate::terminal::{RESET, YELLOW};

/// Read an account's unsubscribe history, or nothing if it is unavailable.
///
/// The history enriches what we show; it never gates a run. An unreadable or
/// unopenable history warns and leaves the caller with the pre-history view.
pub fn load_history(history: Option<&dyn HistoryStore>, account: &str) -> Vec<UnsubscribeAttempt> {
    let Some(history) = history else {
        return Vec::new();
    };
    match history.attempts_for_account(account) {
        Ok(attempts) => attempts,
        Err(e) => {
            eprintln!("{YELLOW}Warning: could not read unsubscribe history: {e}{RESET}");
            Vec::new()
        }
    }
}
