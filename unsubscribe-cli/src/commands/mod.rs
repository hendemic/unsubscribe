//! CLI subcommand implementations, grouped by coherent area.

pub mod config;
pub mod history;
pub mod misc;
pub mod run;
pub mod scan;
pub mod setup;
pub mod update;

use unsubscribe_core::{HistoryStore, Resumption, UnsubscribeAttempt};

use crate::note;
use crate::terminal::{RESET, YELLOW};

/// Everything an account's history says, as the annotation stage wants it.
#[derive(Debug, Default)]
pub struct HistoryView {
    pub attempts: Vec<UnsubscribeAttempt>,
    pub resumptions: Vec<Resumption>,
}

/// Read an account's unsubscribe history, or nothing if it is unavailable.
///
/// The history enriches what we show; it never gates a run. An unreadable or
/// unopenable history warns and leaves the caller with the pre-history view.
pub fn load_history(history: Option<&dyn HistoryStore>, account: &str) -> HistoryView {
    let Some(history) = history else {
        return HistoryView::default();
    };
    HistoryView {
        attempts: read_or_warn(history.attempts_for_account(account), "unsubscribe history"),
        resumptions: read_or_warn(history.resumptions_for_account(account), "resumed senders"),
    }
}

/// Half a history is better than none: a failed read warns and yields nothing.
fn read_or_warn<T>(read: anyhow::Result<Vec<T>>, what: &str) -> Vec<T> {
    read.unwrap_or_else(|e| {
        note!("{YELLOW}Warning: could not read {what}: {e}{RESET}");
        Vec::new()
    })
}
