use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use unsubscribe_core::{
    Folder, PlannedSender, RunObserver, RunWarning, ScanProgress, UnsubscribeResult,
};

use crate::action_log::append_log_entry;
use crate::note;
use crate::terminal::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

/// CLI scan progress using indicatif multi-progress bars.
///
/// Displays one progress bar per folder, matching the legacy UX:
/// folder name as prefix, position/length display, cyan bar styling.
///
/// A bar redrawn in place is noise in a log file, so with no terminal on
/// stderr the same events are reported as one line each instead.
pub struct CliScanProgress {
    mp: MultiProgress,
    style: ProgressStyle,
    bars: Mutex<HashMap<String, ProgressBar>>,
    /// Whether to draw bars at all.
    bars_enabled: bool,
}

impl CliScanProgress {
    pub fn new(bars_enabled: bool) -> Self {
        let style = ProgressStyle::default_bar()
            .template(" \x1b[1m{prefix:<12}\x1b[0m [{bar:30.cyan/dim}] \x1b[36m{pos}\x1b[0m/{len}")
            .expect("valid progress bar template")
            .progress_chars("=> ");

        Self {
            mp: MultiProgress::new(),
            style,
            bars: Mutex::new(HashMap::new()),
            bars_enabled,
        }
    }
}

impl ScanProgress for CliScanProgress {
    fn on_folder_start(&self, folder: &Folder, total_messages: u32) {
        if !self.bars_enabled {
            note!("Scanning {} ({total_messages} messages)", folder.as_str());
            return;
        }
        let pb = self.mp.add(ProgressBar::new(total_messages as u64));
        pb.set_style(self.style.clone());
        pb.set_prefix(folder.as_str().to_string());

        let mut bars = self.bars.lock().expect("progress bar lock poisoned");
        bars.insert(folder.as_str().to_string(), pb);
    }

    fn on_messages_scanned(&self, folder: &Folder, count: u32) {
        let bars = self.bars.lock().expect("progress bar lock poisoned");
        if let Some(pb) = bars.get(folder.as_str()) {
            pb.inc(count as u64);
        }
    }

    fn on_folder_done(&self, folder: &Folder) {
        if !self.bars_enabled {
            note!("Finished {}", folder.as_str());
            return;
        }
        let bars = self.bars.lock().expect("progress bar lock poisoned");
        if let Some(pb) = bars.get(folder.as_str()) {
            pb.finish();
        }
    }
}

// ---------------------------------------------------------------------------
// Run reporting
// ---------------------------------------------------------------------------

/// Terminal rendering for a run: the phase headers, the unsubscribe progress
/// bar, the results table, and the disposable CSV action log.
///
/// Everything the pipeline reports arrives here as data; the wording and the
/// colours are this adapter's business, not core's.
pub struct CliRunObserver {
    /// Nothing is actually done, so the log is not written and the archive is
    /// announced as hypothetical.
    dry_run: bool,
    /// Archive folder name, for the messages that name it.
    archive_folder: String,
    /// Where the action log goes. Written one row at a time so a later archive
    /// failure still leaves a record of what was unsubscribed.
    log_path: PathBuf,
    bar: Mutex<Option<ProgressBar>>,
    /// Whether to draw a bar; a log gets a line per sender instead.
    bars_enabled: bool,
}

impl CliRunObserver {
    pub fn new(
        dry_run: bool,
        archive_folder: &str,
        log_path: PathBuf,
        bars_enabled: bool,
    ) -> Self {
        Self {
            dry_run,
            archive_folder: archive_folder.to_string(),
            log_path,
            bar: Mutex::new(None),
            bars_enabled,
        }
    }

    /// The action log path, for telling the user where results were preserved.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

impl RunObserver for CliRunObserver {
    fn on_unsubscribe_start(&self, sender_count: u32) {
        if sender_count == 0 {
            return;
        }
        note!("{BOLD}Unsubscribing...{RESET}\n");
        if self.dry_run || !self.bars_enabled {
            return;
        }
        let pb = ProgressBar::new(u64::from(sender_count));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(" [{bar:40.cyan/dim}] \x1b[36m{pos}\x1b[0m/{len} unsubscribing")
                .expect("valid template")
                .progress_chars("=> "),
        );
        *self.bar.lock().expect("progress bar lock poisoned") = Some(pb);
    }

    fn on_sender_result(&self, _planned: &PlannedSender, result: &UnsubscribeResult) {
        match self.bar.lock().expect("progress bar lock poisoned").as_ref() {
            Some(pb) => pb.inc(1),
            // No bar to advance, so say what happened as it happens: an
            // unattended run's log is the only place this is visible.
            None if !self.dry_run => {
                let tag = if result.success { "ok" } else { "FAILED" };
                note!("  [{tag}] {} \u{2014} {}", result.email, result.detail);
            }
            None => {}
        }
        // A dry run did nothing worth logging.
        if self.dry_run {
            return;
        }
        // Best-effort incremental write -- a write failure is warned about but
        // does not abort the run.
        if let Err(e) = append_log_entry(result, &self.log_path) {
            note!("{YELLOW}Warning: could not write to action log: {e}{RESET}");
        }
    }

    fn on_unsubscribe_done(&self, planned: &[PlannedSender], results: &[UnsubscribeResult]) {
        if let Some(pb) = self.bar.lock().expect("progress bar lock poisoned").take() {
            pb.finish();
        }
        if results.is_empty() {
            return;
        }

        note!(
            "\n{BOLD}Results:{RESET} {GREEN}{} succeeded{RESET}, {RED}{} failed{RESET}\n",
            results.iter().filter(|r| r.success).count(),
            results.iter().filter(|r| !r.success).count(),
        );
        for (planned, r) in planned.iter().zip(results) {
            let tag = if r.success {
                format!("{GREEN}[OK]{RESET}  ")
            } else {
                format!("{RED}[FAIL]{RESET}")
            };
            note!(
                "  {tag} {:<40} {DIM}{}{}{RESET}",
                r.email,
                r.detail,
                escalation_note(planned)
            );
        }
        if !self.dry_run {
            note!("{DIM}Action log written to {}{RESET}", self.log_path.display());
        }
    }

    fn on_archive_start(&self, _message_count: u32, email_count: u32) {
        note!("\n{BOLD}Archiving emails...{RESET}\n");
        if self.dry_run {
            note!(
                "Dry run: would archive {email_count} emails to '{}'",
                self.archive_folder
            );
        }
    }

    fn on_archive_done(&self, archived: u32) {
        note!(
            "{GREEN}Archived {archived} emails{RESET} to '{}'.",
            self.archive_folder
        );
    }

    fn on_warning(&self, warning: &RunWarning) {
        print_run_warning(warning);
    }
}

/// Observer for the commands that only obtain senders (`scan`, `export`) and
/// so can report a warning but never a phase.
pub struct CliWarningsOnly;

impl RunObserver for CliWarningsOnly {
    fn on_unsubscribe_start(&self, _sender_count: u32) {}
    fn on_sender_result(&self, _planned: &PlannedSender, _result: &UnsubscribeResult) {}
    fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}
    fn on_archive_start(&self, _message_count: u32, _email_count: u32) {}
    fn on_archive_done(&self, _archived: u32) {}
    fn on_warning(&self, warning: &RunWarning) {
        print_run_warning(warning);
    }
}

/// What a row says about climbing the ladder, when it climbed one.
///
/// A plain retry says nothing; an escalation names what was ignored and what
/// was tried instead, which is the whole point of the ladder.
fn escalation_note(planned: &PlannedSender) -> String {
    let Some(escalation) = planned.escalation() else {
        return String::new();
    };
    match escalation.from {
        Some(from) => format!(
            "  (escalated: {} \u{2192} {})",
            from.label(),
            escalation.rung.label()
        ),
        None => format!("  (escalated to {})", escalation.rung.label()),
    }
}

/// The user-facing wording for each warning the pipeline can report.
fn print_run_warning(warning: &RunWarning) {
    match warning {
        RunWarning::CacheUnreadable(e) => {
            note!("{YELLOW}Warning: could not read the scan cache: {e}{RESET}");
        }
        RunWarning::CacheNotWritten(e) => {
            note!("{YELLOW}Warning: could not write scan cache: {e}{RESET}");
        }
        RunWarning::CacheNotPruned(e) => {
            note!("{YELLOW}Warning: could not prune the scan cache: {e}{RESET}");
            note!("{DIM}Run `unsubscribe scan` to rebuild it.{RESET}");
        }
        RunWarning::AttemptNotRecorded(e) => {
            note!("{YELLOW}Warning: could not record unsubscribe history: {e}{RESET}");
        }
        RunWarning::ResumptionNotRecorded(e) => {
            note!("{YELLOW}Warning: could not record a resumed sender: {e}{RESET}");
        }
    }
}
