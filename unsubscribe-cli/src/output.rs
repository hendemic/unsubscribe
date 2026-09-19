//! Output policy: which stream carries what, and what `--quiet` silences.
//!
//! The split is the contract a script depends on. **stdout** carries the
//! command's result and nothing else -- a single JSON document under `--json`,
//! the plain listing otherwise. **stderr** carries everything a person reads:
//! phase headers, progress, warnings and errors. That is what makes
//! `unsubscribe run --resumed --yes --json > run.json` produce a parseable file
//! whether or not anything went wrong along the way.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};

/// The version of the JSON documents this build emits.
///
/// Bumped when a field changes meaning or disappears; new optional fields do
/// not need it. Every document carries it as `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;

static QUIET: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);

/// Whether narration is suppressed.
#[must_use]
pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Whether the result goes out as JSON.
#[must_use]
pub fn json_mode() -> bool {
    JSON.load(Ordering::Relaxed)
}

pub fn set_json_mode(json: bool) {
    JSON.store(json, Ordering::Relaxed);
}

/// Narration for a person: everything that is not the command's result.
///
/// Goes to stderr, and says nothing under `--quiet`. Errors do not go through
/// here -- a failure is reported however quiet the run was asked to be.
#[macro_export]
macro_rules! note {
    () => {
        if !$crate::output::quiet() { eprintln!(); }
    };
    ($($arg:tt)*) => {
        if !$crate::output::quiet() { eprintln!($($arg)*); }
    };
}

/// Write the command's result document to stdout.
///
/// One document per invocation, pretty-printed and newline-terminated, so the
/// output is both greppable by a person and parseable in one read by a script.
pub fn emit_json(document: &serde_json::Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, document).context("Failed to write JSON output")?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
