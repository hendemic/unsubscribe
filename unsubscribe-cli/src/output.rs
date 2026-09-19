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

/// Whether narration is suppressed.
#[must_use]
pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
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
    write_json(std::io::stdout().lock(), document)
}

/// The bytes `emit_json` puts on stdout, against any writer.
///
/// Split out so the "exactly one document and nothing else" contract can be
/// checked without a subprocess; `emit_json` is this with stdout bound.
pub fn write_json(mut out: impl Write, document: &serde_json::Value) -> Result<()> {
    serde_json::to_writer_pretty(&mut out, document).context("Failed to write JSON output")?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// What `emit_json` would have put on stdout.
    fn emitted(document: &serde_json::Value) -> String {
        let mut buffer = Vec::new();
        write_json(&mut buffer, document).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn the_output_is_one_json_document_and_nothing_else() {
        let document = json!({ "schema_version": SCHEMA_VERSION, "senders": [] });
        let written = emitted(&document);

        let mut stream = serde_json::Deserializer::from_str(&written).into_iter::<Value>();
        assert_eq!(stream.next().transpose().unwrap(), Some(document));
        assert!(
            stream.next().is_none(),
            "a second document followed the first: {written:?}"
        );
    }

    #[test]
    fn the_document_ends_with_exactly_one_newline() {
        // A script reads the stream once; trailing noise would be part of it.
        let written = emitted(&json!({ "count": 0 }));
        assert!(written.ends_with("}\n"), "{written:?}");
        assert!(!written.ends_with("\n\n"), "{written:?}");
    }

    #[test]
    fn the_document_is_pretty_printed_for_a_person_reading_it() {
        let written = emitted(&json!({ "count": 0 }));
        assert!(written.contains("\n  \"count\""), "{written:?}");
    }

    #[test]
    fn nothing_is_written_before_the_document_begins() {
        let written = emitted(&json!({ "count": 0 }));
        assert!(written.starts_with('{'), "{written:?}");
    }

    #[test]
    fn an_empty_listing_is_still_a_parseable_document() {
        // The "nothing to do" paths emit a document too, so a script never has
        // to special-case an empty run.
        let written = emitted(&json!({ "schema_version": SCHEMA_VERSION, "senders": [], "count": 0 }));
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["count"], 0);
    }

    #[test]
    fn the_schema_version_is_the_one_documents_carry() {
        // Bumped only when a field changes meaning or disappears; pinned here
        // so that is a deliberate edit.
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn the_quiet_switch_note_reads_follows_what_it_was_set_to() {
        // `note!` is a macro, so this flag is the only seam that decides
        // whether narration reaches stderr. Restored afterwards because it is
        // process-wide and the test binary is shared.
        let previous = quiet();
        set_quiet(true);
        assert!(quiet());
        set_quiet(false);
        assert!(!quiet());
        set_quiet(previous);
    }
}
