//! Shared SQLite plumbing: connection setup and `PRAGMA user_version` migrations.
//!
//! Both stores in this crate (`history.db` and `cache.db`) open their databases
//! through here so they agree on journal mode, busy handling, and how schema
//! versions advance. They stay separate files on purpose: deleting the cache
//! must always be safe, deleting the history never is.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// How long a writer waits for a competing writer before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Open (creating if needed) a SQLite database in WAL mode.
///
/// `path` may be `:memory:`, which tests use to avoid touching the data
/// directory; in that case no directories are created and the journal mode
/// stays whatever SQLite chooses for an in-memory database.
pub(crate) fn open_database(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create data directory: {}", parent.display())
            })?;
        }
    }

    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;

    conn.busy_timeout(BUSY_TIMEOUT)
        .context("Failed to set SQLite busy timeout")?;

    // journal_mode returns the mode it settled on, so it has to be queried
    // rather than executed. In-memory databases answer "memory" and that is fine.
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .context("Failed to enable WAL mode")?;

    Ok(conn)
}

/// Apply any migrations the database has not seen yet.
///
/// The index of a migration in `migrations` is its version, tracked in
/// `PRAGMA user_version`. Each migration and its version bump commit together,
/// so an interrupted upgrade leaves the database on the last complete version.
/// Migrations are therefore append-only: never edit or reorder a released one.
pub(crate) fn apply_migrations(conn: &Connection, migrations: &[&str]) -> Result<()> {
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("Failed to read schema version")?;

    for (index, migration) in migrations.iter().enumerate().skip(current as usize) {
        let version = index + 1;
        conn.execute_batch(&format!(
            "BEGIN;\n{migration};\nPRAGMA user_version = {version};\nCOMMIT;"
        ))
        .with_context(|| format!("Failed to apply schema migration {version}"))?;
    }

    Ok(())
}
