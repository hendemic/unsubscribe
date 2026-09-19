//! SQLite-backed `HistoryStore`: the durable, append-only record of unsubscribe
//! attempts, stored at `{data_dir}/history.db`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, Row};
use unsubscribe_core::{HistoryStore, UnsubscribeAttempt};

use crate::sqlite::{apply_migrations, open_database};

/// Schema migrations, in order. Append only -- never edit a released entry.
const MIGRATIONS: &[&str] = &["
    CREATE TABLE unsubscribe_attempts (
        id                   TEXT PRIMARY KEY,
        account              TEXT NOT NULL,
        sender_email         TEXT NOT NULL,
        sender_domain        TEXT NOT NULL,
        list_id              TEXT,
        attempted_at         INTEGER NOT NULL,
        method               TEXT NOT NULL,
        success              INTEGER NOT NULL,
        http_status          INTEGER,
        url                  TEXT NOT NULL,
        final_url            TEXT,
        list_unsubscribe_raw TEXT,
        detail               TEXT NOT NULL
    );
    CREATE INDEX idx_attempts_account_sender
        ON unsubscribe_attempts (account, sender_email);
"];

/// The file name used inside the data directory.
pub const HISTORY_DB_FILE: &str = "history.db";

/// Append-only unsubscribe history backed by SQLite.
///
/// There are no UPDATE or DELETE paths here by design: the history is evidence,
/// and a record that can be rewritten is not evidence.
pub struct SqliteHistoryStore {
    conn: Mutex<Connection>,
}

impl SqliteHistoryStore {
    /// Open (creating if needed) the history database at `path`.
    ///
    /// The path is a parameter rather than derived internally so tests can use
    /// a temp file or `:memory:` without touching the real data directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = open_database(path.as_ref())?;
        apply_migrations(&conn, MIGRATIONS)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open the history database at its standard location in the data directory.
    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_path())
    }

    /// Standard location of the history database, for display in messages.
    pub fn default_path() -> PathBuf {
        crate::data_dir().join(HISTORY_DB_FILE)
    }
}

impl HistoryStore for SqliteHistoryStore {
    fn record_attempt(&self, attempt: &UnsubscribeAttempt) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        conn.execute(
            "INSERT INTO unsubscribe_attempts (
                 id, account, sender_email, sender_domain, list_id, attempted_at,
                 method, success, http_status, url, final_url, list_unsubscribe_raw, detail
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                attempt.id,
                attempt.account,
                attempt.sender_email,
                attempt.sender_domain,
                attempt.list_id,
                attempt.attempted_at,
                attempt.method,
                attempt.success,
                attempt.http_status,
                attempt.url,
                attempt.final_url,
                attempt.list_unsubscribe_raw,
                attempt.detail,
            ],
        )
        .context("Failed to record unsubscribe attempt")?;
        Ok(())
    }

    fn attempts_for_account(&self, account: &str) -> Result<Vec<UnsubscribeAttempt>> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, account, sender_email, sender_domain, list_id, attempted_at,
                        method, success, http_status, url, final_url, list_unsubscribe_raw, detail
                 FROM unsubscribe_attempts
                 WHERE account = ?1
                 ORDER BY attempted_at ASC, id ASC",
            )
            .context("Failed to prepare history query")?;

        let attempts = stmt
            .query_map([account], row_to_attempt)
            .context("Failed to read unsubscribe history")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Failed to read unsubscribe history")?;

        Ok(attempts)
    }
}

fn row_to_attempt(row: &Row<'_>) -> rusqlite::Result<UnsubscribeAttempt> {
    Ok(UnsubscribeAttempt {
        id: row.get(0)?,
        account: row.get(1)?,
        sender_email: row.get(2)?,
        sender_domain: row.get(3)?,
        list_id: row.get(4)?,
        attempted_at: row.get(5)?,
        method: row.get(6)?,
        success: row.get(7)?,
        http_status: row.get(8)?,
        url: row.get(9)?,
        final_url: row.get(10)?,
        list_unsubscribe_raw: row.get(11)?,
        detail: row.get(12)?,
    })
}

/// A poisoned lock means a previous caller panicked mid-statement; the
/// connection is not trustworthy, so report rather than plough on.
fn poisoned() -> anyhow::Error {
    anyhow::anyhow!("History database connection is poisoned")
}
