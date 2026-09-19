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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use unsubscribe_core::{split_previously_unsubscribed, SenderInfo, UnsubscribeMethod};

    /// A history database in a throwaway directory.
    ///
    /// The `TempDir` is returned alongside the store so it outlives it; dropping
    /// it removes the file.
    fn temp_store() -> (TempDir, SqliteHistoryStore) {
        let dir = TempDir::new().expect("temp dir");
        let store = SqliteHistoryStore::open(dir.path().join(HISTORY_DB_FILE)).expect("open");
        (dir, store)
    }

    /// An attempt with every field set to something distinguishable.
    fn full_attempt(account: &str, sender_email: &str) -> UnsubscribeAttempt {
        UnsubscribeAttempt {
            id: format!("{account}|{sender_email}"),
            account: account.to_string(),
            sender_email: sender_email.to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: Some("news.acme.example.com".to_string()),
            attempted_at: 1_700_000_000,
            method: UnsubscribeMethod::OneClickPost.as_id().to_string(),
            success: true,
            http_status: Some(202),
            url: "https://acme.example.com/unsub?id=1".to_string(),
            final_url: Some("https://acme.example.com/done".to_string()),
            list_unsubscribe_raw: Some(
                "<https://acme.example.com/unsub?id=1>, <mailto:u@acme.example.com>".to_string(),
            ),
            detail: "HTTP 202".to_string(),
        }
    }

    fn sender(email: &str) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: Vec::new(),
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 1,
            messages: Vec::new(),
            last_seen: None,
        }
    }

    // -----------------------------------------------------------------------
    // Round-tripping
    // -----------------------------------------------------------------------

    #[test]
    fn a_recorded_attempt_reads_back_with_every_field_intact() {
        let (_dir, store) = temp_store();
        let attempt = full_attempt("user@example.com", "news@acme.example.com");

        store.record_attempt(&attempt).expect("record");
        let read = store.attempts_for_account("user@example.com").expect("read");

        assert_eq!(read, vec![attempt]);
    }

    #[test]
    fn a_failed_attempt_round_trips_with_its_empty_and_absent_fields() {
        let (_dir, store) = temp_store();
        let attempt = UnsubscribeAttempt {
            id: "failure-1".to_string(),
            account: "user@example.com".to_string(),
            sender_email: "news@acme.example.com".to_string(),
            sender_domain: "acme.example.com".to_string(),
            list_id: None,
            attempted_at: -1,
            method: UnsubscribeMethod::MailtoSkipped.as_id().to_string(),
            success: false,
            http_status: None,
            url: String::new(),
            final_url: None,
            list_unsubscribe_raw: None,
            detail: String::new(),
        };

        store.record_attempt(&attempt).expect("record");
        let read = store.attempts_for_account("user@example.com").expect("read");

        assert_eq!(read, vec![attempt]);
    }

    #[test]
    fn detail_strings_with_quotes_commas_and_newlines_survive() {
        let (_dir, store) = temp_store();
        let nasty = "Form submit error: \"bad, request\"\nline two\t--\u{2014} 'quoted'; DROP TABLE unsubscribe_attempts;--";
        let mut attempt = full_attempt("user@example.com", "news@acme.example.com");
        attempt.detail = nasty.to_string();
        attempt.list_unsubscribe_raw = Some(nasty.to_string());

        store.record_attempt(&attempt).expect("record");
        let read = store.attempts_for_account("user@example.com").expect("read");

        assert_eq!(read[0].detail, nasty);
        assert_eq!(read[0].list_unsubscribe_raw.as_deref(), Some(nasty));
        // The injection attempt above must not have dropped the table.
        assert_eq!(read.len(), 1);
    }

    #[test]
    fn attempts_come_back_oldest_first() {
        let (_dir, store) = temp_store();
        for (id, at) in [("c", 300), ("a", 100), ("b", 200)] {
            let mut attempt = full_attempt("user@example.com", "news@acme.example.com");
            attempt.id = id.to_string();
            attempt.attempted_at = at;
            store.record_attempt(&attempt).expect("record");
        }

        let read = store.attempts_for_account("user@example.com").expect("read");
        assert_eq!(
            read.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
    }

    // -----------------------------------------------------------------------
    // Account scoping
    // -----------------------------------------------------------------------

    #[test]
    fn attempts_for_account_returns_only_that_accounts_rows() {
        let (_dir, store) = temp_store();
        store
            .record_attempt(&full_attempt("alice@example.com", "news@acme.example.com"))
            .expect("record");
        store
            .record_attempt(&full_attempt("bob@example.com", "deals@other.example.com"))
            .expect("record");

        let alice = store.attempts_for_account("alice@example.com").expect("read");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].sender_email, "news@acme.example.com");

        let bob = store.attempts_for_account("bob@example.com").expect("read");
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].sender_email, "deals@other.example.com");
    }

    #[test]
    fn an_account_with_no_attempts_reads_back_empty() {
        let (_dir, store) = temp_store();
        store
            .record_attempt(&full_attempt("alice@example.com", "news@acme.example.com"))
            .expect("record");

        assert!(store
            .attempts_for_account("nobody@example.com")
            .expect("read")
            .is_empty());
    }

    #[test]
    fn account_matching_is_exact_not_fuzzy() {
        let (_dir, store) = temp_store();
        store
            .record_attempt(&full_attempt("alice@example.com", "news@acme.example.com"))
            .expect("record");

        assert!(store
            .attempts_for_account("ALICE@EXAMPLE.COM")
            .expect("read")
            .is_empty());
        assert!(store
            .attempts_for_account("alice@example.co")
            .expect("read")
            .is_empty());
    }

    #[test]
    fn another_accounts_history_never_marks_a_sender_as_previously_unsubscribed() {
        let (_dir, store) = temp_store();
        store
            .record_attempt(&full_attempt("bob@example.com", "news@acme.example.com"))
            .expect("record");

        let alice_history = store.attempts_for_account("alice@example.com").expect("read");
        let sections =
            split_previously_unsubscribed(vec![sender("news@acme.example.com")], &alice_history);

        assert!(sections.previously_unsubscribed.is_empty());
        assert_eq!(sections.remaining.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Schema and reopening
    // -----------------------------------------------------------------------

    #[test]
    fn opening_a_fresh_database_creates_the_schema() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("nested").join(HISTORY_DB_FILE);
        assert!(!path.exists());

        let store = SqliteHistoryStore::open(&path).expect("open");
        assert!(path.exists(), "the database file should be created");
        assert!(store
            .attempts_for_account("user@example.com")
            .expect("read")
            .is_empty());
    }

    #[test]
    fn user_version_reflects_the_applied_migration() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(HISTORY_DB_FILE);
        let _store = SqliteHistoryStore::open(&path).expect("open");

        let conn = rusqlite::Connection::open(&path).expect("reopen");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user_version");
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn reopening_an_existing_database_preserves_rows_and_the_version() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(HISTORY_DB_FILE);

        let attempt = full_attempt("user@example.com", "news@acme.example.com");
        {
            let store = SqliteHistoryStore::open(&path).expect("first open");
            store.record_attempt(&attempt).expect("record");
        }

        let store = SqliteHistoryStore::open(&path).expect("second open");
        assert_eq!(
            store.attempts_for_account("user@example.com").expect("read"),
            vec![attempt]
        );

        let conn = rusqlite::Connection::open(&path).expect("reopen");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user_version");
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn two_stores_on_one_file_can_both_write() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(HISTORY_DB_FILE);

        let first = SqliteHistoryStore::open(&path).expect("open first");
        let second = SqliteHistoryStore::open(&path).expect("open second");

        let mut a = full_attempt("user@example.com", "a@acme.example.com");
        a.id = "from-first".to_string();
        let mut b = full_attempt("user@example.com", "b@acme.example.com");
        b.id = "from-second".to_string();

        first.record_attempt(&a).expect("first write");
        second.record_attempt(&b).expect("second write");

        let mut ids: Vec<String> = first
            .attempts_for_account("user@example.com")
            .expect("read")
            .into_iter()
            .map(|attempt| attempt.id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["from-first", "from-second"]);
    }

    #[test]
    fn recording_the_same_id_twice_is_rejected() {
        // Ids are unique by construction; a duplicate means a caller bug, and
        // the history must not silently absorb it.
        let (_dir, store) = temp_store();
        let attempt = full_attempt("user@example.com", "news@acme.example.com");

        store.record_attempt(&attempt).expect("first record");
        assert!(store.record_attempt(&attempt).is_err());
        assert_eq!(
            store.attempts_for_account("user@example.com").expect("read").len(),
            1
        );
    }
}
