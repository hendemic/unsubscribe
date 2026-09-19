//! SQLite-backed `ScanCacheStore`, stored at `{data_dir}/cache.db`.
//!
//! Deliberately a different file from `history.db`: deleting the cache must
//! always be safe. It is also stored row by row rather than as one JSON blob,
//! so a later incremental scan can add messages to an existing sender and
//! advance a folder's watermark without rewriting everything.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction};
use unsubscribe_core::{
    CacheMeta, CachedScan, FolderMessage, Folder, MessageId, ScanCacheStore, ScanWatermark,
    SenderInfo,
};

use crate::sqlite::{apply_migrations, open_database};

/// Schema migrations, in order. Append only -- never edit a released entry.
const MIGRATIONS: &[&str] = &["
    CREATE TABLE scan_meta (
        account        TEXT PRIMARY KEY,
        scanned_at     TEXT NOT NULL,
        format_version INTEGER NOT NULL,
        adapter_state  TEXT
    );
    CREATE TABLE scan_watermarks (
        account      TEXT NOT NULL,
        folder       TEXT NOT NULL,
        highest_uid  INTEGER,
        uid_validity INTEGER,
        PRIMARY KEY (account, folder)
    );
    CREATE TABLE scan_senders (
        account              TEXT NOT NULL,
        sender_key           TEXT NOT NULL,
        position             INTEGER NOT NULL,
        display_name         TEXT NOT NULL,
        email                TEXT NOT NULL,
        domain               TEXT NOT NULL,
        one_click            INTEGER NOT NULL,
        list_id              TEXT,
        list_unsubscribe_raw TEXT,
        email_count          INTEGER NOT NULL,
        last_seen            INTEGER,
        PRIMARY KEY (account, sender_key)
    );
    CREATE TABLE scan_unsubscribe_targets (
        account    TEXT NOT NULL,
        sender_key TEXT NOT NULL,
        kind       TEXT NOT NULL,
        position   INTEGER NOT NULL,
        target     TEXT NOT NULL,
        PRIMARY KEY (account, sender_key, kind, position)
    );
    CREATE TABLE scan_messages (
        account    TEXT NOT NULL,
        folder     TEXT NOT NULL,
        message_id TEXT NOT NULL,
        sender_key TEXT NOT NULL,
        position   INTEGER NOT NULL,
        PRIMARY KEY (account, folder, message_id)
    );
    CREATE INDEX idx_scan_messages_sender ON scan_messages (account, sender_key);
"];

/// Target kinds in `scan_unsubscribe_targets`. Stored values, not display text.
const KIND_HTTP: &str = "http";
const KIND_MAILTO: &str = "mailto";

/// The file name used inside the data directory.
pub const CACHE_DB_FILE: &str = "cache.db";

/// Row-level scan cache backed by SQLite.
pub struct SqliteCacheStore {
    conn: Mutex<Connection>,
}

impl SqliteCacheStore {
    /// Open (creating if needed) the cache database at `path`.
    ///
    /// The path is a parameter rather than derived internally so tests can use
    /// a temp file or `:memory:` without touching the real data directory.
    ///
    /// Any `scan_cache_*.json` left by the previous file-based cache is deleted
    /// here. There is no import: the cache is disposable and a rescan rebuilds it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = open_database(path)?;
        apply_migrations(&conn, MIGRATIONS)?;

        if let Some(dir) = path.parent() {
            remove_legacy_json_caches(dir);
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open the cache database at its standard location in the data directory.
    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_path())
    }

    /// Standard location of the cache database, for display in messages.
    pub fn default_path() -> PathBuf {
        crate::data_dir().join(CACHE_DB_FILE)
    }
}

impl ScanCacheStore for SqliteCacheStore {
    fn read_scan_cache(&self, account: &str) -> Result<Option<CachedScan>> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;

        let meta = conn
            .query_row(
                "SELECT scanned_at, format_version, adapter_state FROM scan_meta WHERE account = ?1",
                [account],
                |row| {
                    Ok((
                        CacheMeta {
                            scanned_at: row.get(0)?,
                            format_version: row.get(1)?,
                            account: account.to_string(),
                        },
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .context("Failed to read scan cache metadata")?;

        let Some((meta, adapter_state)) = meta else {
            return Ok(None);
        };

        let watermark = read_watermark(&conn, account, adapter_state)?;
        let senders = read_senders(&conn, account)?;

        Ok(Some(CachedScan {
            meta,
            senders,
            watermark,
        }))
    }

    fn write_scan_cache(&self, cache: &CachedScan) -> Result<()> {
        let mut conn = self.conn.lock().map_err(|_| poisoned())?;
        let tx = conn
            .transaction()
            .context("Failed to begin scan cache transaction")?;
        let account = cache.meta.account.as_str();

        // A scan is a complete picture of the account, so replacing it wholesale
        // is correct; other accounts' rows are addressed by key and untouched.
        delete_account_rows(&tx, account, &["scan_meta", "scan_watermarks"])?;
        delete_sender_rows(&tx, account)?;

        tx.execute(
            "INSERT INTO scan_meta (account, scanned_at, format_version, adapter_state)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                account,
                cache.meta.scanned_at,
                cache.meta.format_version,
                cache.watermark.adapter_state,
            ],
        )
        .context("Failed to write scan cache metadata")?;

        write_watermark(&tx, account, &cache.watermark)?;
        write_senders(&tx, account, &cache.senders)?;

        tx.commit().context("Failed to commit scan cache")?;
        Ok(())
    }

    fn remove_cached_senders(&self, account: &str, sender_emails: &[String]) -> Result<()> {
        if sender_emails.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().map_err(|_| poisoned())?;
        let tx = conn
            .transaction()
            .context("Failed to begin scan cache prune")?;

        for email in sender_emails {
            let key = email.to_lowercase();
            for table in ["scan_senders", "scan_unsubscribe_targets", "scan_messages"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE account = ?1 AND sender_key = ?2"),
                    rusqlite::params![account, key],
                )
                .with_context(|| format!("Failed to prune {table}"))?;
            }
        }

        tx.commit().context("Failed to commit scan cache prune")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

fn read_watermark(
    conn: &Connection,
    account: &str,
    adapter_state: Option<String>,
) -> Result<ScanWatermark> {
    let mut stmt = conn
        .prepare("SELECT folder, highest_uid, uid_validity FROM scan_watermarks WHERE account = ?1")
        .context("Failed to prepare watermark query")?;

    let mut highest_uid = HashMap::new();
    let mut uid_validity = HashMap::new();

    let rows = stmt
        .query_map([account], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<u32>>(1)?,
                row.get::<_, Option<u32>>(2)?,
            ))
        })
        .context("Failed to read watermarks")?;

    for row in rows {
        let (folder, uid, validity) = row.context("Failed to read watermark row")?;
        if let Some(uid) = uid {
            highest_uid.insert(folder.clone(), uid);
        }
        if let Some(validity) = validity {
            uid_validity.insert(folder, validity);
        }
    }

    Ok(ScanWatermark {
        highest_uid,
        uid_validity,
        adapter_state,
    })
}

fn read_senders(conn: &Connection, account: &str) -> Result<Vec<SenderInfo>> {
    let mut stmt = conn
        .prepare(
            "SELECT sender_key, display_name, email, domain, one_click, list_id,
                    list_unsubscribe_raw, email_count, last_seen
             FROM scan_senders
             WHERE account = ?1
             ORDER BY position ASC",
        )
        .context("Failed to prepare sender query")?;

    let rows = stmt
        .query_map([account], |row| {
            Ok((
                row.get::<_, String>(0)?,
                SenderInfo {
                    display_name: row.get(1)?,
                    email: row.get(2)?,
                    domain: row.get(3)?,
                    unsubscribe_urls: Vec::new(),
                    unsubscribe_mailto: Vec::new(),
                    one_click: row.get(4)?,
                    list_id: row.get(5)?,
                    list_unsubscribe_raw: row.get(6)?,
                    email_count: row.get(7)?,
                    messages: Vec::new(),
                    last_seen: row.get(8)?,
                },
            ))
        })
        .context("Failed to read cached senders")?;

    let mut keys = Vec::new();
    let mut senders = Vec::new();
    for row in rows {
        let (key, sender) = row.context("Failed to read cached sender row")?;
        keys.push(key);
        senders.push(sender);
    }

    let mut targets = read_targets(conn, account)?;
    let mut messages = read_messages(conn, account)?;

    for (key, sender) in keys.iter().zip(senders.iter_mut()) {
        if let Some((urls, mailtos)) = targets.remove(key) {
            sender.unsubscribe_urls = urls;
            sender.unsubscribe_mailto = mailtos;
        }
        if let Some(sender_messages) = messages.remove(key) {
            sender.messages = sender_messages;
        }
    }

    Ok(senders)
}

/// Unsubscribe targets per sender key, as `(http urls, mailto targets)` in the
/// order they were written -- the first URL is the one the flow actually uses.
type SenderTargets = HashMap<String, (Vec<String>, Vec<String>)>;

fn read_targets(conn: &Connection, account: &str) -> Result<SenderTargets> {
    let mut stmt = conn
        .prepare(
            "SELECT sender_key, kind, target FROM scan_unsubscribe_targets
             WHERE account = ?1
             ORDER BY position ASC",
        )
        .context("Failed to prepare unsubscribe target query")?;

    let rows = stmt
        .query_map([account], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .context("Failed to read unsubscribe targets")?;

    let mut targets: SenderTargets = HashMap::new();
    for row in rows {
        let (key, kind, target) = row.context("Failed to read unsubscribe target row")?;
        let entry = targets.entry(key).or_default();
        if kind == KIND_MAILTO {
            entry.1.push(target);
        } else {
            entry.0.push(target);
        }
    }
    Ok(targets)
}

fn read_messages(conn: &Connection, account: &str) -> Result<HashMap<String, Vec<FolderMessage>>> {
    let mut stmt = conn
        .prepare(
            "SELECT sender_key, folder, message_id FROM scan_messages
             WHERE account = ?1
             ORDER BY position ASC",
        )
        .context("Failed to prepare cached message query")?;

    let rows = stmt
        .query_map([account], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .context("Failed to read cached messages")?;

    let mut messages: HashMap<String, Vec<FolderMessage>> = HashMap::new();
    for row in rows {
        let (key, folder, message_id) = row.context("Failed to read cached message row")?;
        messages.entry(key).or_default().push(FolderMessage {
            folder: Folder::new(folder),
            message_id: MessageId::new(message_id),
        });
    }
    Ok(messages)
}

// ---------------------------------------------------------------------------
// Write helpers
// ---------------------------------------------------------------------------

fn delete_account_rows(tx: &Transaction<'_>, account: &str, tables: &[&str]) -> Result<()> {
    for table in tables {
        tx.execute(
            &format!("DELETE FROM {table} WHERE account = ?1"),
            [account],
        )
        .with_context(|| format!("Failed to clear {table}"))?;
    }
    Ok(())
}

fn delete_sender_rows(tx: &Transaction<'_>, account: &str) -> Result<()> {
    delete_account_rows(
        tx,
        account,
        &["scan_senders", "scan_unsubscribe_targets", "scan_messages"],
    )
}

fn write_watermark(tx: &Transaction<'_>, account: &str, watermark: &ScanWatermark) -> Result<()> {
    // The two maps are populated independently, so a folder can appear in one
    // and not the other; the row carries NULL for the missing side.
    let folders: std::collections::BTreeSet<&String> = watermark
        .highest_uid
        .keys()
        .chain(watermark.uid_validity.keys())
        .collect();

    for folder in folders {
        tx.execute(
            "INSERT INTO scan_watermarks (account, folder, highest_uid, uid_validity)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                account,
                folder,
                watermark.highest_uid.get(folder),
                watermark.uid_validity.get(folder),
            ],
        )
        .context("Failed to write watermark")?;
    }
    Ok(())
}

fn write_senders(tx: &Transaction<'_>, account: &str, senders: &[SenderInfo]) -> Result<()> {
    for (position, sender) in senders.iter().enumerate() {
        let key = sender.email.to_lowercase();

        tx.execute(
            "INSERT INTO scan_senders (
                 account, sender_key, position, display_name, email, domain, one_click,
                 list_id, list_unsubscribe_raw, email_count, last_seen
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                account,
                key,
                position as i64,
                sender.display_name,
                sender.email,
                sender.domain,
                sender.one_click,
                sender.list_id,
                sender.list_unsubscribe_raw,
                sender.email_count,
                sender.last_seen,
            ],
        )
        .context("Failed to write cached sender")?;

        let targets = sender
            .unsubscribe_urls
            .iter()
            .map(|url| (KIND_HTTP, url))
            .chain(
                sender
                    .unsubscribe_mailto
                    .iter()
                    .map(|target| (KIND_MAILTO, target)),
            );
        for (index, (kind, target)) in targets.enumerate() {
            tx.execute(
                "INSERT INTO scan_unsubscribe_targets (account, sender_key, kind, position, target)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![account, key, kind, index as i64, target],
            )
            .context("Failed to write unsubscribe target")?;
        }

        for (index, message) in sender.messages.iter().enumerate() {
            tx.execute(
                "INSERT OR REPLACE INTO scan_messages
                     (account, folder, message_id, sender_key, position)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    account,
                    message.folder.as_str(),
                    message.message_id.as_str(),
                    key,
                    index as i64,
                ],
            )
            .context("Failed to write cached message")?;
        }
    }
    Ok(())
}

/// Delete the JSON caches written by the previous file-based store.
///
/// Best effort: a cache we cannot delete is stale data we simply stop reading.
fn remove_legacy_json_caches(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("scan_cache_") && name.ends_with(".json") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// A poisoned lock means a previous caller panicked mid-statement; the
/// connection is not trustworthy, so report rather than plough on.
fn poisoned() -> anyhow::Error {
    anyhow::anyhow!("Cache database connection is poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A cache database in a throwaway directory.
    ///
    /// The `TempDir` is returned alongside the store so it outlives it.
    fn temp_store() -> (TempDir, SqliteCacheStore) {
        let dir = TempDir::new().expect("temp dir");
        let store = SqliteCacheStore::open(dir.path().join(CACHE_DB_FILE)).expect("open");
        (dir, store)
    }

    fn sender(email: &str) -> SenderInfo {
        SenderInfo {
            display_name: format!("{email} Newsletter"),
            email: email.to_string(),
            domain: email.rsplit('@').next().unwrap_or("").to_string(),
            unsubscribe_urls: vec![format!("https://{email}/unsub")],
            unsubscribe_mailto: vec![format!("mailto:unsub@{email}")],
            one_click: false,
            list_id: Some(format!("list.{email}")),
            list_unsubscribe_raw: Some(format!("<https://{email}/unsub>")),
            email_count: 3,
            messages: vec![FolderMessage {
                folder: Folder::new("INBOX"),
                message_id: MessageId::new(format!("INBOX:1:1:{email}")),
            }],
            last_seen: Some(1_700_000_000),
        }
    }

    fn cached_scan(account: &str, senders: Vec<SenderInfo>) -> CachedScan {
        CachedScan {
            meta: CacheMeta {
                scanned_at: "2026-03-18T19:30:00Z".to_string(),
                format_version: 1,
                account: account.to_string(),
            },
            senders,
            watermark: ScanWatermark {
                highest_uid: HashMap::from([("INBOX".to_string(), 42u32)]),
                uid_validity: HashMap::from([("INBOX".to_string(), 7u32)]),
                adapter_state: Some("historyId:991".to_string()),
            },
        }
    }

    /// Every sender email in a cached scan, in the order it reads back.
    fn emails(scan: &CachedScan) -> Vec<&str> {
        scan.senders.iter().map(|s| s.email.as_str()).collect()
    }

    /// Row count in a cache table, read through a second connection so that
    /// leftovers invisible to `read_scan_cache` are still caught.
    fn row_count(path: &std::path::Path, table: &str) -> i64 {
        let conn = rusqlite::Connection::open(path).expect("reopen");
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .expect("count")
    }

    // -----------------------------------------------------------------------
    // Round-tripping
    // -----------------------------------------------------------------------

    #[test]
    fn reading_an_account_with_no_cache_returns_none_not_an_error() {
        let (_dir, store) = temp_store();
        assert!(store
            .read_scan_cache("user@example.com")
            .expect("read must succeed")
            .is_none());
    }

    #[test]
    fn a_written_scan_reads_back_with_every_field_intact() {
        let (_dir, store) = temp_store();
        let written = cached_scan("user@example.com", vec![sender("news@acme.com")]);

        store.write_scan_cache(&written).expect("write");
        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .expect("cache present");

        assert_eq!(read.meta.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(read.meta.format_version, 1);
        assert_eq!(read.meta.account, "user@example.com");

        let s = &read.senders[0];
        let original = &written.senders[0];
        assert_eq!(s.display_name, original.display_name);
        assert_eq!(s.email, original.email);
        assert_eq!(s.domain, original.domain);
        assert_eq!(s.unsubscribe_urls, original.unsubscribe_urls);
        assert_eq!(s.unsubscribe_mailto, original.unsubscribe_mailto);
        assert_eq!(s.one_click, original.one_click);
        assert_eq!(s.list_id, original.list_id);
        assert_eq!(s.list_unsubscribe_raw, original.list_unsubscribe_raw);
        assert_eq!(s.email_count, original.email_count);
        assert_eq!(s.last_seen, original.last_seen);
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.messages[0].folder.as_str(), "INBOX");
        assert_eq!(s.messages[0].message_id.as_str(), "INBOX:1:1:news@acme.com");

        assert_eq!(read.watermark.highest_uid, written.watermark.highest_uid);
        assert_eq!(read.watermark.uid_validity, written.watermark.uid_validity);
        assert_eq!(
            read.watermark.adapter_state.as_deref(),
            Some("historyId:991")
        );
    }

    #[test]
    fn a_sender_with_no_last_seen_date_round_trips_as_none() {
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.last_seen = None;
        s.list_id = None;
        s.list_unsubscribe_raw = None;
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![s]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.senders[0].last_seen, None);
        assert_eq!(read.senders[0].list_id, None);
        assert_eq!(read.senders[0].list_unsubscribe_raw, None);
    }

    #[test]
    fn the_one_click_flag_round_trips_in_both_states() {
        let (_dir, store) = temp_store();
        let mut yes = sender("yes@acme.com");
        yes.one_click = true;
        let no = sender("no@acme.com");
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![yes, no]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert!(read.senders[0].one_click);
        assert!(!read.senders[1].one_click);
    }

    #[test]
    fn unsubscribe_target_order_is_preserved() {
        // `best_unsubscribe_url` takes the first URL, so a reordered cache
        // would silently change which endpoint a run hits.
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.unsubscribe_urls = vec![
            "https://acme.com/first".to_string(),
            "https://acme.com/second".to_string(),
            "https://acme.com/third".to_string(),
        ];
        s.unsubscribe_mailto = vec![
            "mailto:a@acme.com".to_string(),
            "mailto:b@acme.com".to_string(),
        ];
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![s]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(
            read.senders[0].unsubscribe_urls,
            [
                "https://acme.com/first",
                "https://acme.com/second",
                "https://acme.com/third"
            ]
        );
        assert_eq!(
            read.senders[0].unsubscribe_mailto,
            ["mailto:a@acme.com", "mailto:b@acme.com"]
        );
        assert_eq!(
            read.senders[0].best_unsubscribe_url(),
            Some("https://acme.com/first")
        );
    }

    #[test]
    fn sender_order_is_preserved() {
        // Senders arrive sorted by email count; the cache must not reshuffle
        // them into some storage order.
        let (_dir, store) = temp_store();
        let senders = vec![
            sender("z@acme.com"),
            sender("a@acme.com"),
            sender("m@acme.com"),
        ];
        store
            .write_scan_cache(&cached_scan("user@example.com", senders))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["z@acme.com", "a@acme.com", "m@acme.com"]);
    }

    #[test]
    fn message_order_within_a_sender_is_preserved() {
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.messages = (0..5)
            .map(|i| FolderMessage {
                folder: Folder::new("INBOX"),
                message_id: MessageId::new(format!("INBOX:{i}:1")),
            })
            .collect();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![s]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(
            read.senders[0]
                .messages
                .iter()
                .map(|m| m.message_id.as_str())
                .collect::<Vec<_>>(),
            ["INBOX:0:1", "INBOX:1:1", "INBOX:2:1", "INBOX:3:1", "INBOX:4:1"]
        );
    }

    #[test]
    fn a_sender_with_no_unsubscribe_targets_round_trips() {
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.unsubscribe_urls.clear();
        s.unsubscribe_mailto.clear();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![s]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.senders.len(), 1);
        assert!(read.senders[0].unsubscribe_urls.is_empty());
        assert!(read.senders[0].unsubscribe_mailto.is_empty());
    }

    #[test]
    fn a_sender_with_no_messages_round_trips() {
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.messages.clear();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![s]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.senders.len(), 1);
        assert!(read.senders[0].messages.is_empty());
    }

    #[test]
    fn a_scan_with_no_senders_round_trips() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![]))
            .expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .expect("metadata is still a cache");
        assert!(read.senders.is_empty());
        assert_eq!(read.meta.scanned_at, "2026-03-18T19:30:00Z");
    }

    #[test]
    fn an_absent_watermark_round_trips_as_empty() {
        let (_dir, store) = temp_store();
        let mut scan = cached_scan("user@example.com", vec![sender("news@acme.com")]);
        scan.watermark = ScanWatermark {
            highest_uid: HashMap::new(),
            uid_validity: HashMap::new(),
            adapter_state: None,
        };
        store.write_scan_cache(&scan).expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert!(read.watermark.highest_uid.is_empty());
        assert!(read.watermark.uid_validity.is_empty());
        assert_eq!(read.watermark.adapter_state, None);
    }

    #[test]
    fn a_folder_present_in_only_one_watermark_map_round_trips() {
        let (_dir, store) = temp_store();
        let mut scan = cached_scan("user@example.com", vec![sender("news@acme.com")]);
        scan.watermark.highest_uid = HashMap::from([("Archive".to_string(), 9u32)]);
        scan.watermark.uid_validity = HashMap::from([("INBOX".to_string(), 5u32)]);
        store.write_scan_cache(&scan).expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.watermark.highest_uid, HashMap::from([("Archive".to_string(), 9)]));
        assert_eq!(read.watermark.uid_validity, HashMap::from([("INBOX".to_string(), 5)]));
    }

    #[test]
    fn unicode_quotes_and_slashes_in_names_and_folders_round_trip() {
        let (_dir, store) = temp_store();
        let mut s = sender("news@acme.com");
        s.display_name = "Café \"Déjà Vu\" — ニュース; DROP TABLE scan_senders;--".to_string();
        s.messages = vec![
            FolderMessage {
                folder: Folder::new("[Gmail]/All Mail"),
                message_id: MessageId::new("[Gmail]/All Mail:1:1"),
            },
            FolderMessage {
                folder: Folder::new("Dossiers/Reçus 'divers'"),
                message_id: MessageId::new("Dossiers/Reçus 'divers':2:1"),
            },
        ];
        let mut scan = cached_scan("user@example.com", vec![s.clone()]);
        scan.watermark.highest_uid =
            HashMap::from([("[Gmail]/All Mail".to_string(), 12u32)]);
        scan.watermark.uid_validity = HashMap::new();
        store.write_scan_cache(&scan).expect("write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.senders[0].display_name, s.display_name);
        assert_eq!(
            read.senders[0]
                .messages
                .iter()
                .map(|m| m.folder.as_str())
                .collect::<Vec<_>>(),
            ["[Gmail]/All Mail", "Dossiers/Reçus 'divers'"]
        );
        assert_eq!(
            read.watermark.highest_uid.get("[Gmail]/All Mail"),
            Some(&12)
        );
    }

    // -----------------------------------------------------------------------
    // Replacement and account isolation
    // -----------------------------------------------------------------------

    #[test]
    fn a_second_write_replaces_the_first_with_no_leftover_rows() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(CACHE_DB_FILE);
        let store = SqliteCacheStore::open(&path).expect("open");

        store
            .write_scan_cache(&cached_scan(
                "user@example.com",
                vec![sender("a@acme.com"), sender("b@acme.com")],
            ))
            .expect("first write");

        let mut second = cached_scan("user@example.com", vec![sender("c@acme.com")]);
        second.meta.scanned_at = "2026-03-25T08:00:00Z".to_string();
        second.watermark.highest_uid = HashMap::from([("Archive".to_string(), 3u32)]);
        second.watermark.uid_validity = HashMap::new();
        store.write_scan_cache(&second).expect("second write");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["c@acme.com"]);
        assert_eq!(read.meta.scanned_at, "2026-03-25T08:00:00Z");
        assert_eq!(read.watermark.highest_uid, HashMap::from([("Archive".to_string(), 3)]));
        assert!(read.watermark.uid_validity.is_empty());

        // Nothing from the first scan may survive at the row level.
        assert_eq!(row_count(&path, "scan_senders"), 1);
        assert_eq!(row_count(&path, "scan_messages"), 1);
        assert_eq!(row_count(&path, "scan_unsubscribe_targets"), 2);
        assert_eq!(row_count(&path, "scan_watermarks"), 1);
        assert_eq!(row_count(&path, "scan_meta"), 1);
    }

    #[test]
    fn writing_one_account_leaves_another_accounts_cache_untouched() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("alice@example.com", vec![sender("a@acme.com")]))
            .expect("write alice");
        store
            .write_scan_cache(&cached_scan("bob@example.com", vec![sender("b@acme.com")]))
            .expect("write bob");

        // Rewriting bob's scan must not disturb alice's.
        store
            .write_scan_cache(&cached_scan(
                "bob@example.com",
                vec![sender("b2@acme.com")],
            ))
            .expect("rewrite bob");

        let alice = store
            .read_scan_cache("alice@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&alice), ["a@acme.com"]);
        assert_eq!(alice.watermark.adapter_state.as_deref(), Some("historyId:991"));

        let bob = store.read_scan_cache("bob@example.com").expect("read").unwrap();
        assert_eq!(emails(&bob), ["b2@acme.com"]);
    }

    #[test]
    fn two_accounts_can_cache_the_same_sender_independently() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan(
                "alice@example.com",
                vec![sender("news@acme.com")],
            ))
            .expect("write alice");
        store
            .write_scan_cache(&cached_scan(
                "bob@example.com",
                vec![sender("news@acme.com")],
            ))
            .expect("write bob");

        assert_eq!(
            store
                .read_scan_cache("alice@example.com")
                .expect("read")
                .unwrap()
                .senders
                .len(),
            1
        );
        assert_eq!(
            store
                .read_scan_cache("bob@example.com")
                .expect("read")
                .unwrap()
                .senders
                .len(),
            1
        );
    }

    #[test]
    fn reopening_the_database_preserves_the_cache() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(CACHE_DB_FILE);
        {
            let store = SqliteCacheStore::open(&path).expect("first open");
            store
                .write_scan_cache(&cached_scan("user@example.com", vec![sender("a@acme.com")]))
                .expect("write");
        }

        let store = SqliteCacheStore::open(&path).expect("second open");
        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["a@acme.com"]);

        let conn = rusqlite::Connection::open(&path).expect("reopen");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user_version");
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    // -----------------------------------------------------------------------
    // Pruning
    // -----------------------------------------------------------------------

    #[test]
    fn removing_a_sender_drops_its_message_and_target_rows_too() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(CACHE_DB_FILE);
        let store = SqliteCacheStore::open(&path).expect("open");
        store
            .write_scan_cache(&cached_scan(
                "user@example.com",
                vec![sender("a@acme.com"), sender("b@acme.com")],
            ))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &["a@acme.com".to_string()])
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["b@acme.com"]);
        assert_eq!(row_count(&path, "scan_senders"), 1);
        assert_eq!(row_count(&path, "scan_messages"), 1);
        assert_eq!(row_count(&path, "scan_unsubscribe_targets"), 2);
    }

    #[test]
    fn pruning_leaves_the_watermark_and_scan_timestamp_alone() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan(
                "user@example.com",
                vec![sender("a@acme.com"), sender("b@acme.com")],
            ))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &["a@acme.com".to_string()])
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.meta.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(read.watermark.highest_uid, HashMap::from([("INBOX".to_string(), 42)]));
        assert_eq!(read.watermark.uid_validity, HashMap::from([("INBOX".to_string(), 7)]));
        assert_eq!(read.watermark.adapter_state.as_deref(), Some("historyId:991"));
    }

    #[test]
    fn the_remaining_senders_keep_their_own_data() {
        let (_dir, store) = temp_store();
        let keep = sender("b@acme.com");
        store
            .write_scan_cache(&cached_scan(
                "user@example.com",
                vec![sender("a@acme.com"), keep.clone(), sender("c@acme.com")],
            ))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &["a@acme.com".to_string(), "c@acme.com".to_string()])
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(read.senders.len(), 1);
        assert_eq!(read.senders[0].unsubscribe_urls, keep.unsubscribe_urls);
        assert_eq!(read.senders[0].unsubscribe_mailto, keep.unsubscribe_mailto);
        assert_eq!(read.senders[0].email_count, keep.email_count);
        assert_eq!(
            read.senders[0].messages[0].message_id.as_str(),
            keep.messages[0].message_id.as_str()
        );
    }

    #[test]
    fn pruning_matches_the_sender_address_case_insensitively() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![sender("news@acme.com")]))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &["NEWS@ACME.COM".to_string()])
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert!(read.senders.is_empty());
    }

    #[test]
    fn removing_an_unknown_sender_is_a_no_op() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![sender("a@acme.com")]))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &["nobody@acme.com".to_string()])
            .expect("prune must not error");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["a@acme.com"]);
    }

    #[test]
    fn pruning_an_empty_list_is_a_no_op() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("user@example.com", vec![sender("a@acme.com")]))
            .expect("write");

        store
            .remove_cached_senders("user@example.com", &[])
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read")
            .unwrap();
        assert_eq!(emails(&read), ["a@acme.com"]);
    }

    #[test]
    fn pruning_only_touches_the_named_account() {
        let (_dir, store) = temp_store();
        store
            .write_scan_cache(&cached_scan("alice@example.com", vec![sender("news@acme.com")]))
            .expect("write alice");
        store
            .write_scan_cache(&cached_scan("bob@example.com", vec![sender("news@acme.com")]))
            .expect("write bob");

        store
            .remove_cached_senders("alice@example.com", &["news@acme.com".to_string()])
            .expect("prune");

        assert!(store
            .read_scan_cache("alice@example.com")
            .expect("read")
            .unwrap()
            .senders
            .is_empty());
        assert_eq!(
            emails(&store.read_scan_cache("bob@example.com").expect("read").unwrap()),
            ["news@acme.com"]
        );
    }

    #[test]
    fn removing_every_sender_leaves_a_readable_empty_cache() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(CACHE_DB_FILE);
        let store = SqliteCacheStore::open(&path).expect("open");
        store
            .write_scan_cache(&cached_scan(
                "user@example.com",
                vec![sender("a@acme.com"), sender("b@acme.com")],
            ))
            .expect("write");

        store
            .remove_cached_senders(
                "user@example.com",
                &["a@acme.com".to_string(), "b@acme.com".to_string()],
            )
            .expect("prune");

        let read = store
            .read_scan_cache("user@example.com")
            .expect("read must still succeed")
            .expect("the scan itself is still cached");
        assert!(read.senders.is_empty());
        assert_eq!(read.meta.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(row_count(&path, "scan_senders"), 0);
        assert_eq!(row_count(&path, "scan_messages"), 0);
        assert_eq!(row_count(&path, "scan_unsubscribe_targets"), 0);
    }

    // -----------------------------------------------------------------------
    // Legacy JSON cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn opening_removes_legacy_json_caches_and_spares_everything_else() {
        let dir = TempDir::new().expect("temp dir");
        let legacy = [
            "scan_cache_user@example.com.json",
            "scan_cache_.json",
            "scan_cache_other.json",
        ];
        let spared = [
            "warnings.log",
            "history.db",
            "scan_cache_user@example.com.json.bak",
            "my_scan_cache_user.json",
            "config.toml",
        ];
        for name in legacy.iter().chain(spared.iter()) {
            std::fs::write(dir.path().join(name), b"x").expect("seed file");
        }

        let _store = SqliteCacheStore::open(dir.path().join(CACHE_DB_FILE)).expect("open");

        for name in legacy {
            assert!(
                !dir.path().join(name).exists(),
                "{name} should have been removed"
            );
        }
        for name in spared {
            assert!(dir.path().join(name).exists(), "{name} should be untouched");
        }
    }

    #[test]
    fn opening_an_empty_data_directory_removes_nothing_and_still_works() {
        let dir = TempDir::new().expect("temp dir");
        let store = SqliteCacheStore::open(dir.path().join(CACHE_DB_FILE)).expect("open");
        assert!(store.read_scan_cache("user@example.com").expect("read").is_none());
    }
}
