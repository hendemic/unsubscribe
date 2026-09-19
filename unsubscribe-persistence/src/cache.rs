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
