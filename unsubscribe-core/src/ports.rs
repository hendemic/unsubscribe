use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::history::{Resumption, UnsubscribeAttempt};
use crate::types::{
    AccountConfig, Credential, Folder, FolderMessage, HttpResponse, Preferences, ScanResult,
    ScanWatermark, SenderInfo,
};

/// Port for scan progress reporting.
///
/// Consumers implement this to display progress during scanning (progress bars,
/// status updates, etc.). The trait requires `Send + Sync` because adapters like
/// IMAP may call it from multiple threads concurrently.
pub trait ScanProgress: Send + Sync {
    /// Called when a folder scan begins, after the folder is selected.
    fn on_folder_start(&self, folder: &Folder, total_messages: u32);

    /// Called after each batch of messages is scanned within a folder.
    fn on_messages_scanned(&self, folder: &Folder, count: u32);

    /// Called when a folder scan is complete.
    fn on_folder_done(&self, folder: &Folder);

    /// Running totals once another folder's results have been merged in.
    ///
    /// Senders are deduplicated across folders, so only the adapter can say
    /// how many *distinct* senders have been found so far; it reports the
    /// figure whenever it changes. Consumers that show no live tally ignore
    /// it, which is the default.
    fn on_totals(&self, _senders: u32, _warnings: u32) {}

    /// Whether the consumer has asked the scan to stop.
    ///
    /// Adapters poll this between batches -- never mid-fetch -- and return
    /// whatever they have; [`crate::pipeline::scan_senders`] then discards it
    /// and leaves the existing cache alone, so a cancelled scan costs nothing
    /// but the time it ran for. Cancelling is a consumer's choice, so the
    /// default is never, and an adapter that cannot poll is still correct.
    fn should_cancel(&self) -> bool {
        false
    }
}

/// No-op implementation for consumers that don't need progress reporting.
pub struct NoopProgress;

impl ScanProgress for NoopProgress {
    fn on_folder_start(&self, _folder: &Folder, _total_messages: u32) {}
    fn on_messages_scanned(&self, _folder: &Folder, _count: u32) {}
    fn on_folder_done(&self, _folder: &Folder) {}
}

/// Port for email providers (IMAP, Gmail API, Exchange, Apple Accounts, etc.).
///
/// Adapters implement this trait to let core scan mailboxes and archive messages.
/// All methods are synchronous -- adapters own their own concurrency internally.
pub trait EmailProvider {
    /// Scan the given folders for senders with List-Unsubscribe headers.
    fn scan(&self, folders: &[Folder], progress: &dyn ScanProgress) -> Result<ScanResult>;

    /// Move the given messages to the specified destination folder.
    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32>;
}

/// Port for HTTP operations needed during unsubscribe flows and API access.
///
/// CLI provides this via reqwest, iOS via URLSession, tests via mocks.
///
/// URLs passed here come from attacker-controlled email headers and are
/// fetched unattended (no human watching the result), so every adapter
/// must guard against SSRF: refuse loopback/private/link-local/other
/// non-public addresses, checked against the address actually connected
/// to (not just the hostname string) and re-checked on every redirect
/// hop. The CLI's `ReqwestHttpClient` (`unsubscribe-cli/src/http.rs`) is
/// the reference implementation; a future iOS `URLSession` adapter needs
/// the equivalent, most likely via a custom `URLProtocol` or
/// `NWConnection`-based address filtering, since `URLSession` has no
/// pluggable DNS resolver hook.
pub trait HttpClient {
    /// Perform an HTTP GET request.
    fn get(&self, url: &str) -> Result<HttpResponse>;

    /// Perform an HTTP GET request with additional request headers.
    fn get_with_headers(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;

    /// Perform an HTTP POST with form-encoded key-value pairs.
    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<HttpResponse>;

    /// Perform an HTTP POST with the given content-type and raw body.
    fn post_body(&self, url: &str, content_type: &str, body: &str) -> Result<HttpResponse>;

    /// Perform an HTTP POST with the given content-type, raw body, and additional request headers.
    fn post_body_with_headers(
        &self,
        url: &str,
        content_type: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse>;
}

/// Port for sending emails on behalf of the user.
///
/// Used for mailto-based unsubscribe flows where the unsubscribe mechanism
/// requires sending an email rather than visiting a URL. Adapters implement
/// this trait separately from `EmailProvider` because sending is a distinct
/// concern from scanning/archiving.
///
/// Gmail provides this via `users.messages.send`. IMAP users provide this
/// via SMTP. The trait is optional in the unsubscribe flow -- when absent,
/// mailto-only senders are skipped as before.
pub trait EmailSender {
    /// Send an email with the given recipient, subject, and body.
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<()>;
}

/// Port for reading and writing account configuration.
///
/// CLI implements this with TOML files. iOS will use CoreData/SwiftData.
/// The persistence crate (`unsubscribe-persistence`) provides the CLI implementation.
pub trait ConfigStore {
    /// Read the configuration for an account, or None if it doesn't exist.
    fn read_config(&self, account_id: &str) -> Result<Option<AccountConfig>>;

    /// Write (create or update) the configuration for an account.
    fn write_config(&self, config: &AccountConfig) -> Result<()>;

    /// Read the user's behavior preferences.
    ///
    /// Implementations return `Preferences::default()` when nothing is stored,
    /// and an error when stored values are present but unusable -- a bad value
    /// should never degrade silently into a default.
    fn read_preferences(&self) -> Result<Preferences>;

    /// Write (create or update) the user's behavior preferences.
    fn write_preferences(&self, preferences: &Preferences) -> Result<()>;
}

/// Port for storing, retrieving, and deleting credentials.
///
/// CLI implements this with the OS keychain. iOS will use Keychain Services.
/// The persistence crate (`unsubscribe-persistence`) provides the CLI implementation.
pub trait CredentialStore {
    /// Store a credential for the given account.
    fn store_credential(&self, account_id: &str, credential: &Credential) -> Result<()>;

    /// Retrieve the credential for the given account, or None if not stored.
    fn get_credential(&self, account_id: &str) -> Result<Option<Credential>>;

    /// Delete the credential for the given account. No-op if not stored.
    fn delete_credential(&self, account_id: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// HistoryStore: durable record of unsubscribe attempts
// ---------------------------------------------------------------------------

/// Port for the append-only unsubscribe history.
///
/// Deliberately separate from `DataStore`: a server or an iOS client wants the
/// history without the file-oriented warnings and scan-cache methods, and the
/// two have opposite durability guarantees -- the cache is disposable, the
/// history is not. The methods are coarse enough that an HTTP-backed
/// implementation could sit behind this trait later.
pub trait HistoryStore {
    /// Append one attempt. Implementations never update or delete.
    fn record_attempt(&self, attempt: &UnsubscribeAttempt) -> Result<()>;

    /// All attempts recorded for an account, oldest first.
    fn attempts_for_account(&self, account: &str) -> Result<Vec<UnsubscribeAttempt>>;

    /// Append one observed resumption. Append-only, like attempts.
    ///
    /// At most one resumption exists per ignored attempt; implementations
    /// enforce that, and callers are expected not to offer a duplicate.
    fn record_resumption(&self, resumption: &Resumption) -> Result<()>;

    /// All resumptions recorded for an account, oldest first.
    fn resumptions_for_account(&self, account: &str) -> Result<Vec<Resumption>>;
}

// ---------------------------------------------------------------------------
// DataStore: scan warnings, action logs, and cached scan results
// ---------------------------------------------------------------------------

/// Metadata about a cached scan (persistence-layer concern, not a domain type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    /// ISO 8601 timestamp of when the scan was performed
    pub scanned_at: String,
    /// Cache format version for future migration support
    pub format_version: u32,
    /// Account identifier to prevent cross-account stale reads
    pub account: String,
}

/// Cached scan data: results + metadata + watermark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    pub meta: CacheMeta,
    pub senders: Vec<SenderInfo>,
    pub watermark: ScanWatermark,
}

/// Port for persisting scan warnings.
///
/// CLI implements this with XDG data dir files. iOS would use CoreData/SwiftData.
/// The persistence crate (`unsubscribe-persistence`) provides the CLI implementation.
pub trait DataStore {
    /// Persist scan warnings, replacing any previous warnings.
    fn write_warnings(&self, warnings: &[String]) -> Result<()>;

    /// Read previously persisted scan warnings.
    fn read_warnings(&self) -> Result<Vec<String>>;
}

/// Port for the scan cache.
///
/// Separate from both `DataStore` and `HistoryStore`: the cache is disposable
/// -- discarding it costs a rescan and nothing else -- while warnings are
/// display state and the history is evidence that must never be lost.
pub trait ScanCacheStore {
    /// Read cached scan results for the given account, if any exist.
    fn read_scan_cache(&self, account: &str) -> Result<Option<CachedScan>>;

    /// Replace the cached scan for the account the cache names.
    fn write_scan_cache(&self, cache: &CachedScan) -> Result<()>;

    /// Drop the named senders from an account's cache, leaving the scan
    /// timestamp and watermarks alone.
    ///
    /// Called after a run archives a sender's messages: those messages have
    /// moved, so leaving the sender cached would offer stale message ids and
    /// make a sender that was just handled look like it reappeared. Unknown
    /// senders are ignored; matching is case-insensitive.
    fn remove_cached_senders(&self, account: &str, sender_emails: &[String]) -> Result<()>;
}

#[cfg(test)]
mod cached_scan_compat_tests {
    use super::*;

    /// A cached scan as the file-based cache wrote it before `list_id` and
    /// `list_unsubscribe_raw` were added to `SenderInfo`.
    ///
    /// Typed out rather than produced by serializing today's struct: the point
    /// is that a document written by an older build still loads.
    const PRE_LIST_ID_CACHE: &str = r#"{
        "meta": {
            "scanned_at": "2026-03-18T19:30:00Z",
            "format_version": 1,
            "account": "user@example.com"
        },
        "senders": [
            {
                "display_name": "Acme Newsletter",
                "email": "news@acme.example.com",
                "domain": "acme.example.com",
                "unsubscribe_urls": ["https://acme.example.com/unsub"],
                "unsubscribe_mailto": ["mailto:unsub@acme.example.com"],
                "one_click": true,
                "email_count": 7,
                "messages": [{"folder": "INBOX", "message_id": "INBOX:42:1"}],
                "last_seen": null
            }
        ],
        "watermark": {
            "highest_uid": {"INBOX": 42},
            "uid_validity": {"INBOX": 1},
            "adapter_state": null
        }
    }"#;

    #[test]
    fn cache_written_before_list_id_existed_still_deserializes() {
        let cache: CachedScan =
            serde_json::from_str(PRE_LIST_ID_CACHE).expect("old cache shape must still load");

        assert_eq!(cache.meta.account, "user@example.com");
        assert_eq!(cache.meta.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(cache.senders.len(), 1);

        let sender = &cache.senders[0];
        assert_eq!(sender.email, "news@acme.example.com");
        assert_eq!(sender.unsubscribe_urls, ["https://acme.example.com/unsub"]);
        assert_eq!(sender.last_seen, None);
        assert_eq!(sender.list_id, None);
        assert_eq!(sender.list_unsubscribe_raw, None);

        assert_eq!(cache.watermark.highest_uid.get("INBOX"), Some(&42));
        assert_eq!(cache.watermark.uid_validity.get("INBOX"), Some(&1));
        assert_eq!(cache.watermark.adapter_state, None);
    }
}

#[cfg(test)]
mod default_port_behaviour_tests {
    use super::*;
    use crate::pipeline::{NoopRunObserver, PlannedSender, RunObserver, RunWarning};
    use crate::types::UnsubscribeResult;
    use std::sync::Mutex;

    /// A progress reporter that implements only the required methods, as a
    /// consumer with no way to cancel would.
    #[derive(Default)]
    struct MinimalProgress {
        totals: Mutex<Vec<(u32, u32)>>,
    }

    impl ScanProgress for MinimalProgress {
        fn on_folder_start(&self, _folder: &Folder, _total_messages: u32) {}
        fn on_messages_scanned(&self, _folder: &Folder, _count: u32) {}
        fn on_folder_done(&self, _folder: &Folder) {}
        fn on_totals(&self, senders: u32, warnings: u32) {
            self.totals.lock().expect("totals").push((senders, warnings));
        }
    }

    /// A reporter with nothing beyond the required methods: no cancel, no
    /// totals, exactly as a consumer with neither would write it.
    struct BareProgress;

    impl ScanProgress for BareProgress {
        fn on_folder_start(&self, _folder: &Folder, _total_messages: u32) {}
        fn on_messages_scanned(&self, _folder: &Folder, _count: u32) {}
        fn on_folder_done(&self, _folder: &Folder) {}
    }

    /// The same for the run side.
    struct MinimalObserver;

    impl RunObserver for MinimalObserver {
        fn on_unsubscribe_start(&self, _sender_count: u32) {}
        fn on_sender_result(&self, _planned: &PlannedSender, _result: &UnsubscribeResult) {}
        fn on_unsubscribe_done(&self, _planned: &[PlannedSender], _results: &[UnsubscribeResult]) {}
        fn on_archive_start(&self, _message_count: u32, _email_count: u32) {}
        fn on_archive_done(&self, _archived: u32) {}
        fn on_warning(&self, _warning: &RunWarning) {}
    }

    #[test]
    fn a_progress_reporter_that_says_nothing_about_cancelling_never_cancels() {
        assert!(!BareProgress.should_cancel());
        assert!(!NoopProgress.should_cancel());
    }

    #[test]
    fn a_run_observer_that_says_nothing_about_cancelling_never_cancels() {
        assert!(!MinimalObserver.should_cancel());
        assert!(!NoopRunObserver.should_cancel());
    }

    #[test]
    fn a_consumer_that_wants_totals_gets_them_through_the_port() {
        // The default is a no-op, so the only way to tell the override is
        // wired up is to make one and call it through the trait object the
        // adapters actually hold.
        let counting = MinimalProgress::default();
        let reporter: &dyn ScanProgress = &counting;

        reporter.on_totals(12, 3);
        reporter.on_totals(40, 5);

        assert_eq!(counting.totals.lock().expect("totals").as_slice(), [(12, 3), (40, 5)]);
    }

    #[test]
    fn the_default_on_totals_is_a_no_op_an_adapter_can_always_call() {
        let silent: &dyn ScanProgress = &NoopProgress;

        // Would panic or fail to compile if the default were not provided.
        silent.on_totals(7, 1);
    }
}
