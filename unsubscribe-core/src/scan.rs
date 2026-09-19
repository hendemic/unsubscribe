//! Policy for deciding whether a run uses the cached scan or rescans.
//!
//! Kept here, pure and UI-free, so the TUI, a headless server and a future iOS
//! client all answer the question the same way. Nothing in here prompts, reads
//! a cache, or touches a terminal: the caller supplies what it found and acts
//! on the answer.

/// What the caller found in the scan cache, after applying its own filters.
///
/// Absent entirely (`None` in [`decide_scan_action`]) covers every unusable
/// case -- no cache, an unreadable one, a different account, or one whose
/// senders have all been pruned by previous runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedScanSummary {
    /// Senders the cache would offer, after the caller's `min_emails` filter.
    pub sender_count: usize,
    /// How old the cached scan is, in seconds. `None` when its timestamp could
    /// not be parsed, which is treated as old rather than fresh.
    pub age_secs: Option<u64>,
}

impl CachedScanSummary {
    /// Whether the scan is older than `max_age_secs` (or of unknown age).
    #[must_use]
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        self.age_secs.is_none_or(|age| age > max_age_secs)
    }
}

/// What a `run` or `export` invocation should do about the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAction {
    /// Use the cached scan without asking.
    UseCache,
    /// Scan the mailbox.
    Rescan,
    /// Ask, then use the cache or rescan. `default_cached` is what Enter means.
    Ask { default_cached: bool },
    /// The caller demanded the cache but there is nothing usable in it.
    CacheUnavailable,
}

/// Decide what to do with the cache.
///
/// `cache` is `None` whenever the cache is unusable, and an unusable cache
/// simply scans -- silently, because there is nothing to ask about. Explicit
/// flags always win over the prompt, and a non-interactive caller is never
/// asked: it takes the cache if there is one. Otherwise the user chooses, with
/// a fresh cache defaulting to reuse and a stale one defaulting to a rescan.
#[must_use]
pub fn decide_scan_action(
    cache: Option<CachedScanSummary>,
    force_cached: bool,
    force_rescan: bool,
    interactive: bool,
    max_age_secs: u64,
) -> ScanAction {
    if force_rescan {
        return ScanAction::Rescan;
    }
    if force_cached {
        return match cache {
            Some(_) => ScanAction::UseCache,
            None => ScanAction::CacheUnavailable,
        };
    }
    match cache {
        None => ScanAction::Rescan,
        Some(_) if !interactive => ScanAction::UseCache,
        Some(summary) => ScanAction::Ask {
            default_cached: !summary.is_stale(max_age_secs),
        },
    }
}
