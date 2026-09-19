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

#[cfg(test)]
mod tests {
    use super::*;

    /// A week, in seconds -- the default `cache_max_age_days` of 7.
    const WEEK: u64 = 7 * 24 * 3600;

    /// A usable cache of the given age.
    fn cache(age_secs: u64) -> Option<CachedScanSummary> {
        Some(CachedScanSummary {
            sender_count: 12,
            age_secs: Some(age_secs),
        })
    }

    /// A usable cache whose timestamp would not parse.
    fn undated_cache() -> Option<CachedScanSummary> {
        Some(CachedScanSummary {
            sender_count: 12,
            age_secs: None,
        })
    }

    // -----------------------------------------------------------------------
    // is_stale
    // -----------------------------------------------------------------------

    #[test]
    fn a_scan_exactly_at_the_limit_is_still_fresh() {
        let summary = CachedScanSummary {
            sender_count: 1,
            age_secs: Some(WEEK),
        };
        assert!(!summary.is_stale(WEEK));
    }

    #[test]
    fn a_scan_one_second_past_the_limit_is_stale() {
        let summary = CachedScanSummary {
            sender_count: 1,
            age_secs: Some(WEEK + 1),
        };
        assert!(summary.is_stale(WEEK));
    }

    #[test]
    fn a_scan_of_unknown_age_is_treated_as_stale() {
        let summary = CachedScanSummary {
            sender_count: 1,
            age_secs: None,
        };
        assert!(summary.is_stale(WEEK));
    }

    // -----------------------------------------------------------------------
    // No usable cache
    // -----------------------------------------------------------------------

    #[test]
    fn no_cache_and_no_flags_rescans_without_asking() {
        assert_eq!(
            decide_scan_action(None, false, false, true, WEEK),
            ScanAction::Rescan
        );
        assert_eq!(
            decide_scan_action(None, false, false, false, WEEK),
            ScanAction::Rescan
        );
    }

    #[test]
    fn demanding_the_cache_when_there_is_none_is_reported() {
        assert_eq!(
            decide_scan_action(None, true, false, true, WEEK),
            ScanAction::CacheUnavailable
        );
        assert_eq!(
            decide_scan_action(None, true, false, false, WEEK),
            ScanAction::CacheUnavailable
        );
    }

    // -----------------------------------------------------------------------
    // Explicit flags
    // -----------------------------------------------------------------------

    #[test]
    fn rescan_flag_scans_whatever_the_cache_holds() {
        for state in [None, cache(0), cache(WEEK * 10), undated_cache()] {
            for interactive in [true, false] {
                assert_eq!(
                    decide_scan_action(state, false, true, interactive, WEEK),
                    ScanAction::Rescan,
                    "--rescan must scan regardless of cache state or TTY"
                );
            }
        }
    }

    #[test]
    fn rescan_flag_wins_over_the_cached_flag() {
        // clap rejects the pair, but the policy has to be unambiguous anyway.
        assert_eq!(
            decide_scan_action(cache(0), true, true, true, WEEK),
            ScanAction::Rescan
        );
    }

    #[test]
    fn cached_flag_uses_even_a_long_stale_cache() {
        assert_eq!(
            decide_scan_action(cache(WEEK * 52), true, false, true, WEEK),
            ScanAction::UseCache
        );
        assert_eq!(
            decide_scan_action(undated_cache(), true, false, true, WEEK),
            ScanAction::UseCache
        );
    }

    // -----------------------------------------------------------------------
    // Non-interactive callers are never asked
    // -----------------------------------------------------------------------

    #[test]
    fn without_a_tty_any_cache_is_used_rather_than_prompted_for() {
        for state in [cache(0), cache(WEEK * 10), undated_cache()] {
            assert_eq!(
                decide_scan_action(state, false, false, false, WEEK),
                ScanAction::UseCache
            );
        }
    }

    // -----------------------------------------------------------------------
    // Interactive prompt defaults
    // -----------------------------------------------------------------------

    #[test]
    fn a_fresh_cache_offers_the_prompt_defaulting_to_reuse() {
        assert_eq!(
            decide_scan_action(cache(3600), false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: true
            }
        );
    }

    #[test]
    fn a_cache_exactly_at_the_limit_still_defaults_to_reuse() {
        assert_eq!(
            decide_scan_action(cache(WEEK), false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: true
            }
        );
    }

    #[test]
    fn a_cache_one_second_past_the_limit_defaults_to_rescan() {
        assert_eq!(
            decide_scan_action(cache(WEEK + 1), false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: false
            }
        );
    }

    #[test]
    fn a_cache_of_unknown_age_defaults_to_rescan() {
        assert_eq!(
            decide_scan_action(undated_cache(), false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: false
            }
        );
    }

    #[test]
    fn the_freshness_window_comes_from_the_argument_not_a_constant() {
        // The same two-day-old cache is fresh under a 7-day window and stale
        // under a 1-day one, so the preference really does drive the default.
        let two_days = 2 * 24 * 3600;
        assert_eq!(
            decide_scan_action(cache(two_days), false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: true
            }
        );
        assert_eq!(
            decide_scan_action(cache(two_days), false, false, true, 24 * 3600),
            ScanAction::Ask {
                default_cached: false
            }
        );
    }

    #[test]
    fn sender_count_does_not_affect_the_decision() {
        // Emptiness is the caller's business: it passes `None` for a cache
        // with nothing left to offer, so a count of zero here still asks.
        let empty = Some(CachedScanSummary {
            sender_count: 0,
            age_secs: Some(0),
        });
        assert_eq!(
            decide_scan_action(empty, false, false, true, WEEK),
            ScanAction::Ask {
                default_cached: true
            }
        );
    }
}
