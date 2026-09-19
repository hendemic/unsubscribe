//! Time helpers shared by commands and the TUI: staleness checks, local-time
//! display, and the minimal ISO 8601 (UTC, `YYYY-MM-DDThh:mm:ssZ`)
//! formatting/parsing used for scan timestamps.

use unsubscribe_core::SenderInfo;

/// Month abbreviations for the hand-rolled date formatting below.
pub const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub use unsubscribe_core::now_unix_secs;

/// A sender is stale when their most recent message predates the configured
/// threshold, judged against the clock right now.
///
/// The rule itself lives in core so the pipeline and the screens agree; this
/// only supplies "now" for the display paths that have no run to take it from.
pub fn is_stale(sender: &SenderInfo, stale_after_months: u32) -> bool {
    unsubscribe_core::is_stale(sender, stale_after_months, now_unix_secs())
}

/// The configured cached-scan freshness window, in seconds.
///
/// One value, two uses: the TUI paints the scan timestamp red past it, and the
/// run/export prompt flips its default from "use cached" to "rescan".
pub fn scan_max_age_secs(cache_max_age_days: u32) -> u64 {
    u64::from(cache_max_age_days) * 24 * 3600
}

/// Whether a cached scan has aged past the configured freshness window.
///
/// An unparseable timestamp is treated as fresh: a display quirk is preferable
/// to nagging the user about a scan we cannot date.
pub fn is_scan_stale(timestamp: &str, cache_max_age_days: u32) -> bool {
    age_secs_since(timestamp).is_some_and(|age| age > scan_max_age_secs(cache_max_age_days))
}

pub fn now_iso8601() -> String {
    let secs = now_unix_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_civil(days + 719468);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert day count to civil date (algorithm from Howard Hinnant).
fn days_to_civil(day_count: i64) -> (i64, u32, u32) {
    let era = if day_count >= 0 {
        day_count
    } else {
        day_count - 146096
    } / 146097;
    let doe = (day_count - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parse an ISO 8601 timestamp (e.g., "2026-03-18T19:30:00Z") into Unix seconds.
pub fn parse_iso8601_age_secs(ts: &str) -> Option<u64> {
    // Minimal parser for the format produced by now_iso8601(): YYYY-MM-DDThh:mm:ssZ
    let b = ts.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let year: i64 = ts.get(0..4)?.parse().ok()?;
    let month: u32 = ts.get(5..7)?.parse().ok()?;
    let day: u32 = ts.get(8..10)?.parse().ok()?;
    let hour: u64 = ts.get(11..13)?.parse().ok()?;
    let min: u64 = ts.get(14..16)?.parse().ok()?;
    let sec: u64 = ts.get(17..19)?.parse().ok()?;

    // Convert civil date to days since epoch (inverse of days_to_civil)
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let day_count = era * 146097 + doe as i64 - 719468;

    Some(day_count as u64 * 86400 + hour * 3600 + min * 60 + sec)
}

/// Age of an ISO 8601 UTC timestamp in seconds, or `None` if it will not parse.
///
/// A timestamp in the future ages to zero rather than wrapping.
pub fn age_secs_since(ts: &str) -> Option<u64> {
    let then = parse_iso8601_age_secs(ts)?;
    Some((now_unix_secs() as u64).saturating_sub(then))
}

/// Render an age as the coarse phrase a person would use out loud.
pub fn format_relative_age(age_secs: u64) -> String {
    const HOUR: u64 = 3600;
    const DAY: u64 = 24 * HOUR;

    match age_secs {
        secs if secs < HOUR => "just now".to_string(),
        secs if secs < 2 * HOUR => "1 hour ago".to_string(),
        secs if secs < DAY => format!("{} hours ago", secs / HOUR),
        secs if secs < 2 * DAY => "1 day ago".to_string(),
        secs => format!("{} days ago", secs / DAY),
    }
}

/// Convert a UTC ISO 8601 timestamp to local time as "Mon DD, YYYY hh:mm".
pub fn utc_to_local_display(utc_ts: &str) -> Option<String> {
    let tm = local_time(utc_ts)?;
    let month_name = MONTH_NAMES.get(tm.tm_mon as usize)?;
    Some(format!(
        "{} {:02}, {} {:02}:{:02}",
        month_name,
        tm.tm_mday,
        1900 + tm.tm_year,
        tm.tm_hour,
        tm.tm_min,
    ))
}

/// Convert a UTC ISO 8601 timestamp to a local calendar date, "Mon DD, YYYY".
pub fn utc_to_local_date(utc_ts: &str) -> Option<String> {
    let tm = local_time(utc_ts)?;
    let month_name = MONTH_NAMES.get(tm.tm_mon as usize)?;
    Some(format!("{} {}, {}", month_name, tm.tm_mday, 1900 + tm.tm_year))
}

/// Break a UTC ISO 8601 timestamp into local calendar fields.
fn local_time(utc_ts: &str) -> Option<libc::tm> {
    let unix_secs = parse_iso8601_age_secs(utc_ts)? as i64;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let time_t = unix_secs as libc::time_t;
    // localtime_r fills `tm` from the process timezone; it only fails on
    // timestamps the platform cannot represent.
    if unsafe { libc::localtime_r(&time_t, &mut tm) }.is_null() {
        return None;
    }
    Some(tm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A twelfth of a 365-day year, worked out by hand rather than read from
    /// the constant under test: 365 * 86400 / 12.
    const MONTH: i64 = 2_628_000;
    const DAY: i64 = 86_400;

    /// Slack against the clock ticking between building a fixture and reading
    /// it back. Generous next to a month, tight next to nothing.
    const MARGIN: i64 = 3_600;

    fn sender(last_seen: Option<i64>) -> SenderInfo {
        SenderInfo {
            display_name: "Acme Newsletter".to_string(),
            email: "news@acme.example".to_string(),
            domain: "acme.example".to_string(),
            unsubscribe_urls: Vec::new(),
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 1,
            messages: Vec::new(),
            last_seen,
        }
    }

    /// Render a Unix timestamp the way the scan cache stores it.
    ///
    /// Built on the C library's calendar conversion so that expected values do
    /// not come out of the same civil-date arithmetic they are checking.
    fn iso_utc(unix_secs: i64) -> String {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let time_t = unix_secs as libc::time_t;
        assert!(
            !unsafe { libc::gmtime_r(&time_t, &mut tm) }.is_null(),
            "gmtime_r rejected {unix_secs}"
        );
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            1900 + tm.tm_year,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        )
    }

    // ─── timestamp parsing, which staleness rests on ────────────────────────

    #[test]
    fn known_timestamps_parse_to_their_known_unix_values() {
        assert_eq!(parse_iso8601_age_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_age_secs("2000-01-01T00:00:00Z"),
            Some(946_684_800)
        );
        assert_eq!(
            parse_iso8601_age_secs("2001-09-09T01:46:40Z"),
            Some(1_000_000_000)
        );
    }

    #[test]
    fn parsing_agrees_with_the_c_library_across_awkward_dates() {
        // Leap day, the day after a leap day, a century boundary, and a
        // year-end rollover -- the cases a hand-rolled calendar gets wrong.
        for unix_secs in [
            0,
            951_782_400,   // 2000-02-29
            951_868_800,   // 2000-03-01
            1_709_164_800, // 2024-02-29
            1_735_689_599, // 2024-12-31T23:59:59Z
            1_735_689_600, // 2025-01-01T00:00:00Z
        ] {
            let rendered = iso_utc(unix_secs);
            assert_eq!(
                parse_iso8601_age_secs(&rendered),
                Some(unix_secs as u64),
                "round trip failed for {rendered}"
            );
        }
    }

    #[test]
    fn a_timestamp_that_is_not_one_parses_to_nothing() {
        for bad in ["", "yesterday", "2026-03-18", "2026-03-18T19:30", "Z"] {
            assert_eq!(parse_iso8601_age_secs(bad), None, "accepted {bad:?}");
        }
    }

    // ─── is_stale ───────────────────────────────────────────────────────────

    #[test]
    fn a_sender_with_no_date_is_never_stale() {
        // A missing date is the adapter's failure, not the sender's age.
        assert!(!is_stale(&sender(None), 1));
        assert!(!is_stale(&sender(None), 1200));
    }

    #[test]
    fn a_sender_seen_just_now_is_not_stale() {
        assert!(!is_stale(&sender(Some(now_unix_secs())), 1));
    }

    #[test]
    fn a_sender_just_inside_the_threshold_is_not_stale() {
        let last_seen = now_unix_secs() - 12 * MONTH + MARGIN;
        assert!(!is_stale(&sender(Some(last_seen)), 12));
    }

    #[test]
    fn a_sender_just_past_the_threshold_is_stale() {
        let last_seen = now_unix_secs() - 12 * MONTH - MARGIN;
        assert!(is_stale(&sender(Some(last_seen)), 12));
    }

    #[test]
    fn the_same_sender_is_stale_or_not_according_to_the_configured_months() {
        // Seven months old: past a six-month threshold, inside a twelve.
        let last_seen = now_unix_secs() - 7 * MONTH;
        let sender = sender(Some(last_seen));
        assert!(is_stale(&sender, 6), "should be stale at 6 months");
        assert!(!is_stale(&sender, 12), "should not be stale at 12 months");
    }

    #[test]
    fn the_twelve_month_default_is_one_calendar_year() {
        const YEAR: i64 = 365 * DAY;
        let now = now_unix_secs();
        assert!(!is_stale(&sender(Some(now - YEAR + MARGIN)), 12));
        assert!(is_stale(&sender(Some(now - YEAR - MARGIN)), 12));
    }

    #[test]
    fn a_sender_dated_in_the_future_is_not_stale() {
        // Clock skew on the server should not wrap into a huge age.
        let last_seen = now_unix_secs() + 30 * DAY;
        assert!(!is_stale(&sender(Some(last_seen)), 1));
    }

    // ─── scan_max_age_secs ──────────────────────────────────────────────────

    #[test]
    fn the_freshness_window_is_the_configured_days_in_seconds() {
        assert_eq!(scan_max_age_secs(1), 86_400);
        assert_eq!(scan_max_age_secs(7), 604_800);
        assert_eq!(scan_max_age_secs(30), 2_592_000);
    }

    #[test]
    fn a_zero_day_window_is_zero_seconds() {
        assert_eq!(scan_max_age_secs(0), 0);
    }

    // ─── is_scan_stale ──────────────────────────────────────────────────────

    #[test]
    fn a_scan_just_inside_the_window_is_fresh() {
        let ts = iso_utc(now_unix_secs() - 7 * DAY + MARGIN);
        assert!(!is_scan_stale(&ts, 7));
    }

    #[test]
    fn a_scan_just_past_the_window_is_stale() {
        let ts = iso_utc(now_unix_secs() - 7 * DAY - MARGIN);
        assert!(is_scan_stale(&ts, 7));
    }

    #[test]
    fn the_same_scan_is_stale_or_not_according_to_the_configured_days() {
        let ts = iso_utc(now_unix_secs() - 10 * DAY);
        assert!(is_scan_stale(&ts, 7), "should be stale with a 7 day window");
        assert!(!is_scan_stale(&ts, 30), "should be fresh with a 30 day window");
    }

    #[test]
    fn a_scan_from_a_moment_ago_is_fresh() {
        assert!(!is_scan_stale(&iso_utc(now_unix_secs()), 1));
    }

    #[test]
    fn a_very_old_scan_is_stale_even_at_the_longest_window() {
        assert!(is_scan_stale("2000-01-01T00:00:00Z", 3650));
    }

    #[test]
    fn an_unparseable_scan_timestamp_is_treated_as_fresh() {
        // Better a display quirk than nagging about a scan we cannot date.
        for bad in ["", "yesterday", "2026-03-18"] {
            assert!(!is_scan_stale(bad, 7), "{bad:?} should not read as stale");
        }
    }

    #[test]
    fn a_scan_timestamped_in_the_future_is_fresh() {
        let ts = iso_utc(now_unix_secs() + 30 * DAY);
        assert!(!is_scan_stale(&ts, 1));
    }
}
