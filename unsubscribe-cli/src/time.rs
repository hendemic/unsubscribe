//! Time helpers shared by commands and the TUI: staleness checks, local-time
//! display, and the minimal ISO 8601 (UTC, `YYYY-MM-DDThh:mm:ssZ`)
//! formatting/parsing used for scan timestamps.

use unsubscribe_core::SenderInfo;

/// A sender is considered stale if their most recent message is older than 12 months.
const STALE_THRESHOLD_SECS: i64 = 365 * 24 * 60 * 60;

/// How old a cached scan may be before we stop treating it as current.
///
/// One value, two uses: the TUI paints the scan timestamp red past it, and the
/// run/export prompt flips its default from "use cached" to "rescan".
pub const SCAN_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Month abbreviations for the hand-rolled date formatting below.
pub const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Current time in Unix seconds (UTC), or 0 if the clock is before the epoch.
pub fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn is_stale(sender: &SenderInfo) -> bool {
    let now = now_unix_secs();
    match sender.last_seen {
        Some(ts) => now - ts > STALE_THRESHOLD_SECS,
        None => false,
    }
}

pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs as i64 / 86400;
    let time_of_day = secs as i64 % 86400;
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
