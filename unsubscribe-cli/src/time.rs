//! Time helpers shared by commands and the TUI: staleness checks and the
//! minimal ISO 8601 (UTC, `YYYY-MM-DDThh:mm:ssZ`) formatting/parsing used for
//! scan timestamps.

use unsubscribe_core::SenderInfo;

/// A sender is considered stale if their most recent message is older than 12 months.
const STALE_THRESHOLD_SECS: i64 = 365 * 24 * 60 * 60;

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
