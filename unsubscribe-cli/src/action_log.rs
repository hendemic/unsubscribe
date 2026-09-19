//! Writer for the `run` command's per-sender action log (a disposable CSV
//! debugging aid, distinct from the app's persistent unsubscribe history).

use anyhow::{Context, Result};
use std::path::Path;
use unsubscribe_core::UnsubscribeResult;

/// Append a single result row to the action log CSV.
pub fn append_log_entry(result: &UnsubscribeResult, path: &Path) -> Result<()> {
    let is_new = !path.exists();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open action log: {}", path.display()))?;
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(file);
    if is_new {
        wtr.write_record(["email", "method", "success", "detail", "url"])?;
    }
    wtr.write_record([
        &result.email,
        &result.method,
        &result.success.to_string(),
        &result.detail,
        &result.url,
    ])?;
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_log(results: &[UnsubscribeResult], path: &Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["email", "method", "success", "detail", "url"])?;
    for r in results {
        wtr.write_record([&r.email, &r.method, &r.success.to_string(), &r.detail, &r.url])?;
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(email: &str, method: &str, success: bool, detail: &str, url: &str) -> UnsubscribeResult {
        UnsubscribeResult {
            email: email.to_string(),
            method: method.to_string(),
            success,
            detail: detail.to_string(),
            url: url.to_string(),
        }
    }

    #[test]
    fn write_log_produces_correct_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        write_log(&[], &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert_eq!(first_line, "email,method,success,detail,url");
    }

    #[test]
    fn write_log_empty_results_only_writes_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        write_log(&[], &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "only the header row should be present");
    }

    #[test]
    fn write_log_round_trips_with_csv_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        let results = vec![
            make_result("user@example.com", "one-click POST", true, "HTTP 200", "https://example.com/unsub"),
            make_result("other@lists.io", "GET", false, "HTTP 404", "https://lists.io/unsub"),
        ];

        write_log(&results, &path).unwrap();

        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let records: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();

        assert_eq!(records.len(), 2);
        assert_eq!(&records[0][0], "user@example.com");
        assert_eq!(&records[0][1], "one-click POST");
        assert_eq!(&records[0][2], "true");
        assert_eq!(&records[0][3], "HTTP 200");
        assert_eq!(&records[0][4], "https://example.com/unsub");
        assert_eq!(&records[1][0], "other@lists.io");
        assert_eq!(&records[1][2], "false");
    }

    #[test]
    fn write_log_escapes_commas_in_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        // A detail string containing a comma must be quoted in the CSV output
        let results = vec![make_result(
            "user@example.com",
            "GET",
            true,
            "redirect, then confirmed",
            "https://example.com/unsub",
        )];

        write_log(&results, &path).unwrap();

        // Round-trip via CSV reader — the field must survive intact
        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let record = rdr.records().next().unwrap().unwrap();
        assert_eq!(&record[3], "redirect, then confirmed");
    }

    #[test]
    fn write_log_escapes_quotes_in_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.csv");

        let results = vec![make_result(
            "user@example.com",
            "GET",
            false,
            r#"Error: "connection refused""#,
            "https://example.com/unsub",
        )];

        write_log(&results, &path).unwrap();

        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let record = rdr.records().next().unwrap().unwrap();
        assert_eq!(&record[3], r#"Error: "connection refused""#);
    }
}
