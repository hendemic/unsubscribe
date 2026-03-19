use anyhow::{Context, Result};
use std::path::PathBuf;

use unsubscribe_core::{CachedScan, DataStore, UnsubscribeResult};

/// File-backed `DataStore` using XDG data directory.
///
/// Preserves existing file locations and formats for backward compatibility:
/// - `warnings.log` -- one warning per line
/// - `unsubscribe_log.csv` -- CSV with email, method, success, detail, url
/// - `scan_cache_{account}.json` -- JSON-serialized `CachedScan`
pub struct FileDataStore {
    data_dir: PathBuf,
}

impl FileDataStore {
    pub fn new() -> Self {
        Self {
            data_dir: xdg_data_dir(),
        }
    }

    /// The data directory path, for display in uninstall messages.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir).with_context(|| {
            format!(
                "Failed to create data directory: {}",
                self.data_dir.display()
            )
        })
    }

    fn warnings_path(&self) -> PathBuf {
        self.data_dir.join("warnings.log")
    }

    fn action_log_path(&self) -> PathBuf {
        self.data_dir.join("unsubscribe_log.csv")
    }

    fn cache_path(&self, account: &str) -> PathBuf {
        let safe_account: String = account
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.data_dir.join(format!("scan_cache_{safe_account}.json"))
    }
}

impl DataStore for FileDataStore {
    fn write_warnings(&self, warnings: &[String]) -> Result<()> {
        if warnings.is_empty() {
            return Ok(());
        }
        self.ensure_dir()?;
        std::fs::write(self.warnings_path(), warnings.join("\n") + "\n")
            .context("Failed to write warnings log")
    }

    fn read_warnings(&self) -> Result<Vec<String>> {
        let path = self.warnings_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) if !contents.trim().is_empty() => {
                Ok(contents.lines().map(String::from).collect())
            }
            Ok(_) => Ok(Vec::new()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).context("Failed to read warnings log"),
        }
    }

    fn write_action_log(&self, results: &[UnsubscribeResult]) -> Result<()> {
        self.ensure_dir()?;
        let path = self.action_log_path();
        let mut wtr =
            csv::Writer::from_path(&path).context("Failed to create action log CSV")?;
        wtr.write_record(["email", "method", "success", "detail", "url"])?;
        for r in results {
            wtr.write_record([
                &r.email,
                &r.method,
                &r.success.to_string(),
                &r.detail,
                &r.url,
            ])?;
        }
        wtr.flush()?;
        Ok(())
    }

    fn write_scan_cache(&self, cache: &CachedScan) -> Result<()> {
        self.ensure_dir()?;
        let path = self.cache_path(&cache.meta.account);
        let json =
            serde_json::to_string_pretty(cache).context("Failed to serialize scan cache")?;
        std::fs::write(&path, json).context("Failed to write scan cache")
    }

    fn read_scan_cache(&self, account: &str) -> Result<Option<CachedScan>> {
        let path = self.cache_path(account);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let cache: CachedScan =
                    serde_json::from_str(&contents).context("Failed to parse scan cache")?;
                if cache.meta.account != account {
                    return Ok(None);
                }
                Ok(Some(cache))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("Failed to read scan cache"),
        }
    }
}

fn xdg_data_dir() -> PathBuf {
    let dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
            home.push(".local/share");
            home
        });
    dir.join("email-unsubscribe")
}
