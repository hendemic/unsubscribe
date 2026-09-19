use anyhow::{Context, Result};
use std::path::PathBuf;

use unsubscribe_core::{CachedScan, DataStore};

/// File-backed `DataStore` using XDG data directory.
///
/// Preserves existing file locations and formats for backward compatibility:
/// - `warnings.log` -- one warning per line
/// - `scan_cache_{account}.json` -- JSON-serialized `CachedScan`
pub struct FileDataStore {
    data_dir: PathBuf,
}

impl FileDataStore {
    pub fn new() -> Self {
        Self {
            data_dir: crate::data_dir(),
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
