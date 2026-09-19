use anyhow::{Context, Result};
use std::path::PathBuf;

use unsubscribe_core::DataStore;

/// File-backed `DataStore` using XDG data directory.
///
/// Preserves existing file locations and formats for backward compatibility:
/// - `warnings.log` -- one warning per line
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
}
