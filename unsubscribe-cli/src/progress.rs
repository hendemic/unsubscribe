use std::collections::HashMap;
use std::sync::Mutex;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use unsubscribe_core::{Folder, ScanProgress};

/// CLI scan progress using indicatif multi-progress bars.
///
/// Displays one progress bar per folder, matching the legacy UX:
/// folder name as prefix, position/length display, cyan bar styling.
pub struct CliScanProgress {
    mp: MultiProgress,
    style: ProgressStyle,
    bars: Mutex<HashMap<String, ProgressBar>>,
}

impl CliScanProgress {
    pub fn new() -> Self {
        let style = ProgressStyle::default_bar()
            .template(" \x1b[1m{prefix:<12}\x1b[0m [{bar:30.cyan/dim}] \x1b[36m{pos}\x1b[0m/{len}")
            .expect("valid progress bar template")
            .progress_chars("=> ");

        Self {
            mp: MultiProgress::new(),
            style,
            bars: Mutex::new(HashMap::new()),
        }
    }
}

impl ScanProgress for CliScanProgress {
    fn on_folder_start(&self, folder: &Folder, total_messages: u32) {
        let pb = self.mp.add(ProgressBar::new(total_messages as u64));
        pb.set_style(self.style.clone());
        pb.set_prefix(folder.as_str().to_string());

        let mut bars = self.bars.lock().expect("progress bar lock poisoned");
        bars.insert(folder.as_str().to_string(), pb);
    }

    fn on_messages_scanned(&self, folder: &Folder, count: u32) {
        let bars = self.bars.lock().expect("progress bar lock poisoned");
        if let Some(pb) = bars.get(folder.as_str()) {
            pb.inc(count as u64);
        }
    }

    fn on_folder_done(&self, folder: &Folder) {
        let bars = self.bars.lock().expect("progress bar lock poisoned");
        if let Some(pb) = bars.get(folder.as_str()) {
            pb.finish();
        }
    }
}
