//! Single-instance lock for runs.
//!
//! Two `run`s against one account race on the archive: both scan, both plan
//! from the same cache, and the second moves messages the first has already
//! moved. A timer that fires while the previous run is still working is the
//! obvious way to get there, so the lock exists for the unattended case first.
//!
//! The lock is one file per account in the data directory holding the owning
//! process id. A lock left behind by a process that no longer exists is cleared
//! rather than blocking every future run -- a crashed run must not need manual
//! cleanup.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::data_dir;

/// Who is holding a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    /// Process id recorded in the lock file, when it could be read.
    pub pid: Option<u32>,
    /// Path of the lock file, so the user can inspect or remove it.
    pub path: PathBuf,
}

/// The result of asking for the lock.
#[derive(Debug)]
pub enum LockOutcome {
    /// The lock is ours until the guard is dropped.
    Acquired(RunLock),
    /// Another live process holds it.
    Held(LockInfo),
}

/// An acquired run lock, released when dropped.
///
/// Release is best-effort: a lock file that cannot be removed is cleared by the
/// next run's liveness check, so a failure here costs nothing.
#[derive(Debug)]
pub struct RunLock {
    path: PathBuf,
}

impl RunLock {
    /// Take the lock for `account` in the default data directory.
    pub fn acquire(account: &str) -> Result<LockOutcome> {
        Self::acquire_in(&data_dir(), account)
    }

    /// Take the lock for `account` in `dir`.
    ///
    /// The directory is an argument so tests -- and a future server with its
    /// own layout -- do not have to move the real one.
    pub fn acquire_in(dir: &Path, account: &str) -> Result<LockOutcome> {
        let path = lock_path(dir, account);
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create data directory: {}", dir.display()))?;

        match try_create(&path) {
            Ok(lock) => Ok(LockOutcome::Acquired(lock)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = read_pid(&path);
                // A lock whose owner is gone is debris from a crash, not a
                // second run. Clearing it is the only way a crashed run does
                // not require the user to know this file exists.
                if pid.is_none_or(|pid| !process_is_alive(pid)) {
                    let _ = fs::remove_file(&path);
                    if let Ok(lock) = try_create(&path) {
                        return Ok(LockOutcome::Acquired(lock));
                    }
                }
                Ok(LockOutcome::Held(LockInfo { pid, path }))
            }
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("Failed to create lock file: {}", path.display()))),
        }
    }

    /// Where this lock lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// The lock file for one account.
///
/// The account id is an email address, so it is reduced to something safe to
/// put in a filename. Two accounts that reduce to the same name would share a
/// lock, which costs a wait rather than a corrupted archive.
fn lock_path(dir: &Path, account: &str) -> PathBuf {
    let safe: String = account
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    dir.join(format!("run-{safe}.lock"))
}

/// Create the lock file, failing if it already exists.
///
/// `create_new` is the atomic part: two processes racing here cannot both
/// succeed, whatever the filesystem does afterwards.
fn try_create(path: &Path) -> std::io::Result<RunLock> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    write!(file, "{}", std::process::id())?;
    Ok(RunLock {
        path: path.to_path_buf(),
    })
}

/// The pid in an existing lock file, if it holds one we can read.
fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Whether a process with this id still exists.
///
/// Signal 0 asks the kernel exactly that question without delivering anything.
/// `EPERM` means the process exists and belongs to someone else, which still
/// counts as alive.
#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: `kill` with signal 0 performs the permission and existence
    // checks and sends nothing.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Without a way to ask, assume the holder is alive: refusing to run is
/// recoverable, racing on the archive is not.
#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    true
}
