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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const ACCOUNT: &str = "user@example.com";

    /// The lock, or a panic naming who is holding it.
    fn acquire(dir: &Path, account: &str) -> RunLock {
        match RunLock::acquire_in(dir, account).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::Held(info) => panic!("expected the lock, but it is held: {info:?}"),
        }
    }

    /// Who holds the lock, or a panic because we got it.
    fn held(dir: &Path, account: &str) -> LockInfo {
        match RunLock::acquire_in(dir, account).unwrap() {
            LockOutcome::Held(info) => info,
            LockOutcome::Acquired(_) => panic!("expected the lock to be held"),
        }
    }

    /// A process id that certainly no longer exists: one we started and reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("a shell should be startable");
        let pid = child.id();
        child.wait().expect("the child should exit");
        pid
    }

    // -----------------------------------------------------------------------
    // Mutual exclusion
    // -----------------------------------------------------------------------

    #[test]
    fn a_second_run_against_the_same_account_is_refused() {
        let dir = TempDir::new().unwrap();
        let _first = acquire(dir.path(), ACCOUNT);
        let info = held(dir.path(), ACCOUNT);
        assert_eq!(info.pid, Some(std::process::id()));
    }

    #[test]
    fn a_refused_run_is_told_where_the_lock_file_is() {
        // The message points at a file the user can inspect or remove, so the
        // path has to be the one actually in the way.
        let dir = TempDir::new().unwrap();
        let first = acquire(dir.path(), ACCOUNT);
        let info = held(dir.path(), ACCOUNT);
        assert_eq!(info.path, first.path());
        assert!(info.path.exists());
    }

    #[test]
    fn a_run_against_a_different_account_is_not_blocked() {
        let dir = TempDir::new().unwrap();
        let first = acquire(dir.path(), ACCOUNT);
        let second = acquire(dir.path(), "other@example.com");
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn two_accounts_differing_only_in_case_do_not_share_a_lock() {
        let dir = TempDir::new().unwrap();
        let _first = acquire(dir.path(), "User@Example.com");
        // Different credentials, different mailbox: blocking one on the other
        // would be a false conflict.
        let _second = acquire(dir.path(), "user@example.com");
    }

    #[test]
    fn the_lock_file_records_the_owning_process() {
        let dir = TempDir::new().unwrap();
        let lock = acquire(dir.path(), ACCOUNT);
        let contents = fs::read_to_string(lock.path()).unwrap();
        assert_eq!(contents.trim(), std::process::id().to_string());
    }

    #[test]
    fn the_lock_file_name_contains_nothing_a_path_could_mistake() {
        let dir = TempDir::new().unwrap();
        let lock = acquire(dir.path(), "a/../b@example.com");
        let name = lock.path().file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "run-a____b_example_com.lock");
        assert_eq!(lock.path().parent(), Some(dir.path()));
    }

    #[test]
    fn the_data_directory_is_created_if_it_is_not_there_yet() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("does/not/exist/yet");
        let lock = acquire(&nested, ACCOUNT);
        assert!(lock.path().exists());
    }

    // -----------------------------------------------------------------------
    // Release
    // -----------------------------------------------------------------------

    #[test]
    fn the_lock_is_released_when_the_guard_goes_out_of_scope() {
        let dir = TempDir::new().unwrap();
        let path = {
            let lock = acquire(dir.path(), ACCOUNT);
            lock.path().to_path_buf()
        };
        assert!(!path.exists(), "the lock file outlived its guard");
        let _again = acquire(dir.path(), ACCOUNT);
    }

    #[test]
    fn a_run_that_returns_an_error_still_releases_the_lock() {
        let dir = TempDir::new().unwrap();
        let failed: Result<()> = (|| {
            let _lock = acquire(dir.path(), ACCOUNT);
            anyhow::bail!("the archive step failed")
        })();
        assert!(failed.is_err());
        let _again = acquire(dir.path(), ACCOUNT);
    }

    #[test]
    fn a_run_that_returns_early_still_releases_the_lock() {
        let dir = TempDir::new().unwrap();
        let nothing_to_do = || {
            let _lock = acquire(dir.path(), ACCOUNT);
            // The "nothing matched" path: an ordinary early return.
            42
        };
        assert_eq!(nothing_to_do(), 42);
        let _again = acquire(dir.path(), ACCOUNT);
    }

    #[test]
    fn a_lock_removed_underneath_us_does_not_make_release_fail() {
        // Release is best effort by design; a missing file must not panic.
        let dir = TempDir::new().unwrap();
        let lock = acquire(dir.path(), ACCOUNT);
        fs::remove_file(lock.path()).unwrap();
        drop(lock);
    }

    // -----------------------------------------------------------------------
    // Debris from a crashed run
    // -----------------------------------------------------------------------

    #[test]
    fn a_lock_left_by_a_dead_process_is_cleared_and_retaken() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let path = lock_path(dir.path(), ACCOUNT);
        fs::write(&path, dead_pid().to_string()).unwrap();

        let lock = acquire(dir.path(), ACCOUNT);
        assert_eq!(lock.path(), path);
        assert_eq!(
            fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string(),
            "the stale lock was reused rather than retaken"
        );
    }

    #[test]
    fn a_lock_file_with_nothing_readable_in_it_is_treated_as_debris() {
        // A run killed between creating the file and writing its pid leaves
        // this; needing manual cleanup for it would be the worst outcome.
        let dir = TempDir::new().unwrap();
        for contents in ["", "   ", "not-a-pid", "-1"] {
            let path = lock_path(dir.path(), ACCOUNT);
            fs::create_dir_all(dir.path()).unwrap();
            fs::write(&path, contents).unwrap();
            let lock = acquire(dir.path(), ACCOUNT);
            assert_eq!(
                fs::read_to_string(lock.path()).unwrap().trim(),
                std::process::id().to_string(),
                "lock file containing {contents:?} was not cleared"
            );
            drop(lock);
        }
    }

    #[test]
    fn a_lock_held_by_a_live_process_is_never_cleared() {
        let dir = TempDir::new().unwrap();
        let _first = acquire(dir.path(), ACCOUNT);
        // Two refusals in a row: the first must not have removed the file.
        let _ = held(dir.path(), ACCOUNT);
        let info = held(dir.path(), ACCOUNT);
        assert_eq!(info.pid, Some(std::process::id()));
    }

    // -----------------------------------------------------------------------
    // Liveness check
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn our_own_process_counts_as_alive() {
        assert!(process_is_alive(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn a_reaped_process_does_not_count_as_alive() {
        assert!(!process_is_alive(dead_pid()));
    }

    #[cfg(unix)]
    #[test]
    fn pid_zero_is_never_alive() {
        // `kill(0, 0)` signals our whole process group, which would report the
        // holder as alive forever.
        assert!(!process_is_alive(0));
    }

    #[cfg(unix)]
    #[test]
    fn pid_one_counts_as_alive_even_though_it_is_not_ours() {
        // init always exists and never belongs to us: EPERM must read as
        // "alive", not "gone".
        assert!(process_is_alive(1));
    }
}
