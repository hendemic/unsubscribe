//! Exit codes.
//!
//! A script's only reliable channel is the exit status, so each distinguishable
//! outcome gets its own code and they are documented in `--help` and the
//! README. Commands return an [`Exit`] on the paths that are not plain success,
//! and attach one to an error with [`ExitError`] where the failure is
//! recognisable; everything else is an unexpected error.

use std::fmt;

/// Why the process is ending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Everything asked for happened.
    Success,
    /// An unexpected error. The catch-all.
    Failure,
    /// The invocation itself was wrong: bad flags, unknown key, a headless run
    /// with nothing to select by.
    Usage,
    /// The run finished, but at least one unsubscribe failed.
    SomeFailed,
    /// Credentials were missing, rejected, or could not be refreshed.
    Auth,
    /// Another run holds the lock for this account.
    Locked,
    /// Nothing matched, so nothing was done.
    NothingToDo,
}

impl Exit {
    /// The process exit status for this outcome.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::SomeFailed => 3,
            Self::Auth => 4,
            Self::Locked => 5,
            Self::NothingToDo => 6,
        }
    }

    /// One-line description, as the `--help` table prints it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "unexpected error",
            Self::Usage => "usage error",
            Self::SomeFailed => "completed with some failed unsubscribes",
            Self::Auth => "authentication failure",
            Self::Locked => "another run holds the lock",
            Self::NothingToDo => "nothing to do",
        }
    }

    /// Every code, in numeric order, for the help text and the README.
    pub const ALL: [Exit; 7] = [
        Exit::Success,
        Exit::Failure,
        Exit::Usage,
        Exit::SomeFailed,
        Exit::Auth,
        Exit::Locked,
        Exit::NothingToDo,
    ];
}

/// The exit-code table, as `--help` prints it and the README repeats it.
pub const EXIT_CODE_HELP: &str = "\
Exit codes:
  0  success
  1  unexpected error
  2  usage error
  3  completed with some failed unsubscribes
  4  authentication failure
  5  another run holds the lock
  6  nothing to do (no senders matched)";

/// An error that knows which exit code it deserves.
///
/// Wrapped in `anyhow` like any other error, so a command reports a usage
/// problem or a held lock with `?` and the mapping happens once, in `main`.
#[derive(Debug)]
pub struct ExitError {
    exit: Exit,
    message: String,
}

impl ExitError {
    #[must_use]
    pub fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
        }
    }

    /// A misuse of the command line.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Exit::Usage, message)
    }

    #[must_use]
    pub fn exit(&self) -> Exit {
        self.exit
    }
}

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

/// The process exit code for a finished command.
///
/// Pure: an error carrying an [`ExitError`] anywhere in its chain reports that
/// code, and anything else is the catch-all failure.
#[must_use]
pub fn exit_code(result: &anyhow::Result<Exit>) -> u8 {
    match result {
        Ok(exit) => exit.code(),
        Err(e) => e
            .chain()
            .find_map(|cause| cause.downcast_ref::<ExitError>())
            .map_or(Exit::Failure, ExitError::exit)
            .code(),
    }
}

/// Whether a failure looks like the provider rejecting our credentials.
///
/// Best-effort, and deliberately so: the adapters report protocol errors as
/// text, and the alternative -- a typed error on every port -- would change the
/// port contract for one consumer's exit code. A missed match costs the generic
/// failure code, never a wrong action.
#[must_use]
pub fn looks_like_auth_failure(error: &anyhow::Error) -> bool {
    const MARKERS: [&str; 8] = [
        "authenticationfailed",
        "invalid credentials",
        "login failed",
        "authentication failed",
        "invalid_grant",
        "unauthorized",
        "no credentials found",
        "run `unsubscribe reauth`",
    ];
    let text = format!("{error:#}").to_lowercase();
    MARKERS.iter().any(|marker| text.contains(marker))
}

/// Re-classify a failure that happened while talking to the provider.
///
/// Leaves an error that already carries an exit code alone: a lock or a usage
/// problem stays what it is.
#[must_use]
pub fn classify_provider_error(error: anyhow::Error) -> anyhow::Error {
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<ExitError>().is_some())
    {
        return error;
    }
    if looks_like_auth_failure(&error) {
        let message = format!("{error:#}");
        return anyhow::Error::new(ExitError::new(Exit::Auth, message));
    }
    error
}
