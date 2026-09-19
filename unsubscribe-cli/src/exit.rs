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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Context};

    /// The documented table, written out rather than derived from `code()`, so
    /// a renumbering has to be a deliberate edit in two places.
    const DOCUMENTED: [(Exit, u8); 7] = [
        (Exit::Success, 0),
        (Exit::Failure, 1),
        (Exit::Usage, 2),
        (Exit::SomeFailed, 3),
        (Exit::Auth, 4),
        (Exit::Locked, 5),
        (Exit::NothingToDo, 6),
    ];

    #[test]
    fn every_outcome_has_the_exit_code_its_documentation_promises() {
        for (exit, code) in DOCUMENTED {
            assert_eq!(exit.code(), code, "{exit:?} changed its exit code");
        }
    }

    #[test]
    fn no_two_outcomes_share_an_exit_code() {
        // A script branches on these, so a collision makes two different
        // situations indistinguishable.
        let mut codes: Vec<u8> = DOCUMENTED.iter().map(|(_, code)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), DOCUMENTED.len());
    }

    #[test]
    fn the_help_text_lists_every_code_the_program_can_return() {
        for (exit, code) in DOCUMENTED {
            assert!(
                EXIT_CODE_HELP.contains(&format!("  {code}  ")),
                "{exit:?} ({code}) is missing from the printed table:\n{EXIT_CODE_HELP}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // exit_code
    // -----------------------------------------------------------------------

    #[test]
    fn a_successful_command_reports_its_own_outcome() {
        for (exit, code) in DOCUMENTED {
            assert_eq!(exit_code(&Ok(exit)), code);
        }
    }

    #[test]
    fn an_unrecognised_failure_is_the_catch_all() {
        let result: anyhow::Result<Exit> = Err(anyhow!("the disk caught fire"));
        assert_eq!(exit_code(&result), 1);
    }

    #[test]
    fn a_failure_that_names_its_outcome_reports_that_code() {
        let result: anyhow::Result<Exit> =
            Err(ExitError::new(Exit::Locked, "another run holds the lock").into());
        assert_eq!(exit_code(&result), 5);
    }

    #[test]
    fn a_usage_error_reports_two() {
        let result: anyhow::Result<Exit> = Err(ExitError::usage("pass a selection flag").into());
        assert_eq!(exit_code(&result), 2);
    }

    #[test]
    fn an_exit_code_survives_being_wrapped_in_context() {
        // Commands add context as an error travels up; the code must not be
        // lost on the way.
        let result: anyhow::Result<Exit> = Err(ExitError::new(Exit::Auth, "rejected"))
            .context("while opening the mailbox")
            .context("while running the timer job");
        assert_eq!(exit_code(&result), 4);
    }

    #[test]
    fn the_innermost_named_outcome_is_the_one_reported() {
        let result: anyhow::Result<Exit> = Err(ExitError::new(Exit::NothingToDo, "no senders"))
            .context("while planning the run");
        assert_eq!(exit_code(&result), 6);
    }

    #[test]
    fn the_message_of_an_exit_error_is_what_the_user_is_shown() {
        let error = ExitError::usage("pass --yes to run unattended");
        assert_eq!(error.to_string(), "pass --yes to run unattended");
        assert_eq!(error.exit(), Exit::Usage);
    }

    // -----------------------------------------------------------------------
    // Auth detection
    // -----------------------------------------------------------------------

    #[test]
    fn the_shapes_a_provider_rejects_a_login_in_are_recognised() {
        let rejections = [
            "[AUTHENTICATIONFAILED] Invalid credentials",
            "LOGIN failed",
            "Authentication failed for user@example.com",
            "invalid_grant: token expired",
            "HTTP 401 Unauthorized",
            "No credentials found. Run `unsubscribe init`",
        ];
        for text in rejections {
            assert!(
                looks_like_auth_failure(&anyhow!("{text}")),
                "{text:?} should read as an authentication failure"
            );
        }
    }

    #[test]
    fn an_ordinary_failure_is_not_mistaken_for_a_rejected_login() {
        for text in [
            "connection reset by peer",
            "Failed to move 3 messages to Unsubscribed",
            "the scan cache is corrupt",
        ] {
            assert!(
                !looks_like_auth_failure(&anyhow!("{text}")),
                "{text:?} should not read as an authentication failure"
            );
        }
    }

    #[test]
    fn a_rejection_buried_under_context_is_still_recognised() {
        // The marker is usually the innermost cause; `{:#}` is what flattens
        // the chain so the match can see it.
        let error = anyhow!("[AUTHENTICATIONFAILED] Invalid credentials")
            .context("Failed to open INBOX");
        assert!(looks_like_auth_failure(&error));
    }

    // -----------------------------------------------------------------------
    // classify_provider_error
    // -----------------------------------------------------------------------

    #[test]
    fn a_rejected_login_becomes_the_authentication_exit_code() {
        let classified = classify_provider_error(anyhow!("LOGIN failed"));
        assert_eq!(exit_code(&Err(classified)), 4);
    }

    #[test]
    fn an_unrelated_provider_failure_keeps_the_catch_all_code() {
        let classified = classify_provider_error(anyhow!("connection reset by peer"));
        assert_eq!(exit_code(&Err(classified)), 1);
    }

    #[test]
    fn classifying_never_overwrites_an_outcome_the_command_already_named() {
        // A held lock whose message happens to mention a login is still a
        // held lock.
        let held = ExitError::new(Exit::Locked, "another run holds the lock: login failed");
        let classified = classify_provider_error(held.into());
        assert_eq!(exit_code(&Err(classified)), 5);
    }

    #[test]
    fn classifying_keeps_the_message_the_provider_gave() {
        let classified = classify_provider_error(
            anyhow!("[AUTHENTICATIONFAILED] Invalid credentials").context("Failed to open INBOX"),
        );
        let shown = format!("{classified:#}");
        assert!(shown.contains("Invalid credentials"), "{shown}");
        assert!(shown.contains("Failed to open INBOX"), "{shown}");
    }
}
