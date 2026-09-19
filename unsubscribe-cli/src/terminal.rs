//! Terminal output helpers shared by commands: ANSI color constants, colour
//! and TTY policy, and stdin prompts.
//!
//! The colour constants keep their names and their places in format strings,
//! but render nothing once colour is switched off, so `--no-color`, `NO_COLOR`
//! and a redirected stderr are one decision made at startup rather than a
//! condition at every call site.

use anyhow::{bail, Result};
use std::fmt;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// An ANSI escape that disappears when colour is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ansi(&'static str);

impl fmt::Display for Ansi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if colors_enabled() {
            f.write_str(self.0)
        } else {
            Ok(())
        }
    }
}

// ANSI color helpers
pub const BOLD: Ansi = Ansi("\x1b[1m");
pub const DIM: Ansi = Ansi("\x1b[2m");
pub const RESET: Ansi = Ansi("\x1b[0m");
pub const GREEN: Ansi = Ansi("\x1b[32m");
pub const RED: Ansi = Ansi("\x1b[31m");
pub const YELLOW: Ansi = Ansi("\x1b[33m");
pub const CYAN: Ansi = Ansi("\x1b[36m");
pub const BLUE: Ansi = Ansi("\x1b[34m");

/// Colour is on unless something says otherwise; `set_colors_enabled` runs
/// before any command does.
static COLORS: AtomicBool = AtomicBool::new(true);

/// Whether ANSI colour should be emitted.
#[must_use]
pub fn colors_enabled() -> bool {
    COLORS.load(Ordering::Relaxed)
}

pub fn set_colors_enabled(enabled: bool) {
    COLORS.store(enabled, Ordering::Relaxed);
}

/// Decide whether to colour output.
///
/// Pure, so the precedence is checkable: an explicit `--no-color` wins, then
/// the `NO_COLOR` convention, and finally the only case worth guessing about --
/// output that is being read by something other than a terminal.
#[must_use]
pub fn decide_colors(no_color_flag: bool, no_color_env: bool, stderr_is_tty: bool) -> bool {
    !no_color_flag && !no_color_env && stderr_is_tty
}

/// Which of the standard streams are attached to a terminal.
///
/// Captured once and passed around rather than queried ad hoc, so a command's
/// behaviour can be exercised without a pty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tty {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

impl Tty {
    /// Ask the operating system.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            stdin: std::io::stdin().is_terminal(),
            stdout: std::io::stdout().is_terminal(),
            stderr: std::io::stderr().is_terminal(),
        }
    }

    /// A fully attached terminal, for tests and for the interactive default.
    #[must_use]
    pub const fn attached() -> Self {
        Self {
            stdin: true,
            stdout: true,
            stderr: true,
        }
    }

    /// Nothing attached: the shape of a cron job or a systemd timer.
    #[must_use]
    pub const fn detached() -> Self {
        Self {
            stdin: false,
            stdout: false,
            stderr: false,
        }
    }
}

/// Refuse to read from a stdin nobody is typing into.
///
/// Every prompt goes through here, so an unattended invocation that reaches one
/// fails with something a log can explain instead of blocking until the timer
/// kills it.
fn require_interactive_stdin(label: &str) -> Result<()> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    bail!(
        "`{label}` needs an answer, but stdin is not a terminal.\n\
         Run this command interactively, or use the flags that supply the answer \
         (see `unsubscribe --help`)."
    )
}

pub fn prompt(label: &str, default: &str) -> Result<String> {
    require_interactive_stdin(label)?;
    if default.is_empty() {
        eprint!("  {BOLD}{label}{RESET}: ");
    } else {
        eprint!("  {BOLD}{label}{RESET} {DIM}[{default}]{RESET}: ");
    }
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() && !default.is_empty() {
        Ok(default.to_string())
    } else if input.is_empty() {
        bail!("{label} is required");
    } else {
        Ok(input.to_string())
    }
}

pub fn prompt_password(label: &str) -> Result<String> {
    require_interactive_stdin(label)?;
    eprint!("  {BOLD}{label}{RESET}: ");
    std::io::stderr().flush()?;

    // Disable echo for password input
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios = unsafe {
            let mut t = std::mem::zeroed::<libc::termios>();
            libc::tcgetattr(fd, &mut t);
            t
        };
        let orig = termios;
        termios.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

        let mut input = String::new();
        let result = std::io::stdin().read_line(&mut input);

        // Restore echo
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
        eprintln!(); // newline after hidden input

        result?;
        Ok(input.trim().to_string())
    }

    #[cfg(not(unix))]
    {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}

/// Ask a yes/no question, defaulting to no.
///
/// Used where a headless caller is expected to pass `--yes` instead; callers
/// check for a terminal first, so this never blocks a timer.
pub fn confirm(question: &str) -> Result<bool> {
    require_interactive_stdin(question)?;
    eprint!("{question} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().chars().next(), Some('y') | Some('Y')))
}
