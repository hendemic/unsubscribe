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

    /// A fully attached terminal, for exercising the interactive paths.
    #[must_use]
    #[allow(dead_code)]
    pub const fn attached() -> Self {
        Self {
            stdin: true,
            stdout: true,
            stderr: true,
        }
    }

    /// Nothing attached: the shape of a cron job or a systemd timer.
    #[must_use]
    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Colour is a process-wide switch, so the tests that flip it take turns.
    fn colour_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Render every escape with colour forced on or off, then put the switch
    /// back the way the rest of the suite expects it.
    fn rendered(enabled: bool) -> String {
        let _guard = colour_lock();
        let previous = colors_enabled();
        set_colors_enabled(enabled);
        let text = format!("{BOLD}{DIM}{GREEN}{RED}{YELLOW}{CYAN}{BLUE}text{RESET}");
        set_colors_enabled(previous);
        text
    }

    // -----------------------------------------------------------------------
    // decide_colors
    // -----------------------------------------------------------------------

    #[test]
    fn colour_is_on_for_a_terminal_that_asked_for_nothing_else() {
        assert!(decide_colors(false, false, true));
    }

    #[test]
    fn the_no_color_flag_turns_colour_off_even_on_a_terminal() {
        assert!(!decide_colors(true, false, true));
    }

    #[test]
    fn the_no_color_environment_variable_turns_colour_off() {
        // https://no-color.org: any value means no colour.
        assert!(!decide_colors(false, true, true));
    }

    #[test]
    fn colour_is_off_when_stderr_is_not_a_terminal() {
        // Redirected output is read by something that does not draw escapes.
        assert!(!decide_colors(false, false, false));
    }

    #[test]
    fn any_single_reason_is_enough_to_turn_colour_off() {
        for (flag, env, tty) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
            (true, true, false),
        ] {
            assert!(
                !decide_colors(flag, env, tty),
                "colour should be off for (flag={flag}, env={env}, tty={tty})"
            );
        }
    }

    #[test]
    fn nothing_but_an_attached_terminal_turns_colour_on() {
        let on: Vec<(bool, bool, bool)> = [false, true]
            .into_iter()
            .flat_map(|flag| {
                [false, true].into_iter().flat_map(move |env| {
                    [false, true]
                        .into_iter()
                        .map(move |tty| (flag, env, tty))
                })
            })
            .filter(|(flag, env, tty)| decide_colors(*flag, *env, *tty))
            .collect();
        assert_eq!(on, [(false, false, true)]);
    }

    // -----------------------------------------------------------------------
    // Ansi rendering
    // -----------------------------------------------------------------------

    #[test]
    fn an_escape_renders_nothing_at_all_when_colour_is_off() {
        assert_eq!(rendered(false), "text");
    }

    #[test]
    fn an_escape_renders_its_sequence_when_colour_is_on() {
        let text = rendered(true);
        assert!(text.starts_with("\x1b[1m"), "{text:?}");
        assert!(text.ends_with("\x1b[0m"), "{text:?}");
        assert!(text.contains("text"), "{text:?}");
    }

    #[test]
    fn every_escape_is_distinct_so_none_is_a_copy_of_another() {
        let all = [BOLD, DIM, RESET, GREEN, RED, YELLOW, CYAN, BLUE];
        let mut seen: Vec<Ansi> = Vec::new();
        for escape in all {
            assert!(!seen.contains(&escape), "{escape:?} is defined twice");
            seen.push(escape);
        }
    }

    // -----------------------------------------------------------------------
    // Tty
    // -----------------------------------------------------------------------

    #[test]
    fn a_detached_invocation_has_no_stream_to_prompt_on() {
        let tty = Tty::detached();
        assert!(!tty.stdin && !tty.stdout && !tty.stderr);
    }

    #[test]
    fn an_attached_invocation_has_all_three() {
        let tty = Tty::attached();
        assert!(tty.stdin && tty.stdout && tty.stderr);
    }

    // -----------------------------------------------------------------------
    // Prompts
    // -----------------------------------------------------------------------

    #[test]
    fn a_prompt_refuses_a_stdin_nobody_is_typing_into() {
        // Under `cargo test` stdin is not a terminal, which is exactly the
        // shape of a cron job: every prompt must fail rather than block.
        assert!(!std::io::stdin().is_terminal(), "this test needs a piped stdin");
        for result in [
            prompt("Host", "imap.example.com"),
            prompt_password("Password"),
            confirm("Proceed?").map(|_| String::new()),
        ] {
            let error = result.unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains("stdin is not a terminal"),
                "a prompt should explain itself, got: {message}"
            );
        }
    }
}
