//! Terminal output helpers shared by commands: ANSI color constants and
//! stdin prompts.

use anyhow::{bail, Result};
use std::io::Write;

// ANSI color helpers
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";

pub fn prompt(label: &str, default: &str) -> Result<String> {
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
