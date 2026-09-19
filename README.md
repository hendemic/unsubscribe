# unsubscribe

A CLI/TUI tool to bulk unsubscribe from email lists via IMAP.

## Install

**From release binary (Linux/macOS):**

```
curl -sL https://raw.githubusercontent.com/hendemic/unsubscribe/main/install.sh | bash
```

The binary is installed to `~/.local/bin`. Make sure it's in your PATH:

```
export PATH="$HOME/.local/bin:$PATH"
```

Add that line to your `~/.bashrc` or `~/.zshrc` to make it permanent.

**From source:**

```
cargo install --git https://github.com/hendemic/unsubscribe
```

## Setup

```
unsubscribe init
```

Interactive prompts will ask for your IMAP host, port, email address, app password, folders to scan, and archive folder. The password is stored in your OS keychain.

## Usage

Run `unsubscribe` with no arguments and the full-screen app opens: a narrow nav
on the left, and a working area on the right that shows whatever is
highlighted.

```
┌ Unsubscribe · you@example.com ─────────────────────────┐
│ > Run              │ Last scan: 2h ago · 214 senders   │
│   Unsubscribe List │ 3 resumed · 12 unsubscribed       │
│   Warnings (2)     │                                   │
│   Logs             │ > Unsubscribe from new scan       │
│   Settings         │   Unsubscribe from cached         │
│                    │   Scan only                       │
│   Quit             │                                   │
├────────────────────┴───────────────────────────────────┤
│ ↑↓ move  Enter open  ? help  q quit                    │
└────────────────────────────────────────────────────────┘
```

- **Run** — what the last scan found, and the three ways to act on it: scan
  the mailbox afresh and unsubscribe, work from the last scan, or just scan
  to refresh the cache. The scan, the sender selection, the confirmation, the
  run and its results all happen inside this panel.
- **Unsubscribe List** — every sender that has been asked, what it did after,
  and its full timeline.
- **Warnings** — `List-Unsubscribe` headers the last scan could not parse.
- **Logs** — every recorded event, newest first: each attempt and each sender
  that started mailing again.
- **Settings** — account, folders and preferences, including re-authentication.

#### Keys

`Enter` moves in, `Esc` moves out — exactly one level per press. `Esc` never
quits: the app is left with `q` from the nav, or `Ctrl-C` from anywhere. These
keys mean the same thing in every panel, sub-view and dialog.

Inside the **Run** workflow — the scan, the sender selection, the run and its
results — `Esc` means something slightly different: it hands focus back to the
nav and leaves the screen standing. A scan or a run keeps going on its worker,
the nav marks Run with what it has waiting (`Run (scanning…)`, `Run ●`), and
coming back to Run finds the same screen with the same cursor, ticks and
progress. Stopping is never something `Esc` does by accident: cancelling is
`c`, which asks first whenever there is work or a choice to lose. Every screen
that can be cancelled also shows the same action as a row you can move onto
and press `Enter` on — `[ Cancel scan ]`, `[ Stop run ]`, `[ Discard
selection ]`, `[ Close ]` — so the hotkey is a shortcut, never the only way.
On the scan and the run it already has the cursor; on the sender selection it
sits below the last sender, reached with `End`/`G` or by pressing down past
the bottom, and `Enter` on a sender row still means "go with what I have
ticked". While a scan or run is stopping the row stays where it is and reads
as inert — `[ Cancelling… ]`, `[ Stopping… ]` — rather than disappearing.
Quitting
while a scan or a run is going asks too, then stops the worker cleanly — an
attempt in flight is always finished first.

Dialogs follow the same rule: every question draws its answers as buttons you
can move onto and press — `[ Keep scanning ]  [ Stop scanning ]`,
`[ Cancel ]  [ Run ]` — and the button says what it will do rather than
"Confirm". `←` `→` move along the row, `Enter` or `Space` presses the
focused button, and the confirm button starts focused so `Enter` answers a
question as it always has. `y` still confirms and `n` or `Esc` still cancels
from anywhere. The run confirmation adds a `[ ] Dry run` checkbox above the
buttons: `↑` moves onto it, `Space` or `Enter` ticks it, `d` ticks it from
anywhere in the dialog, and ticking it renames the confirm button to
`[ Dry run ]` so the mode cannot be on without the button saying so.

The footer lists the keys whatever has focus answers. When they do not fit on
one line it wraps onto a second; when even that is not enough it ends with
`?: more`, and `?` opens the overlay listing every key.

| Key | Does |
|-----|------|
| `↑` `↓` / `k` `j` | Move |
| `Ctrl+↑` `Ctrl+↓` | Move five rows — in every list; the nav is six rows long and ignores it |
| `PgUp` `PgDn` | Move a page |
| `Home` `End` / `g` `G` | First / last row |
| `Enter` | Open, confirm, or act on the highlighted row |
| `→` | Move focus from the nav into the working area |
| `Esc` / `←` | Back one level; from a panel's top level, back to the nav. In the Run workflow, back to the nav with the screen left standing |
| `q` | Quit — only when the nav has focus; never "back" |
| `Ctrl-C` | Quit from anywhere |
| `?` | Show the keys for whatever has focus |
| `/` | Search, wherever a list is searchable |
| `Space` | Tick or untick the row under the cursor |

Panel actions are single letters. A letter means one thing throughout the app:

| Key | Does | Where |
|-----|------|-------|
| `a` | Select all | Sender selection |
| `n` | Select none; also "no" at a confirmation | Sender selection, dialogs |
| `c` | Cancel what is in front of you: stop a scan or a run, discard a selection, close the results — the same as pressing the screen's `[ … ]` row | Scan, sender selection, run, results |
| `y` | Confirm, whatever the dialog has focused | Dialogs |
| `s` | Cycle the sort order | Unsubscribe List |
| `r` | Show only senders that resumed | Unsubscribe List |
| `f` | Cycle the event filter (all / failures / resumptions) | Logs |
| `u` | Unsubscribe from this sender again | Sender timeline |
| `d` | Tick the dry-run checkbox, from any focus | Run confirmation |
| `w` | Write the settings to disk | Settings |
| `x` | Discard unsaved changes | Settings |

While a text field has focus, printable keys type; only `Esc`, `Enter` and
`Backspace` keep their meaning.

```
unsubscribe                     # the app
unsubscribe <command> [options] # scriptable, no prompts
```

The subcommands are the headless half of the same engine — the app and the
commands share every decision, so neither can disagree with the other about
which senders are stale, which resumed, or what to try next.

| Command | Description |
|---------|-------------|
| `tui` | Open the full-screen app explicitly. Same as running with no arguments. |
| `run` | Scan mailbox, select senders in a TUI, unsubscribe, and archive emails. `--dry-run` to preview without changes. `-m <n>` to set minimum email count (default: 3). |
| `scan` | List senders that have unsubscribe links. `-m <n>` for minimum email count. Always performs a full scan. |
| `export` | Export scan results to CSV. `-o <file>` for output path (default: `unsubscribe_senders.csv`). |
| `history` | Show what has been asked of each sender and what it did. `--sender`, `--resumed`, `--since <date>`, `--timeline`. Reads records only; never contacts the mailbox. |
| `warnings` | Show unparseable List-Unsubscribe headers from the last scan. |
| `update` | Self-update to the latest GitHub release. |
| `reauth` | Update IMAP credentials (server, username, password). |
| `init` | Create config file with interactive setup. |
| `config` | Edit settings in a terminal UI, or read and change them one key at a time: `config list`, `get`, `set`, `unset`, `path`. |

Global options: `-c <path>` to specify a config file, `--json` for machine-readable
output, `--quiet` to suppress progress and status messages, `--no-color` to drop ANSI
colours.

Its recommended that you start with a dry run to see what would happen without making any changes:

```
unsubscribe run --dry-run
```

By default, only senders with 3 or more emails are shown. Use `--min-emails` / `-m` to adjust a
single run, or set `min_emails` under `[preferences]` to change the default:

```
unsubscribe run --min-emails 5
unsubscribe scan -m 1
```

### Cached scans

Scanning a large mailbox takes a while, so `run` and `export` remember the last
scan. When one is available they ask whether to reuse it:

```
Last scan: Sep 12, 2026 (6 days ago) — 214 senders. [U]se cached / [r]escan:
```

Enter reuses the cached scan, unless it is more than a week old, in which case
the default flips to a rescan. `--cached` and `--rescan` answer the question up
front and skip the prompt. Senders are dropped from the cache once their emails
are archived, so a cached run never offers senders you have already handled.

### Where your data lives

In `~/.local/share/email-unsubscribe` (or `$XDG_DATA_HOME`):

| File | Contents |
|------|----------|
| `history.db` | Every unsubscribe attempt and every resumption, kept permanently. Senders you have unsubscribed from before appear in their own section in the TUI, labelled with whether the mail actually stopped. A sender that started up again after the grace period is recorded as a violation and a retry escalates to the next method it offers, rather than repeating the one it ignored. |
| `cache.db` | The last scan. Disposable — deleting it only costs a rescan. |
| `warnings.log` | Headers the last scan could not parse. |
| `unsubscribe_log.csv` | The last run's results, rewritten each run. |

`unsubscribe uninstall` removes all of it, along with the config and the binary.

## Headless operation

Every command works with no terminal attached: nothing prompts, progress becomes one
line per event instead of a redrawn bar, and colours switch off automatically. `run`
normally opens the selection screen, so a scheduled run has to say what it wants
instead:

| Flag | Selects |
|------|---------|
| `--resumed` | Senders that ignored a previous unsubscribe |
| `--all-active` | Every non-stale sender not previously unsubscribed from |
| `--stale` | Stale senders, archived without an unsubscribe attempt |
| `--sender <email>` | One named sender; repeat for more |
| `--senders-file <path>` | One address per line, `#` comments |

The flags combine as a union. Any of them makes the run non-interactive. Add `--yes` to
act without a confirmation, and `--max-senders <n>` to change the safety cap (default
50; `0` lifts it). Addresses that are not in the current scan are reported and skipped.

A second `run` for the same account exits with code 5 rather than racing the first on
the archive; a lock left behind by a crashed run is cleared automatically.

```
unsubscribe run --resumed --yes --json --quiet
```

### cron

```cron
# Re-unsubscribe from anyone who started mailing again, every night at 03:20.
20 3 * * * /usr/local/bin/unsubscribe run --resumed --yes --quiet --json >> /var/log/unsubscribe.json 2>> /var/log/unsubscribe.err
```

### systemd timer

`~/.config/systemd/user/unsubscribe.service`:

```ini
[Unit]
Description=Re-unsubscribe from senders that resumed mailing

[Service]
Type=oneshot
ExecStart=/usr/local/bin/unsubscribe run --resumed --yes --quiet
# 3 means some unsubscribes failed and 6 means there was nothing to do; neither
# is a reason to mark the unit failed.
SuccessExitStatus=0 3 6
```

`~/.config/systemd/user/unsubscribe.timer`:

```ini
[Unit]
Description=Nightly unsubscribe sweep

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl --user enable --now unsubscribe.timer`.

### Credentials without a desktop keyring

A headless server usually has no keyring daemon. Point the config at a command that
prints the password instead — it is run at startup and nothing is stored on disk:

```toml
[account]
password_command = "pass show email/imap"
```

Anything that writes the password to stdout works: `pass`, `gopass`, `op read`,
`systemd-creds cat`, or `cat /run/secrets/imap-password` on a machine where that file
is locked down. Gmail accounts use OAuth and need `unsubscribe reauth` run once from a
machine with a browser; the refresh token then lives in the keyring.

### JSON output

`--json` writes the command's result to **stdout** as a single document, with every
human-readable line, progress report and warning on **stderr** — so redirecting stdout
gives a file that parses whether or not anything went wrong. Supported on `run`,
`scan`, `history`, `warnings` and `list-folders`.

Documents carry a `schema_version` and use core's stable identifiers — method ids like
`one_click_post`, outcome names like `resumed` — never display strings.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Unexpected error |
| `2` | Usage error (bad flags, unknown config key, no selection flags with no terminal) |
| `3` | Completed, but some unsubscribes failed |
| `4` | Authentication failure |
| `5` | Another run holds the lock for this account |
| `6` | Nothing to do — no senders matched |

## Config

Config file location: `~/.config/email-unsubscribe/config.toml`

`unsubscribe config` opens a settings screen for everything in that file — account, SMTP, scan
folders, and preferences. The file stays the source of truth and stays hand-editable: saving
edits it in place, so your comments and any keys the screen does not show are left alone.

```
unsubscribe config
```

On a server, where there is no screen to open, the same settings are available one key at a
time. Keys are the dotted paths of the TOML layout, and every write goes through the same
validation and the same comment-preserving editor as the screen:

```
unsubscribe config list                            # every setting, and whether it is a default
unsubscribe config get scan.folders
unsubscribe config set scan.folders INBOX,Promotions
unsubscribe config set preferences.grace_period_days 21
unsubscribe config unset account.smtp_host         # restore the default
unsubscribe config path                            # where the config and data live
```

List settings accept a comma-separated value or several arguments. `config` with no subcommand
and no terminal behaves as `config list`. An unknown key exits with code `2`. Credentials are
never readable or writable here — `config list` says only where they are stored.

| Key | Action |
|-----|--------|
| `j` / `k`, arrows | Move between settings |
| `Enter` | Edit the setting (or cycle provider / auth type, or open the folder picker) |
| `s` | Save |
| `r` | Discard unsaved changes |
| `q` | Quit (asks first if anything is unsaved) |

Scan folders are picked from the list your provider reports, the same list `list-folders` prints.
Folders in your config that the server does not report stay selected and visible so a save never
drops them. If the folder list cannot be fetched — or the provider has none, as with Gmail —
the picker falls back to typing folder names separated by commas.

Credentials are never shown or edited here. The Account section says where they are stored and
offers a **Re-authenticate** action that runs the same flow as `unsubscribe reauth`. Changing the
provider, username, or auth type warns you that re-authentication is needed.

Run `unsubscribe init` first if you have no config file yet.

Passwords are stored in the OS keychain by default. Alternatives:

```toml
# Use an external command (e.g., pass, 1Password CLI)
password_command = "pass show email/imap"

# Or plaintext fallback (not recommended for security sake)
password = "your-password"
```

### Preferences

The optional `[preferences]` section tunes behavior. Omit the section, or any single key, to
use the default:

| Key | Default | Meaning |
|-----|---------|---------|
| `min_emails` | `3` | Minimum emails a sender needs to be listed. `0` shows every sender. Overridden per-run by `--min-emails`. |
| `stale_after_months` | `12` | Months without a message before a sender counts as stale. Stale senders start deselected and are archived without an unsubscribe request. |
| `cache_max_age_days` | `7` | Days a cached scan stays fresh. Past this, the scan timestamp is flagged as old. |
| `grace_period_days` | `14` | Days a sender is given to honour an unsubscribe. Mail arriving after this counts as a resumption and is recorded as a violation. `0` counts any new mail immediately. |

```toml
[preferences]
min_emails = 3
stale_after_months = 12
cache_max_age_days = 7
grace_period_days = 14
```

### Supported providers

| Provider | IMAP host | Notes |
|----------|-----------|-------|
| Gmail | `imap.gmail.com` | [App password](https://myaccount.google.com/apppasswords) required. Folders use `[Gmail]/` prefix (e.g. `[Gmail]/Promotions`). |
| Outlook | `outlook.office365.com` | |
| Yahoo | `imap.mail.yahoo.com` | |
| Zoho | `imap.zoho.com` | |
| iCloud | `imap.mail.me.com` | App-specific password required. |
| Fastmail | `imap.fastmail.com` | |

Any provider with IMAP support on port 993 should work. See [config.toml.example](config.toml.example) for the full template.

## License

GPL-3.0-only
