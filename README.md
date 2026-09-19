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

```
unsubscribe <command> [options]
```

| Command | Description |
|---------|-------------|
| `run` | Scan mailbox, select senders in a TUI, unsubscribe, and archive emails. `--dry-run` to preview without changes. `-m <n>` to set minimum email count (default: 3). |
| `scan` | List senders that have unsubscribe links. `-m <n>` for minimum email count. Always performs a full scan. |
| `export` | Export scan results to CSV. `-o <file>` for output path (default: `unsubscribe_senders.csv`). |
| `warnings` | Show unparseable List-Unsubscribe headers from the last scan. |
| `update` | Self-update to the latest GitHub release. |
| `reauth` | Update IMAP credentials (server, username, password). |
| `init` | Create config file with interactive setup. |
| `config` | Edit settings in a terminal UI. |

Global option: `-c <path>` to specify a config file.

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
| `history.db` | Every unsubscribe attempt, kept permanently. Senders you have unsubscribed from before appear in their own section in the TUI, so you can see who started mailing again. |
| `cache.db` | The last scan. Disposable — deleting it only costs a rescan. |
| `warnings.log` | Headers the last scan could not parse. |
| `unsubscribe_log.csv` | The last run's results, rewritten each run. |

`unsubscribe uninstall` removes all of it, along with the config and the binary.

## Config

Config file location: `~/.config/email-unsubscribe/config.toml`

`unsubscribe config` opens a settings screen for everything in that file — account, SMTP, scan
folders, and preferences. The file stays the source of truth and stays hand-editable: saving
edits it in place, so your comments and any keys the screen does not show are left alone.

```
unsubscribe config
```

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
