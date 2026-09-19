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

Global option: `-c <path>` to specify a config file.

Its recommended that you start with a dry run to see what would happen without making any changes:

```
unsubscribe run --dry-run
```

By default, only senders with 3 or more emails are shown. Use `--min-emails` / `-m` to adjust:

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

Passwords are stored in the OS keychain by default. Alternatives:

```toml
# Use an external command (e.g., pass, 1Password CLI)
password_command = "pass show email/imap"

# Or plaintext fallback (not recommended for security sake)
password = "your-password"
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
