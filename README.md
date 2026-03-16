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
| `scan` | List senders that have unsubscribe links. `-m <n>` for minimum email count. |
| `export` | Export scan results to CSV. `-o <file>` for output path (default: `unsubscribe_senders.csv`). |
| `warnings` | Show unparseable List-Unsubscribe headers from the last scan. |
| `update` | Self-update to the latest GitHub release. |
| `reauth` | Update IMAP credentials (server, username, password). |
| `init` | Create config file with interactive setup. |

Global option: `-c <path>` to specify a config file.

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

MIT
