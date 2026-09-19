# Contributing

## Prerequisites

- Rust (stable toolchain via rustup)
- For Gmail support: a Google Cloud project with OAuth 2.0 credentials

## Building

```
cargo build
```

IMAP support builds without any extra setup. Gmail support requires OAuth credentials (see below).

## Setting up OAuth credentials for Gmail

The Gmail adapter requires a Google OAuth 2.0 client ID and secret. These are injected at build time via environment variables. Without them, `cargo build` will fail with a missing environment variable error.

### 1. Create a Google Cloud project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Gmail API**: APIs & Services > Library > search "Gmail API" > Enable

### 2. Create OAuth 2.0 credentials

1. Go to APIs & Services > Credentials
2. Click **Create Credentials** > **OAuth 2.0 Client ID**
3. Application type: **Desktop app**
4. Name it anything (e.g., "unsubscribe-dev")
5. Click **Create**

You do not need to add any redirect URIs — the app binds a random localhost port at runtime.

### 3. Configure the OAuth consent screen

1. Go to APIs & Services > OAuth consent screen
2. User type: **External** (allows any Google account during testing)
3. Fill in the required fields (app name, support email)
4. Add the scope: `https://www.googleapis.com/auth/gmail.modify`
5. Add yourself as a test user under "Test users"

### 4. Set up .cargo/config.toml

Copy the example file:

```
cp .cargo/config.toml.example .cargo/config.toml
```

Open `.cargo/config.toml` and replace the placeholder values with your credentials from the Google Cloud Console:

```toml
[env]
GOOGLE_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "your-client-secret"
```

This file is gitignored and will never be committed. Do not paste real credentials anywhere else.

### 5. Verify the build

```
cargo check
```

## Project structure

```
unsubscribe-core/         Domain types, orchestration, header parsing, HTML analysis
unsubscribe-email/        EmailProvider adapters (IMAP, Gmail)
unsubscribe-persistence/  Config and credential storage adapters
unsubscribe-cli/          CLI binary
```

The project follows hexagonal architecture. Dependencies flow inward: `cli` and adapter crates depend on `core`, never the reverse. See `.claude/rules/architecture.md` for the full rules.

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-only.
