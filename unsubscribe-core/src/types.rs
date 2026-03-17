use std::fmt;

/// Opaque identifier for an email message within a folder.
///
/// Adapters produce these; core never interprets the contents.
/// For IMAP this wraps a UID string, for Gmail API it might be a message ID, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageId(String);

impl MessageId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque folder name.
///
/// Adapters produce these; core never interprets the contents.
/// For IMAP this is the mailbox name, for Gmail API it might be a label ID, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Folder(String);

impl Folder {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A message located in a specific folder.
#[derive(Debug, Clone)]
pub struct FolderMessage {
    pub folder: Folder,
    pub message_id: MessageId,
}

/// A sender discovered during scanning, with unsubscribe information
/// and references to their messages across folders.
#[derive(Debug, Clone)]
pub struct SenderInfo {
    /// Display name (e.g. "Acme Newsletter")
    pub display_name: String,
    /// Email address of the sender
    pub email: String,
    /// Domain extracted from the sender email
    pub domain: String,
    /// HTTP(S) unsubscribe URLs from List-Unsubscribe headers
    pub unsubscribe_urls: Vec<String>,
    /// Mailto unsubscribe addresses from List-Unsubscribe headers
    pub unsubscribe_mailto: Vec<String>,
    /// Whether RFC 8058 one-click unsubscribe is supported
    pub one_click: bool,
    /// Total number of emails from this sender
    pub email_count: u32,
    /// All messages from this sender, each tagged with its folder
    pub messages: Vec<FolderMessage>,
}

impl SenderInfo {
    /// Returns the best unsubscribe URL for this sender: prefers HTTP URLs over mailto.
    pub fn best_unsubscribe_url(&self) -> Option<&str> {
        self.unsubscribe_urls
            .first()
            .or(self.unsubscribe_mailto.first())
            .map(|s| s.as_str())
    }
}

/// Result of scanning one or more folders.
#[derive(Debug)]
#[must_use]
pub struct ScanResult {
    /// Senders found, sorted by email count descending
    pub senders: Vec<SenderInfo>,
    /// Warnings about unparseable List-Unsubscribe headers
    pub warnings: Vec<String>,
}

/// Outcome of an unsubscribe attempt for a single sender.
#[derive(Debug)]
#[must_use]
pub struct UnsubscribeResult {
    /// Sender email address
    pub email: String,
    /// Method used (e.g. "one-click POST", "GET", "form POST", "mailto (skipped)")
    pub method: String,
    /// Whether the unsubscribe appeared to succeed
    pub success: bool,
    /// Human-readable detail (e.g. "HTTP 200", "Form submit error: ...")
    pub detail: String,
    /// The URL that was used for the attempt
    pub url: String,
}

/// Response from an HTTP request, returned by `HttpClient` implementations.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Response body as a string
    pub body: String,
}

/// Which email provider protocol/API to use for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderType {
    /// Standard IMAP connection (any provider: Zoho, Fastmail, self-hosted, etc.)
    Imap,
    /// Gmail REST API via OAuth2.
    Gmail,
}

impl Default for ProviderType {
    fn default() -> Self {
        Self::Imap
    }
}

/// How an account authenticates with its email provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthType {
    /// Plain password or app password (IMAP providers, etc.)
    Password,
    /// OAuth2 with token refresh (Gmail, future Exchange, etc.)
    OAuth,
}

impl Default for AuthType {
    fn default() -> Self {
        Self::Password
    }
}

/// Configuration for a single email account.
///
/// This is the runtime shape that consumers pass around. It is provider-agnostic:
/// the same struct works for IMAP, future Gmail API, Exchange, etc. Fields that
/// only apply to certain providers (like `port`) are optional.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// Unique identifier for this account (e.g. the email address)
    pub account_id: String,
    /// Which provider protocol to use (IMAP, Gmail API, etc.)
    pub provider_type: ProviderType,
    /// Provider host (e.g. "imap.gmail.com"). Not used by Gmail API provider.
    pub host: String,
    /// Provider port, if applicable (e.g. 993 for IMAPS). Not used by Gmail API provider.
    pub port: Option<u16>,
    /// Username for authentication
    pub username: String,
    /// How this account authenticates (password vs OAuth)
    pub auth_type: AuthType,
    /// Folders to scan for unsubscribe headers
    pub scan_folders: Vec<String>,
    /// Folder to move archived messages into
    pub archive_folder: String,
}

/// A stored credential, supporting passwords today and OAuth tokens in the future.
#[derive(Debug, Clone)]
pub enum Credential {
    /// Plain password (IMAP app passwords, etc.)
    Password(String),
    /// OAuth2 access + refresh token pair for providers that require it.
    OAuthToken {
        access_token: String,
        refresh_token: Option<String>,
    },
}
