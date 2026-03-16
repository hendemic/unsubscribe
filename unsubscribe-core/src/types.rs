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

/// Result of scanning one or more folders.
#[derive(Debug)]
pub struct ScanResult {
    /// Senders found, sorted by email count descending
    pub senders: Vec<SenderInfo>,
    /// Warnings about unparseable List-Unsubscribe headers
    pub warnings: Vec<String>,
}

/// Outcome of an unsubscribe attempt for a single sender.
#[derive(Debug)]
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
