use anyhow::Result;

use crate::types::{AccountConfig, Credential, Folder, FolderMessage, HttpResponse, ScanResult};

/// Port for scan progress reporting.
///
/// Consumers implement this to display progress during scanning (progress bars,
/// status updates, etc.). The trait requires `Send + Sync` because adapters like
/// IMAP may call it from multiple threads concurrently.
pub trait ScanProgress: Send + Sync {
    /// Called when a folder scan begins, after the folder is selected.
    fn on_folder_start(&self, folder: &Folder, total_messages: u32);

    /// Called after each batch of messages is scanned within a folder.
    fn on_messages_scanned(&self, folder: &Folder, count: u32);

    /// Called when a folder scan is complete.
    fn on_folder_done(&self, folder: &Folder);
}

/// No-op implementation for consumers that don't need progress reporting.
pub struct NoopProgress;

impl ScanProgress for NoopProgress {
    fn on_folder_start(&self, _folder: &Folder, _total_messages: u32) {}
    fn on_messages_scanned(&self, _folder: &Folder, _count: u32) {}
    fn on_folder_done(&self, _folder: &Folder) {}
}

/// Port for email providers (IMAP, Gmail API, Exchange, Apple Accounts, etc.).
///
/// Adapters implement this trait to let core scan mailboxes and archive messages.
/// All methods are synchronous -- adapters own their own concurrency internally.
pub trait EmailProvider {
    /// Scan the given folders for senders with List-Unsubscribe headers.
    fn scan(&self, folders: &[Folder], progress: &dyn ScanProgress) -> Result<ScanResult>;

    /// Move the given messages to the specified destination folder.
    fn archive(&self, messages: &[FolderMessage], destination: &Folder) -> Result<u32>;
}

/// Port for HTTP operations needed during unsubscribe flows and API access.
///
/// CLI provides this via reqwest, iOS via URLSession, tests via mocks.
pub trait HttpClient {
    /// Perform an HTTP GET request.
    fn get(&self, url: &str) -> Result<HttpResponse>;

    /// Perform an HTTP GET request with additional request headers.
    fn get_with_headers(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;

    /// Perform an HTTP POST with form-encoded key-value pairs.
    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<HttpResponse>;

    /// Perform an HTTP POST with the given content-type and raw body.
    fn post_body(&self, url: &str, content_type: &str, body: &str) -> Result<HttpResponse>;

    /// Perform an HTTP POST with the given content-type, raw body, and additional request headers.
    fn post_body_with_headers(
        &self,
        url: &str,
        content_type: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse>;
}

/// Port for sending emails on behalf of the user.
///
/// Used for mailto-based unsubscribe flows where the unsubscribe mechanism
/// requires sending an email rather than visiting a URL. Adapters implement
/// this trait separately from `EmailProvider` because sending is a distinct
/// concern from scanning/archiving.
///
/// Gmail provides this via `users.messages.send`. IMAP users provide this
/// via SMTP. The trait is optional in the unsubscribe flow -- when absent,
/// mailto-only senders are skipped as before.
pub trait EmailSender {
    /// Send an email with the given recipient, subject, and body.
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<()>;
}

/// Port for reading and writing account configuration.
///
/// CLI implements this with TOML files. iOS will use CoreData/SwiftData.
/// The persistence crate (`unsubscribe-persistence`) provides the CLI implementation.
pub trait ConfigStore {
    /// Read the configuration for an account, or None if it doesn't exist.
    fn read_config(&self, account_id: &str) -> Result<Option<AccountConfig>>;

    /// Write (create or update) the configuration for an account.
    fn write_config(&self, config: &AccountConfig) -> Result<()>;
}

/// Port for storing, retrieving, and deleting credentials.
///
/// CLI implements this with the OS keychain. iOS will use Keychain Services.
/// The persistence crate (`unsubscribe-persistence`) provides the CLI implementation.
pub trait CredentialStore {
    /// Store a credential for the given account.
    fn store_credential(&self, account_id: &str, credential: &Credential) -> Result<()>;

    /// Retrieve the credential for the given account, or None if not stored.
    fn get_credential(&self, account_id: &str) -> Result<Option<Credential>>;

    /// Delete the credential for the given account. No-op if not stored.
    fn delete_credential(&self, account_id: &str) -> Result<()>;
}
