use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Opaque identifier for an email message within a folder.
///
/// Adapters produce these; core never interprets the contents.
/// For IMAP this wraps a UID string, for Gmail API it might be a message ID, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMessage {
    pub folder: Folder,
    pub message_id: MessageId,
}

/// A sender discovered during scanning, with unsubscribe information
/// and references to their messages across folders.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// RFC 2919 `List-Id` of the mailing list, normalized (angle brackets
    /// stripped, lowercased).
    ///
    /// Senders rotate From addresses and send through ESPs; the list identifier
    /// is the stable thing a user actually unsubscribed from, so unsubscribe
    /// history records it as evidence. `None` when the header was absent or
    /// unparseable. Taken from the most recent message seen for this sender.
    #[serde(default)]
    pub list_id: Option<String>,
    /// The `List-Unsubscribe` header exactly as received on the most recent
    /// message, kept verbatim so a later violation report can quote it.
    #[serde(default)]
    pub list_unsubscribe_raw: Option<String>,
    /// Total number of emails from this sender
    pub email_count: u32,
    /// All messages from this sender, each tagged with its folder
    pub messages: Vec<FolderMessage>,
    /// Unix timestamp (seconds) of the most recent message from this sender.
    ///
    /// `None` when the adapter did not provide date information. Consumers use
    /// this to decide whether to treat the sender as stale — core imposes no
    /// staleness threshold.
    pub last_seen: Option<i64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sender(urls: Vec<&str>, mailtos: Vec<&str>, one_click: bool) -> SenderInfo {
        SenderInfo {
            display_name: "Test Sender".to_string(),
            email: "sender@example.com".to_string(),
            domain: "example.com".to_string(),
            unsubscribe_urls: urls.into_iter().map(str::to_string).collect(),
            unsubscribe_mailto: mailtos.into_iter().map(str::to_string).collect(),
            one_click,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 1,
            messages: Vec::new(),
            last_seen: None,
        }
    }

    #[test]
    fn best_url_prefers_http_over_mailto() {
        let sender = make_sender(
            vec!["https://example.com/unsub"],
            vec!["mailto:unsub@example.com"],
            false,
        );
        assert_eq!(
            sender.best_unsubscribe_url(),
            Some("https://example.com/unsub")
        );
    }

    #[test]
    fn best_url_returns_first_http_when_multiple() {
        let sender = make_sender(
            vec!["https://first.example.com/unsub", "https://second.example.com/unsub"],
            vec![],
            false,
        );
        assert_eq!(
            sender.best_unsubscribe_url(),
            Some("https://first.example.com/unsub")
        );
    }

    #[test]
    fn best_url_falls_back_to_mailto_when_no_http() {
        let sender = make_sender(vec![], vec!["mailto:unsub@example.com"], false);
        assert_eq!(
            sender.best_unsubscribe_url(),
            Some("mailto:unsub@example.com")
        );
    }

    #[test]
    fn best_url_returns_none_when_both_empty() {
        let sender = make_sender(vec![], vec![], false);
        assert_eq!(sender.best_unsubscribe_url(), None);
    }

    #[test]
    fn best_url_one_click_true_still_returns_http() {
        // one_click only affects how the URL is used, not which URL is selected
        let sender = make_sender(
            vec!["https://example.com/unsub"],
            vec!["mailto:unsub@example.com"],
            true,
        );
        assert_eq!(
            sender.best_unsubscribe_url(),
            Some("https://example.com/unsub")
        );
    }

    #[test]
    fn best_url_one_click_false_with_only_http() {
        let sender = make_sender(vec!["https://example.com/unsub"], vec![], false);
        assert_eq!(
            sender.best_unsubscribe_url(),
            Some("https://example.com/unsub")
        );
    }
}

/// How far a scan got, in whatever terms its adapter counts position.
///
/// Adapters fill this in from their own identifier format -- IMAP knows its
/// UIDs, Gmail its history ids -- because core never interprets a `MessageId`.
/// Stored alongside cached results for future incremental scanning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanWatermark {
    /// Per-folder highest UID seen (IMAP adapter)
    pub highest_uid: HashMap<String, u32>,
    /// Per-folder UIDVALIDITY (IMAP adapter)
    pub uid_validity: HashMap<String, u32>,
    /// Adapter-specific opaque state (e.g., Gmail historyId)
    pub adapter_state: Option<String>,
}

/// Result of scanning one or more folders.
#[derive(Debug, Default)]
#[must_use]
pub struct ScanResult {
    /// Senders found, sorted by email count descending
    pub senders: Vec<SenderInfo>,
    /// Warnings about unparseable List-Unsubscribe headers
    pub warnings: Vec<String>,
    /// Where the adapter left off, for a future incremental scan.
    pub watermark: ScanWatermark,
}

/// How an unsubscribe attempt was carried out.
///
/// Each variant has two string forms: `as_id` is the stable identifier written
/// to the unsubscribe history and must never be renamed, `label` is the
/// human-readable text shown in the CLI and the CSV action log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsubscribeMethod {
    /// RFC 8058 one-click POST to the `List-Unsubscribe` URL.
    OneClickPost,
    /// Plain GET of the `List-Unsubscribe` URL.
    Get,
    /// POST of a confirmation form found on the unsubscribe page.
    FormPost,
    /// GET of a confirmation form found on the unsubscribe page.
    FormGet,
    /// A confirmation link followed from the unsubscribe page.
    ConfirmLink,
    /// Unsubscribe email sent to the `mailto:` target.
    MailtoSent,
    /// Sending the unsubscribe email failed.
    MailtoFailed,
    /// Only a `mailto:` target was available and no sender was configured.
    MailtoSkipped,
    /// No usable unsubscribe mechanism was found.
    None,
    /// Nothing was attempted because the run was a dry run.
    DryRun,
}

impl UnsubscribeMethod {
    /// Stable identifier for storage. Changing these breaks existing history.
    #[must_use]
    pub fn as_id(&self) -> &'static str {
        match self {
            Self::OneClickPost => "one_click_post",
            Self::Get => "get",
            Self::FormPost => "form_post",
            Self::FormGet => "form_get",
            Self::ConfirmLink => "confirm_link",
            Self::MailtoSent => "mailto_sent",
            Self::MailtoFailed => "mailto_failed",
            Self::MailtoSkipped => "mailto_skipped",
            Self::None => "none",
            Self::DryRun => "dry_run",
        }
    }

    /// Human-readable label for CLI output and the CSV action log.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::OneClickPost => "one-click POST",
            Self::Get => "GET",
            Self::FormPost => "form POST",
            Self::FormGet => "form GET",
            Self::ConfirmLink => "confirm link",
            Self::MailtoSent => "mailto",
            Self::MailtoFailed => "mailto (failed)",
            Self::MailtoSkipped => "mailto (skipped)",
            Self::None => "none",
            Self::DryRun => "dry-run",
        }
    }

    /// Recover a method from its stable identifier, for reading history back.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        let method = match id {
            "one_click_post" => Self::OneClickPost,
            "get" => Self::Get,
            "form_post" => Self::FormPost,
            "form_get" => Self::FormGet,
            "confirm_link" => Self::ConfirmLink,
            "mailto_sent" => Self::MailtoSent,
            "mailto_failed" => Self::MailtoFailed,
            "mailto_skipped" => Self::MailtoSkipped,
            "none" => Self::None,
            "dry_run" => Self::DryRun,
            _ => return None,
        };
        Some(method)
    }
}

impl fmt::Display for UnsubscribeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Outcome of an unsubscribe attempt for a single sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct UnsubscribeResult {
    /// Sender email address
    pub email: String,
    /// How the attempt was carried out
    pub method: UnsubscribeMethod,
    /// Whether the unsubscribe appeared to succeed
    pub success: bool,
    /// Human-readable detail (e.g. "HTTP 200", "Form submit error: ...")
    pub detail: String,
    /// The URL that was used for the attempt
    pub url: String,
    /// Status code of the final HTTP response, when the attempt made one
    pub http_status: Option<u16>,
    /// The URL the attempt ended on after redirects, when the client reports it
    pub final_url: Option<String>,
}

/// Response from an HTTP request, returned by `HttpClient` implementations.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Response body as a string
    pub body: String,
    /// The URL the request ended on after following redirects.
    ///
    /// `None` when the client cannot report it; it is evidence, never control flow.
    pub final_url: Option<String>,
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
    /// Provider host (e.g. "imap.gmail.com"). `None` for providers that don't use a host (e.g. Gmail API).
    pub host: Option<String>,
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
    /// SMTP host for sending unsubscribe emails (optional, derived from IMAP host if absent)
    pub smtp_host: Option<String>,
    /// SMTP port for sending unsubscribe emails (optional, defaults to 465 for SMTPS)
    pub smtp_port: Option<u16>,
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

/// A single tunable preference, used for validation and by settings UIs that
/// need a stable key and an inclusive range per field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferenceField {
    MinEmails,
    StaleAfterMonths,
    CacheMaxAgeDays,
    GracePeriodDays,
}

impl PreferenceField {
    /// Every field, in the order a settings UI should present them.
    pub const ALL: [PreferenceField; 4] = [
        PreferenceField::MinEmails,
        PreferenceField::StaleAfterMonths,
        PreferenceField::CacheMaxAgeDays,
        PreferenceField::GracePeriodDays,
    ];

    /// The TOML key for this field inside `[preferences]`.
    pub const fn key(self) -> &'static str {
        match self {
            PreferenceField::MinEmails => "min_emails",
            PreferenceField::StaleAfterMonths => "stale_after_months",
            PreferenceField::CacheMaxAgeDays => "cache_max_age_days",
            PreferenceField::GracePeriodDays => "grace_period_days",
        }
    }

    /// Inclusive `(min, max)` range of accepted values.
    ///
    /// Upper bounds are generous but finite so that a typo (a pasted timestamp,
    /// say) is reported rather than silently disabling a feature.
    pub const fn bounds(self) -> (u32, u32) {
        match self {
            // 0 is meaningful here: it disables the minimum-count filter.
            PreferenceField::MinEmails => (0, 1_000_000),
            PreferenceField::StaleAfterMonths => (1, 1200),
            PreferenceField::CacheMaxAgeDays => (1, 3650),
            // 0 is meaningful here too: it means any mail after a successful
            // unsubscribe counts as a resumption straight away.
            PreferenceField::GracePeriodDays => (0, 3650),
        }
    }

    /// Check a value against this field's range, returning a message suitable
    /// for both a config-load error and an inline UI error.
    pub fn validate(self, value: u32) -> Result<(), String> {
        let (min, max) = self.bounds();
        if value < min || value > max {
            return Err(format!(
                "`{}` must be between {min} and {max} (got {value})",
                self.key()
            ));
        }
        Ok(())
    }
}

/// User-tunable behavior settings, read from the optional `[preferences]`
/// section of the config file.
///
/// These are a consumer concern -- core reads none of them. The CLI uses them
/// to decide which senders to show, what counts as stale, and how long a
/// cached scan stays fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preferences {
    /// Minimum number of emails a sender must have to appear in results.
    pub min_emails: u32,
    /// Months without a message before a sender is treated as stale.
    pub stale_after_months: u32,
    /// Days a cached scan is considered fresh.
    pub cache_max_age_days: u32,
    /// Days a sender is given to honour an unsubscribe before new mail from it
    /// counts as a resumption.
    ///
    /// CAN-SPAM allows ten business days to act on an opt-out, so the default
    /// leaves a margin either side of that.
    pub grace_period_days: u32,
}

impl Preferences {
    pub const DEFAULT_MIN_EMAILS: u32 = 3;
    pub const DEFAULT_STALE_AFTER_MONTHS: u32 = 12;
    pub const DEFAULT_CACHE_MAX_AGE_DAYS: u32 = 7;
    pub const DEFAULT_GRACE_PERIOD_DAYS: u32 = 14;

    /// Read the value of one field.
    pub fn get(&self, field: PreferenceField) -> u32 {
        match field {
            PreferenceField::MinEmails => self.min_emails,
            PreferenceField::StaleAfterMonths => self.stale_after_months,
            PreferenceField::CacheMaxAgeDays => self.cache_max_age_days,
            PreferenceField::GracePeriodDays => self.grace_period_days,
        }
    }

    /// Overwrite the value of one field, without validating it.
    pub fn set(&mut self, field: PreferenceField, value: u32) {
        match field {
            PreferenceField::MinEmails => self.min_emails = value,
            PreferenceField::StaleAfterMonths => self.stale_after_months = value,
            PreferenceField::CacheMaxAgeDays => self.cache_max_age_days = value,
            PreferenceField::GracePeriodDays => self.grace_period_days = value,
        }
    }

    /// Validate every field, returning the first problem found.
    pub fn validate(&self) -> Result<(), String> {
        PreferenceField::ALL
            .into_iter()
            .try_for_each(|field| field.validate(self.get(field)))
    }
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            min_emails: Self::DEFAULT_MIN_EMAILS,
            stale_after_months: Self::DEFAULT_STALE_AFTER_MONTHS,
            cache_max_age_days: Self::DEFAULT_CACHE_MAX_AGE_DAYS,
            grace_period_days: Self::DEFAULT_GRACE_PERIOD_DAYS,
        }
    }
}

#[cfg(test)]
mod unsubscribe_method_tests {
    use super::*;

    /// The storage identifier of every variant, written out by hand.
    ///
    /// These strings are a storage contract: they are already in users'
    /// `history.db`, so renaming one silently orphans their evidence. Any
    /// change here has to be a deliberate edit of this table.
    const PINNED_IDS: [(UnsubscribeMethod, &str); 10] = [
        (UnsubscribeMethod::OneClickPost, "one_click_post"),
        (UnsubscribeMethod::Get, "get"),
        (UnsubscribeMethod::FormPost, "form_post"),
        (UnsubscribeMethod::FormGet, "form_get"),
        (UnsubscribeMethod::ConfirmLink, "confirm_link"),
        (UnsubscribeMethod::MailtoSent, "mailto_sent"),
        (UnsubscribeMethod::MailtoFailed, "mailto_failed"),
        (UnsubscribeMethod::MailtoSkipped, "mailto_skipped"),
        (UnsubscribeMethod::None, "none"),
        (UnsubscribeMethod::DryRun, "dry_run"),
    ];

    #[test]
    fn every_variant_is_listed_in_the_pinned_table() {
        // Exhaustive on purpose: adding a variant makes this match fail to
        // compile, which is the prompt to pin its id in `PINNED_IDS`.
        fn accounted_for(method: UnsubscribeMethod) {
            match method {
                UnsubscribeMethod::OneClickPost
                | UnsubscribeMethod::Get
                | UnsubscribeMethod::FormPost
                | UnsubscribeMethod::FormGet
                | UnsubscribeMethod::ConfirmLink
                | UnsubscribeMethod::MailtoSent
                | UnsubscribeMethod::MailtoFailed
                | UnsubscribeMethod::MailtoSkipped
                | UnsubscribeMethod::None
                | UnsubscribeMethod::DryRun => {}
            }
        }
        for (method, _) in PINNED_IDS {
            accounted_for(method);
        }
    }

    #[test]
    fn storage_ids_match_the_pinned_table() {
        for (method, id) in PINNED_IDS {
            assert_eq!(method.as_id(), id, "storage id changed for {method:?}");
        }
    }

    #[test]
    fn storage_ids_are_distinct() {
        let mut ids: Vec<&str> = PINNED_IDS.iter().map(|(_, id)| *id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "two variants share a storage id");
    }

    #[test]
    fn from_id_round_trips_every_storage_id() {
        for (method, id) in PINNED_IDS {
            assert_eq!(UnsubscribeMethod::from_id(id), Some(method));
        }
    }

    #[test]
    fn from_id_rejects_unknown_ids() {
        assert_eq!(UnsubscribeMethod::from_id(""), None);
        assert_eq!(UnsubscribeMethod::from_id("mailto"), None);
        assert_eq!(UnsubscribeMethod::from_id("one-click-post"), None);
    }

    #[test]
    fn from_id_is_case_sensitive() {
        // History rows are written by `as_id`, which is always lowercase; an
        // uppercase id is corrupt data, not a synonym.
        assert_eq!(UnsubscribeMethod::from_id("Mailto_Sent"), None);
        assert_eq!(UnsubscribeMethod::from_id("DRY_RUN"), None);
    }

    #[test]
    fn mailto_sent_display_label_differs_from_its_storage_id() {
        // The label was shortened to "mailto" for CLI output; the stored id
        // must not have followed it.
        assert_eq!(UnsubscribeMethod::MailtoSent.label(), "mailto");
        assert_eq!(UnsubscribeMethod::MailtoSent.as_id(), "mailto_sent");
    }

    #[test]
    fn display_renders_the_label_not_the_id() {
        assert_eq!(UnsubscribeMethod::MailtoSent.to_string(), "mailto");
        assert_eq!(UnsubscribeMethod::OneClickPost.to_string(), "one-click POST");
        assert_eq!(UnsubscribeMethod::DryRun.to_string(), "dry-run");
    }

    #[test]
    fn labels_are_distinct_so_cli_output_is_unambiguous() {
        let mut labels: Vec<&str> = PINNED_IDS
            .iter()
            .map(|(method, _)| method.label())
            .collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before, "two variants share a display label");
    }
}

#[cfg(test)]
mod sender_info_compat_tests {
    use super::*;

    /// A `SenderInfo` as it was serialized before `list_id` and
    /// `list_unsubscribe_raw` existed, typed out rather than round-tripped so
    /// the old shape is fixed by the test rather than by today's struct.
    const PRE_LIST_ID_SENDER: &str = r#"{
        "display_name": "Acme Newsletter",
        "email": "news@acme.example.com",
        "domain": "acme.example.com",
        "unsubscribe_urls": ["https://acme.example.com/unsub"],
        "unsubscribe_mailto": [],
        "one_click": true,
        "email_count": 7,
        "messages": [{"folder": "INBOX", "message_id": "INBOX:42:1"}],
        "last_seen": 1700000000
    }"#;

    #[test]
    fn sender_serialized_before_list_id_existed_still_deserializes() {
        let sender: SenderInfo =
            serde_json::from_str(PRE_LIST_ID_SENDER).expect("old sender shape must still load");

        assert_eq!(sender.email, "news@acme.example.com");
        assert_eq!(sender.email_count, 7);
        assert_eq!(sender.messages.len(), 1);
        assert_eq!(sender.last_seen, Some(1_700_000_000));
        assert_eq!(sender.list_id, None);
        assert_eq!(sender.list_unsubscribe_raw, None);
    }
}
