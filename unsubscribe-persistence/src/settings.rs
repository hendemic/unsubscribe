//! The settings schema: every key, its range, and what a valid value looks like.
//!
//! One implementation, in the config layer, because two front-ends ask the same
//! questions of it. `unsubscribe config set` and the settings screen must agree
//! on what a port is, what `min_emails` may be, and which keys exist at all --
//! and a rule that lives in one front-end is a rule the other quietly does not
//! have.
//!
//! Numbers are held as text throughout. A half-typed value has to survive until
//! it is corrected, and the command line hands everything over as a string
//! anyway; parsing happens once, at [`Settings::to_config`].

use unsubscribe_core::{AccountConfig, AuthType, PreferenceField, Preferences, ProviderType};

use crate::config::{default_archive_folder, default_folders};

/// How a setting is written in the TOML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKind {
    /// A quoted string.
    Text,
    /// A bare integer.
    Integer,
    /// An array of strings.
    List,
    /// A string from a fixed set.
    Choice,
}


/// One editable setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKey {
    Provider,
    Host,
    Port,
    Username,
    AuthType,
    SmtpHost,
    SmtpPort,
    Folders,
    ArchiveFolder,
    MinEmails,
    StaleAfterMonths,
    CacheMaxAgeDays,
    GracePeriodDays,
}

impl SettingKey {
    /// Every field, in the order they appear on screen.
    pub const ALL: [SettingKey; 13] = [
        SettingKey::Provider,
        SettingKey::Host,
        SettingKey::Port,
        SettingKey::Username,
        SettingKey::AuthType,
        SettingKey::SmtpHost,
        SettingKey::SmtpPort,
        SettingKey::Folders,
        SettingKey::ArchiveFolder,
        SettingKey::MinEmails,
        SettingKey::StaleAfterMonths,
        SettingKey::CacheMaxAgeDays,
        SettingKey::GracePeriodDays,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            SettingKey::Provider => "Provider",
            SettingKey::Host => "Host",
            SettingKey::Port => "Port",
            SettingKey::Username => "Username",
            SettingKey::AuthType => "Auth type",
            SettingKey::SmtpHost => "SMTP host",
            SettingKey::SmtpPort => "SMTP port",
            SettingKey::Folders => "Folders",
            SettingKey::ArchiveFolder => "Archive folder",
            SettingKey::MinEmails => "Minimum emails",
            SettingKey::StaleAfterMonths => "Stale after (months)",
            SettingKey::CacheMaxAgeDays => "Cache max age (days)",
            SettingKey::GracePeriodDays => "Grace period (days)",
        }
    }

    /// SettingKeys with a fixed set of values cycle through them instead of
    /// accepting free text, so they can never hold something unparseable.
    pub const fn choices(self) -> Option<&'static [&'static str]> {
        match self {
            SettingKey::Provider => Some(&["imap", "gmail"]),
            SettingKey::AuthType => Some(&["password", "oauth"]),
            _ => None,
        }
    }

    /// Whether changing this field invalidates the stored credentials.
    pub const fn affects_credentials(self) -> bool {
        matches!(self, SettingKey::Provider | SettingKey::Username | SettingKey::AuthType)
    }
}

// ---------------------------------------------------------------------------
// The settings themselves
// ---------------------------------------------------------------------------

/// The settings as text, which is what the user is actually editing.
///
/// Numbers are held as strings so a half-typed or invalid value survives until
/// the user corrects it, rather than being silently coerced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub provider: String,
    pub host: String,
    pub port: String,
    pub username: String,
    pub auth_type: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub folders: Vec<String>,
    pub archive_folder: String,
    pub min_emails: String,
    pub stale_after_months: String,
    pub cache_max_age_days: String,
    pub grace_period_days: String,
}

impl Settings {
    pub fn from_config(account: &AccountConfig, preferences: &Preferences) -> Self {
        Self {
            provider: match account.provider_type {
                ProviderType::Gmail => "gmail".to_string(),
                ProviderType::Imap => "imap".to_string(),
            },
            host: account.host.clone().unwrap_or_default(),
            port: account.port.map(|p| p.to_string()).unwrap_or_default(),
            username: account.username.clone(),
            auth_type: match account.auth_type {
                AuthType::OAuth => "oauth".to_string(),
                AuthType::Password => "password".to_string(),
            },
            smtp_host: account.smtp_host.clone().unwrap_or_default(),
            smtp_port: account.smtp_port.map(|p| p.to_string()).unwrap_or_default(),
            folders: account.scan_folders.clone(),
            archive_folder: account.archive_folder.clone(),
            min_emails: preferences.min_emails.to_string(),
            stale_after_months: preferences.stale_after_months.to_string(),
            cache_max_age_days: preferences.cache_max_age_days.to_string(),
            grace_period_days: preferences.grace_period_days.to_string(),
        }
    }

    /// The field's value as editable/displayable text.
    pub fn get(&self, field: SettingKey) -> String {
        match field {
            SettingKey::Provider => self.provider.clone(),
            SettingKey::Host => self.host.clone(),
            SettingKey::Port => self.port.clone(),
            SettingKey::Username => self.username.clone(),
            SettingKey::AuthType => self.auth_type.clone(),
            SettingKey::SmtpHost => self.smtp_host.clone(),
            SettingKey::SmtpPort => self.smtp_port.clone(),
            SettingKey::Folders => self.folders.join(", "),
            SettingKey::ArchiveFolder => self.archive_folder.clone(),
            SettingKey::MinEmails => self.min_emails.clone(),
            SettingKey::StaleAfterMonths => self.stale_after_months.clone(),
            SettingKey::CacheMaxAgeDays => self.cache_max_age_days.clone(),
            SettingKey::GracePeriodDays => self.grace_period_days.clone(),
        }
    }

    pub fn set(&mut self, field: SettingKey, value: String) {
        match field {
            SettingKey::Provider => self.provider = value,
            SettingKey::Host => self.host = value,
            SettingKey::Port => self.port = value,
            SettingKey::Username => self.username = value,
            SettingKey::AuthType => self.auth_type = value,
            SettingKey::SmtpHost => self.smtp_host = value,
            SettingKey::SmtpPort => self.smtp_port = value,
            SettingKey::Folders => self.folders = split_folders(&value),
            SettingKey::ArchiveFolder => self.archive_folder = value,
            SettingKey::MinEmails => self.min_emails = value,
            SettingKey::StaleAfterMonths => self.stale_after_months = value,
            SettingKey::CacheMaxAgeDays => self.cache_max_age_days = value,
            SettingKey::GracePeriodDays => self.grace_period_days = value,
        }
    }

    /// Advance a fixed-choice field to its next value. No-op for text fields.
    pub fn cycle(&mut self, field: SettingKey) {
        let Some(choices) = field.choices() else {
            return;
        };
        let current = self.get(field);
        let next = choices
            .iter()
            .position(|c| *c == current)
            .map_or(0, |i| (i + 1) % choices.len());
        self.set(field, choices[next].to_string());
    }

    fn is_gmail(&self) -> bool {
        self.provider == "gmail"
    }

    /// Check one field, returning a message suitable for display next to it.
    pub fn validate(&self, field: SettingKey) -> Result<(), String> {
        let value = self.get(field);
        match field {
            // Fixed-choice fields can only hold a value they were cycled to.
            SettingKey::Provider | SettingKey::AuthType => Ok(()),
            // Gmail talks to an API rather than a host, so a blank host is fine there.
            SettingKey::Host if self.is_gmail() => Ok(()),
            SettingKey::Host => require_non_empty(&value, "Host"),
            SettingKey::Username => require_non_empty(&value, "Username"),
            SettingKey::ArchiveFolder => require_non_empty(&value, "Archive folder"),
            SettingKey::Port if self.is_gmail() => optional_port(&value, "Port"),
            SettingKey::Port => require_non_empty(&value, "Port").and(optional_port(&value, "Port")),
            SettingKey::SmtpHost => Ok(()),
            SettingKey::SmtpPort => optional_port(&value, "SMTP port"),
            SettingKey::Folders => {
                if self.folders.is_empty() {
                    Err("At least one folder is required".to_string())
                } else {
                    Ok(())
                }
            }
            SettingKey::MinEmails => preference(&value, PreferenceField::MinEmails).map(|_| ()),
            SettingKey::StaleAfterMonths => {
                preference(&value, PreferenceField::StaleAfterMonths).map(|_| ())
            }
            SettingKey::CacheMaxAgeDays => {
                preference(&value, PreferenceField::CacheMaxAgeDays).map(|_| ())
            }
            SettingKey::GracePeriodDays => {
                preference(&value, PreferenceField::GracePeriodDays).map(|_| ())
            }
        }
    }

    /// The first field that fails validation, if any.
    pub fn first_invalid(&self) -> Option<(SettingKey, String)> {
        SettingKey::ALL
            .into_iter()
            .find_map(|field| self.validate(field).err().map(|msg| (field, msg)))
    }

    /// Convert to the shapes the config store writes, or report the first
    /// field that is not usable yet.
    pub fn to_config(&self, account_id_hint: &str) -> Result<(AccountConfig, Preferences), (SettingKey, String)> {
        if let Some(problem) = self.first_invalid() {
            return Err(problem);
        }

        let provider_type = if self.is_gmail() {
            ProviderType::Gmail
        } else {
            ProviderType::Imap
        };
        let auth_type = if self.auth_type == "oauth" {
            AuthType::OAuth
        } else {
            AuthType::Password
        };

        let account = AccountConfig {
            // The username is the account id; the hint only matters when a
            // future multi-account layout keys accounts by something else.
            account_id: if self.username.is_empty() {
                account_id_hint.to_string()
            } else {
                self.username.clone()
            },
            provider_type,
            host: optional_text(&self.host),
            port: self.port.trim().parse().ok(),
            username: self.username.trim().to_string(),
            auth_type,
            scan_folders: self.folders.clone(),
            archive_folder: self.archive_folder.trim().to_string(),
            smtp_host: optional_text(&self.smtp_host),
            smtp_port: self.smtp_port.trim().parse().ok(),
        };

        let preferences = Preferences {
            min_emails: preference(&self.min_emails, PreferenceField::MinEmails)
                .map_err(|e| (SettingKey::MinEmails, e))?,
            stale_after_months: preference(
                &self.stale_after_months,
                PreferenceField::StaleAfterMonths,
            )
            .map_err(|e| (SettingKey::StaleAfterMonths, e))?,
            cache_max_age_days: preference(
                &self.cache_max_age_days,
                PreferenceField::CacheMaxAgeDays,
            )
            .map_err(|e| (SettingKey::CacheMaxAgeDays, e))?,
            grace_period_days: preference(
                &self.grace_period_days,
                PreferenceField::GracePeriodDays,
            )
            .map_err(|e| (SettingKey::GracePeriodDays, e))?,
        };

        Ok((account, preferences))
    }
}

fn optional_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn require_non_empty(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

/// Ports are optional here; a blank one falls back to the protocol default.
fn optional_port(value: &str, label: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    match trimmed.parse::<u32>() {
        Ok(port) if (1..=65535).contains(&port) => Ok(()),
        _ => Err(format!("{label} must be a number between 1 and 65535")),
    }
}

fn preference(value: &str, field: PreferenceField) -> Result<u32, String> {
    let parsed: u32 = value
        .trim()
        .parse()
        .map_err(|_| format!("`{}` must be a whole number", field.key()))?;
    field.validate(parsed)?;
    Ok(parsed)
}

/// Split a comma-separated folder list, dropping blanks.
///
/// Public because the settings screen parses the same text when a folder is
/// picked from a list rather than typed.
pub fn split_folders(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The dotted paths, the TOML layout, and what may be removed.
impl SettingKey {
    /// The dotted path naming this setting, matching the TOML layout.
    ///
    /// This is the name a script uses, so it is deliberately the file's own
    /// structure rather than a second vocabulary to learn.
    pub const fn key(self) -> &'static str {
        match self {
            SettingKey::Provider => "account.provider",
            SettingKey::Host => "account.host",
            SettingKey::Port => "account.port",
            SettingKey::Username => "account.username",
            SettingKey::AuthType => "account.auth_type",
            SettingKey::SmtpHost => "account.smtp_host",
            SettingKey::SmtpPort => "account.smtp_port",
            SettingKey::Folders => "scan.folders",
            SettingKey::ArchiveFolder => "scan.archive_folder",
            SettingKey::MinEmails => "preferences.min_emails",
            SettingKey::StaleAfterMonths => "preferences.stale_after_months",
            SettingKey::CacheMaxAgeDays => "preferences.cache_max_age_days",
            SettingKey::GracePeriodDays => "preferences.grace_period_days",
        }
    }

    /// Look a setting up by its dotted path.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        Self::ALL
            .into_iter()
            .find(|key| key.key().eq_ignore_ascii_case(name))
    }

    /// The `(section, key)` this setting occupies in the document.
    #[must_use]
    pub fn location(self) -> (&'static str, &'static str) {
        self.key()
            .split_once('.')
            .expect("every setting key is a dotted path")
    }

    /// How the value is written.
    #[must_use]
    pub const fn kind(self) -> SettingKind {
        match self {
            SettingKey::Provider | SettingKey::AuthType => SettingKind::Choice,
            SettingKey::Port
            | SettingKey::SmtpPort
            | SettingKey::MinEmails
            | SettingKey::StaleAfterMonths
            | SettingKey::CacheMaxAgeDays
            | SettingKey::GracePeriodDays => SettingKind::Integer,
            SettingKey::Folders => SettingKind::List,
            SettingKey::Host | SettingKey::Username | SettingKey::SmtpHost
            | SettingKey::ArchiveFolder => SettingKind::Text,
        }
    }

    /// Whether the value is a list of strings.
    #[must_use]
    pub const fn is_list(self) -> bool {
        matches!(self.kind(), SettingKind::List)
    }

    /// Whether the key may be removed so its default applies again.
    ///
    /// `account.host` is here because a Gmail account talks to an API and has
    /// no host; validation still refuses to leave an IMAP account without one.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(
            self,
            SettingKey::Host
                | SettingKey::Port
                | SettingKey::SmtpHost
                | SettingKey::SmtpPort
                | SettingKey::MinEmails
                | SettingKey::StaleAfterMonths
                | SettingKey::CacheMaxAgeDays
                | SettingKey::GracePeriodDays
        )
    }

    /// The value that applies when the key is absent from the file.
    #[must_use]
    pub fn default_value(self) -> String {
        let preferences = Preferences::default();
        match self {
            SettingKey::Provider => "imap".to_string(),
            SettingKey::AuthType => "password".to_string(),
            SettingKey::Folders => default_folders().join(", "),
            SettingKey::ArchiveFolder => default_archive_folder(),
            SettingKey::MinEmails => preferences.min_emails.to_string(),
            SettingKey::StaleAfterMonths => preferences.stale_after_months.to_string(),
            SettingKey::CacheMaxAgeDays => preferences.cache_max_age_days.to_string(),
            SettingKey::GracePeriodDays => preferences.grace_period_days.to_string(),
            SettingKey::Host
            | SettingKey::Port
            | SettingKey::Username
            | SettingKey::SmtpHost
            | SettingKey::SmtpPort => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, valid IMAP account as text.
    fn settings() -> Settings {
        Settings {
            provider: "imap".to_string(),
            host: "imap.example.com".to_string(),
            port: "993".to_string(),
            username: "user@example.com".to_string(),
            auth_type: "password".to_string(),
            smtp_host: String::new(),
            smtp_port: String::new(),
            folders: vec!["INBOX".to_string()],
            archive_folder: "Unsubscribed".to_string(),
            min_emails: "3".to_string(),
            stale_after_months: "12".to_string(),
            cache_max_age_days: "7".to_string(),
            grace_period_days: "14".to_string(),
        }
    }

    fn with(key: SettingKey, value: &str) -> Settings {
        let mut settings = settings();
        settings.set(key, value.to_string());
        settings
    }

    // -----------------------------------------------------------------------
    // Dotted keys
    // -----------------------------------------------------------------------

    #[test]
    fn every_key_is_named_by_its_place_in_the_toml_file() {
        // The dotted path is deliberately the file's own layout, so a script
        // and a text editor agree about what a setting is called.
        let expected = [
            (SettingKey::Provider, "account.provider"),
            (SettingKey::Host, "account.host"),
            (SettingKey::Port, "account.port"),
            (SettingKey::Username, "account.username"),
            (SettingKey::AuthType, "account.auth_type"),
            (SettingKey::SmtpHost, "account.smtp_host"),
            (SettingKey::SmtpPort, "account.smtp_port"),
            (SettingKey::Folders, "scan.folders"),
            (SettingKey::ArchiveFolder, "scan.archive_folder"),
            (SettingKey::MinEmails, "preferences.min_emails"),
            (SettingKey::StaleAfterMonths, "preferences.stale_after_months"),
            (SettingKey::CacheMaxAgeDays, "preferences.cache_max_age_days"),
            (SettingKey::GracePeriodDays, "preferences.grace_period_days"),
        ];
        for (key, name) in expected {
            assert_eq!(key.key(), name);
        }
        assert_eq!(expected.len(), SettingKey::ALL.len(), "a key is missing from this table");
    }

    #[test]
    fn every_key_parses_back_from_its_own_name() {
        for key in SettingKey::ALL {
            assert_eq!(SettingKey::parse(key.key()), Some(key));
        }
    }

    #[test]
    fn a_key_is_recognised_whatever_case_or_padding_it_is_typed_in() {
        assert_eq!(SettingKey::parse("SCAN.FOLDERS"), Some(SettingKey::Folders));
        assert_eq!(SettingKey::parse("  scan.folders  "), Some(SettingKey::Folders));
    }

    #[test]
    fn an_unknown_key_is_not_resolved_to_anything() {
        for name in ["", "folders", "scan", "scan.folder", "account.hostname", "preferences"] {
            assert_eq!(SettingKey::parse(name), None, "{name:?} should be unknown");
        }
    }

    #[test]
    fn no_credential_is_addressable_as_a_setting() {
        // Credentials live in the keychain; `config` can say where and no more.
        for name in [
            "account.password",
            "account.password_command",
            "account.refresh_token",
            "account.access_token",
            "credentials",
        ] {
            assert_eq!(SettingKey::parse(name), None, "{name} must not be a setting");
        }
        for key in SettingKey::ALL {
            let name = key.key();
            assert!(
                !name.contains("password") && !name.contains("token") && !name.contains("secret"),
                "{name} looks like a credential"
            );
        }
    }

    #[test]
    fn a_keys_location_is_its_section_and_name() {
        assert_eq!(SettingKey::Folders.location(), ("scan", "folders"));
        assert_eq!(
            SettingKey::GracePeriodDays.location(),
            ("preferences", "grace_period_days")
        );
        for key in SettingKey::ALL {
            let (section, name) = key.location();
            assert_eq!(format!("{section}.{name}"), key.key());
        }
    }

    // -----------------------------------------------------------------------
    // Kinds and defaults
    // -----------------------------------------------------------------------

    #[test]
    fn only_the_folder_list_is_a_list() {
        for key in SettingKey::ALL {
            assert_eq!(
                key.is_list(),
                key == SettingKey::Folders,
                "{} reported the wrong kind",
                key.key()
            );
        }
    }

    #[test]
    fn required_keys_are_the_ones_the_account_cannot_work_without() {
        let optional: Vec<&str> = SettingKey::ALL
            .into_iter()
            .filter(|key| key.is_optional())
            .map(SettingKey::key)
            .collect();
        assert_eq!(
            optional,
            [
                "account.host",
                "account.port",
                "account.smtp_host",
                "account.smtp_port",
                "preferences.min_emails",
                "preferences.stale_after_months",
                "preferences.cache_max_age_days",
                "preferences.grace_period_days",
            ]
        );
    }

    #[test]
    fn preference_defaults_match_the_documented_values() {
        // Written out rather than read from `Preferences::default()`, so a
        // change to a default is a deliberate edit here too.
        assert_eq!(SettingKey::MinEmails.default_value(), "3");
        assert_eq!(SettingKey::StaleAfterMonths.default_value(), "12");
        assert_eq!(SettingKey::CacheMaxAgeDays.default_value(), "7");
        assert_eq!(SettingKey::GracePeriodDays.default_value(), "14");
    }

    #[test]
    fn a_key_with_no_fallback_has_an_empty_default() {
        for key in [
            SettingKey::Host,
            SettingKey::Port,
            SettingKey::Username,
            SettingKey::SmtpHost,
            SettingKey::SmtpPort,
        ] {
            assert_eq!(key.default_value(), "", "{} invented a default", key.key());
        }
    }

    #[test]
    fn a_fixed_choice_key_defaults_to_one_of_its_choices() {
        for key in [SettingKey::Provider, SettingKey::AuthType] {
            let choices = key.choices().expect("a choice key has choices");
            assert!(
                choices.contains(&key.default_value().as_str()),
                "{} defaults to something it cannot hold",
                key.key()
            );
        }
    }

    #[test]
    fn changing_who_the_account_is_invalidates_the_stored_credentials() {
        let affected: Vec<&str> = SettingKey::ALL
            .into_iter()
            .filter(|key| key.affects_credentials())
            .map(SettingKey::key)
            .collect();
        assert_eq!(
            affected,
            ["account.provider", "account.username", "account.auth_type"]
        );
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    #[test]
    fn a_complete_account_has_nothing_invalid_in_it() {
        assert_eq!(settings().first_invalid(), None);
    }

    #[test]
    fn an_imap_account_without_a_host_is_refused() {
        assert_eq!(
            with(SettingKey::Host, "").validate(SettingKey::Host),
            Err("Host cannot be empty".to_string())
        );
    }

    #[test]
    fn a_gmail_account_may_have_no_host_at_all() {
        // Gmail talks to an API, so there is no host to require.
        let mut settings = with(SettingKey::Host, "");
        settings.set(SettingKey::Provider, "gmail".to_string());
        assert_eq!(settings.validate(SettingKey::Host), Ok(()));
        assert_eq!(settings.validate(SettingKey::Port), Ok(()));
    }

    #[test]
    fn an_empty_username_or_archive_folder_is_refused() {
        assert!(with(SettingKey::Username, "  ")
            .validate(SettingKey::Username)
            .is_err());
        assert!(with(SettingKey::ArchiveFolder, "")
            .validate(SettingKey::ArchiveFolder)
            .is_err());
    }

    #[test]
    fn a_port_outside_the_addressable_range_is_refused() {
        for value in ["0", "65536", "-1", "993.5", "imap"] {
            assert_eq!(
                with(SettingKey::Port, value).validate(SettingKey::Port),
                Err("Port must be a number between 1 and 65535".to_string()),
                "port {value:?} should be refused"
            );
        }
    }

    #[test]
    fn the_edges_of_the_port_range_are_accepted() {
        for value in ["1", "65535"] {
            assert_eq!(with(SettingKey::Port, value).validate(SettingKey::Port), Ok(()));
        }
    }

    #[test]
    fn a_blank_smtp_port_falls_back_to_the_protocol_default() {
        assert_eq!(with(SettingKey::SmtpPort, "").validate(SettingKey::SmtpPort), Ok(()));
        assert!(with(SettingKey::SmtpPort, "70000")
            .validate(SettingKey::SmtpPort)
            .is_err());
    }

    #[test]
    fn a_non_numeric_preference_says_it_must_be_a_whole_number() {
        assert_eq!(
            with(SettingKey::MinEmails, "lots").validate(SettingKey::MinEmails),
            Err("`min_emails` must be a whole number".to_string())
        );
    }

    #[test]
    fn a_preference_outside_its_range_reports_the_range_and_the_value() {
        assert_eq!(
            with(SettingKey::StaleAfterMonths, "0").validate(SettingKey::StaleAfterMonths),
            Err("`stale_after_months` must be between 1 and 1200 (got 0)".to_string())
        );
        assert_eq!(
            with(SettingKey::GracePeriodDays, "3651").validate(SettingKey::GracePeriodDays),
            Err("`grace_period_days` must be between 0 and 3650 (got 3651)".to_string())
        );
    }

    #[test]
    fn zero_is_a_meaningful_value_for_the_preferences_that_allow_it() {
        // 0 emails disables the minimum filter; 0 grace days makes any new
        // mail an immediate resumption. Neither is a typo to be rejected.
        assert_eq!(with(SettingKey::MinEmails, "0").validate(SettingKey::MinEmails), Ok(()));
        assert_eq!(
            with(SettingKey::GracePeriodDays, "0").validate(SettingKey::GracePeriodDays),
            Ok(())
        );
    }

    #[test]
    fn an_account_with_no_folders_to_scan_is_refused() {
        assert_eq!(
            with(SettingKey::Folders, "").validate(SettingKey::Folders),
            Err("At least one folder is required".to_string())
        );
        assert_eq!(
            with(SettingKey::Folders, " , , ").validate(SettingKey::Folders),
            Err("At least one folder is required".to_string())
        );
    }

    #[test]
    fn first_invalid_reports_the_earliest_problem_on_screen() {
        // The screen puts the cursor on what it reports, so the order matters.
        let mut settings = settings();
        settings.set(SettingKey::Host, String::new());
        settings.set(SettingKey::MinEmails, "nope".to_string());
        assert_eq!(settings.first_invalid().map(|(key, _)| key), Some(SettingKey::Host));
    }

    // -----------------------------------------------------------------------
    // Reading and writing values as text
    // -----------------------------------------------------------------------

    #[test]
    fn a_folder_list_is_shown_comma_separated_and_read_back_the_same_way() {
        let settings = with(SettingKey::Folders, "INBOX, Promotions ,Updates");
        assert_eq!(settings.folders, ["INBOX", "Promotions", "Updates"]);
        assert_eq!(settings.get(SettingKey::Folders), "INBOX, Promotions, Updates");
    }

    #[test]
    fn splitting_folders_drops_blanks_and_trims_each_name() {
        assert_eq!(split_folders(" INBOX ,, Promotions , "), ["INBOX", "Promotions"]);
        assert!(split_folders("   ").is_empty());
    }

    #[test]
    fn every_key_round_trips_through_set_and_get() {
        let mut settings = settings();
        for key in SettingKey::ALL {
            settings.set(key, "INBOX".to_string());
            assert_eq!(settings.get(key), "INBOX", "{} did not round-trip", key.key());
        }
    }

    #[test]
    fn cycling_a_fixed_choice_key_walks_its_choices_and_comes_back() {
        let mut settings = settings();
        assert_eq!(settings.get(SettingKey::Provider), "imap");
        settings.cycle(SettingKey::Provider);
        assert_eq!(settings.get(SettingKey::Provider), "gmail");
        settings.cycle(SettingKey::Provider);
        assert_eq!(settings.get(SettingKey::Provider), "imap");
    }

    #[test]
    fn cycling_from_an_unrecognised_value_lands_on_the_first_choice() {
        let mut settings = with(SettingKey::AuthType, "something-else");
        settings.cycle(SettingKey::AuthType);
        assert_eq!(settings.get(SettingKey::AuthType), "password");
    }

    #[test]
    fn cycling_a_text_key_leaves_it_alone() {
        let mut settings = settings();
        settings.cycle(SettingKey::Host);
        assert_eq!(settings.get(SettingKey::Host), "imap.example.com");
    }

    // -----------------------------------------------------------------------
    // to_config
    // -----------------------------------------------------------------------

    #[test]
    fn valid_settings_convert_to_the_shapes_the_store_writes() {
        let (account, preferences) = settings().to_config("hint").unwrap();
        assert_eq!(account.account_id, "user@example.com");
        assert_eq!(account.host.as_deref(), Some("imap.example.com"));
        assert_eq!(account.port, Some(993));
        assert_eq!(account.scan_folders, ["INBOX"]);
        assert_eq!(account.smtp_host, None);
        assert_eq!(preferences.grace_period_days, 14);
    }

    #[test]
    fn converting_invalid_settings_names_the_field_that_is_wrong() {
        let settings = with(SettingKey::CacheMaxAgeDays, "0");
        let (key, message) = settings.to_config("hint").unwrap_err();
        assert_eq!(key, SettingKey::CacheMaxAgeDays);
        assert!(
            message.contains("cache_max_age_days"),
            "the message should name the key: {message}"
        );
    }

    #[test]
    fn a_settings_round_trip_through_a_config_changes_nothing() {
        let original = settings();
        let (account, preferences) = original.to_config("hint").unwrap();
        assert_eq!(Settings::from_config(&account, &preferences), original);
    }

    #[test]
    fn the_account_id_falls_back_to_the_hint_only_when_there_is_no_username() {
        let mut settings = with(SettingKey::Username, "");
        // An empty username is invalid, so fill in what the screen would have.
        settings.set(SettingKey::Username, "  ".to_string());
        assert!(settings.to_config("fallback").is_err());
    }
}
