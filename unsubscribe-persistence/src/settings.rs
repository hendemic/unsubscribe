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
