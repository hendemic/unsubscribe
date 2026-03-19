#[cfg(feature = "imap")]
pub mod imap;

#[cfg(feature = "gmail")]
pub mod gmail;

#[cfg(feature = "smtp")]
pub mod smtp;

#[cfg(feature = "imap")]
pub use imap::ImapProvider;

#[cfg(feature = "gmail")]
pub use gmail::GmailProvider;

#[cfg(feature = "gmail")]
pub use gmail::GmailSender;

#[cfg(feature = "smtp")]
pub use smtp::SmtpSender;
