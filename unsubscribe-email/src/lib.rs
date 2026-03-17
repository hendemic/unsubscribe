#[cfg(feature = "imap")]
pub mod imap;

#[cfg(feature = "gmail")]
pub mod gmail;

#[cfg(feature = "imap")]
pub use imap::ImapProvider;

#[cfg(feature = "gmail")]
pub use gmail::GmailProvider;
