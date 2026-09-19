use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use unsubscribe_core::EmailSender;

/// SMTP adapter for the `EmailSender` trait.
///
/// Sends unsubscribe emails via SMTP using the same credentials as the IMAP
/// connection. Uses implicit TLS (SMTPS) on the configured port, which
/// defaults to 465.
pub struct SmtpSender {
    from_address: String,
    smtp_host: String,
    smtp_port: u16,
    username: String,
    password: String,
}

impl SmtpSender {
    pub fn new(
        from_address: impl Into<String>,
        smtp_host: impl Into<String>,
        smtp_port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            from_address: from_address.into(),
            smtp_host: smtp_host.into(),
            smtp_port,
            username: username.into(),
            password: password.into(),
        }
    }

    /// Derive SMTP host from an IMAP host by replacing `imap.` with `smtp.`.
    /// Falls back to the original host if no `imap.` prefix is found.
    pub fn derive_smtp_host(imap_host: &str) -> String {
        if let Some(rest) = imap_host.strip_prefix("imap.") {
            format!("smtp.{rest}")
        } else {
            imap_host.to_string()
        }
    }
}

impl EmailSender for SmtpSender {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let email = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .context("Invalid From address for SMTP")?,
            )
            .to(to.parse().context("Invalid To address for SMTP")?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .context("Failed to build email message")?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = SmtpTransport::relay(&self.smtp_host)
            .context("Failed to configure SMTP transport")?
            .port(self.smtp_port)
            .credentials(creds)
            .build();

        mailer
            .send(&email)
            .context("Failed to send email via SMTP")?;

        Ok(())
    }
}
