/// Result of parsing a List-Unsubscribe header value.
#[derive(Debug, Clone)]
pub struct ParsedUnsub {
    /// HTTP(S) unsubscribe URLs
    pub urls: Vec<String>,
    /// Mailto unsubscribe addresses
    pub mailtos: Vec<String>,
    /// Warning if the header contained content we couldn't parse
    pub warning: Option<String>,
}

/// Decode RFC 2047 encoded words in a header value.
///
/// Handles `=?charset?Q?encoded?=` (quoted-printable) and `=?charset?B?encoded?=` (base64).
/// Also unfolds continuation lines per RFC 5322.
pub fn decode_rfc2047(input: &str) -> String {
    // Unfold the header: remove CRLF + leading whitespace on continuation lines
    let unfolded = input
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ")
        .replace("\n ", " ")
        .replace("\n\t", " ");

    let mut result = String::new();
    let mut remaining = unfolded.as_str();
    let mut last_was_encoded = false;

    while let Some(start) = remaining.find("=?") {
        let before = &remaining[..start];
        // Per RFC 2047: whitespace between adjacent encoded-words is ignored
        if !last_was_encoded || !before.trim().is_empty() {
            result.push_str(before);
        }
        remaining = &remaining[start + 2..];

        // Parse charset
        let Some(q1) = remaining.find('?') else {
            result.push_str("=?");
            last_was_encoded = false;
            continue;
        };
        let charset = &remaining[..q1];
        remaining = &remaining[q1 + 1..];

        // Parse encoding
        let Some(q2) = remaining.find('?') else {
            result.push_str("=?");
            result.push_str(charset);
            result.push('?');
            last_was_encoded = false;
            continue;
        };
        let encoding = &remaining[..q2];
        remaining = &remaining[q2 + 1..];

        // Parse encoded text until ?=
        let Some(end) = remaining.find("?=") else {
            last_was_encoded = false;
            continue;
        };
        let encoded_text = &remaining[..end];
        remaining = &remaining[end + 2..];

        match encoding.to_uppercase().as_str() {
            "Q" => {
                let mut chars = encoded_text.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '=' => {
                            let h1 = chars.next();
                            let h2 = chars.next();
                            if let (Some(h1), Some(h2)) = (h1, h2) {
                                let hex = format!("{h1}{h2}");
                                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                    result.push(byte as char);
                                }
                            }
                        }
                        '_' => result.push(' '),
                        _ => result.push(c),
                    }
                }
            }
            "B" => {
                use base64::Engine;
                if let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(encoded_text)
                {
                    result.push_str(&String::from_utf8_lossy(&decoded));
                }
            }
            _ => {
                result.push_str(encoded_text);
            }
        }
        last_was_encoded = true;
    }

    result.push_str(remaining);
    result
}

/// Extract unsubscribe URLs and mailto addresses from a List-Unsubscribe header value.
///
/// Expects the RFC 2369 format: `<https://example.com/unsub>, <mailto:unsub@example.com>`
/// Decodes RFC 2047 encoded words before parsing.
pub fn parse_list_unsubscribe(header_value: &str, sender_email: &str) -> ParsedUnsub {
    let decoded = decode_rfc2047(header_value);

    let mut urls = Vec::new();
    let mut mailtos = Vec::new();
    let mut had_unparsed = false;

    for part in decoded.split(',') {
        let trimmed = part.trim().trim_start_matches('<').trim_end_matches('>');
        if trimmed.starts_with("mailto:") {
            mailtos.push(trimmed.to_string());
        } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_string());
        } else if !trimmed.is_empty() {
            had_unparsed = true;
        }
    }

    let warning = if urls.is_empty() && mailtos.is_empty() && had_unparsed {
        Some(format!("{sender_email}: {decoded}"))
    } else {
        None
    };

    ParsedUnsub {
        urls,
        mailtos,
        warning,
    }
}

/// Extract the domain from an email address, lowercased.
///
/// Returns the full input lowercased if no `@` is found.
pub fn domain_from_email(email: &str) -> String {
    email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_lowercase())
        .unwrap_or_else(|| email.to_lowercase())
}
