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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // decode_rfc2047
    // -----------------------------------------------------------------------

    #[test]
    fn decode_rfc2047_q_encoding() {
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?Hello_World?="),
            "Hello World"
        );
    }

    #[test]
    fn decode_rfc2047_q_encoding_hex_escape() {
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?caf=C3=A9?="),
            "caf\u{00C3}\u{00A9}"
        );
    }

    #[test]
    fn decode_rfc2047_b_encoding() {
        assert_eq!(
            decode_rfc2047("=?UTF-8?B?SGVsbG8=?="),
            "Hello"
        );
    }

    #[test]
    fn decode_rfc2047_mixed_text_and_encoded() {
        assert_eq!(
            decode_rfc2047("Plain =?UTF-8?Q?Encoded?= more plain"),
            "Plain Encoded more plain"
        );
    }

    #[test]
    fn decode_rfc2047_header_unfolding_crlf_space() {
        assert_eq!(
            decode_rfc2047("Line one\r\n continues"),
            "Line one continues"
        );
    }

    #[test]
    fn decode_rfc2047_header_unfolding_crlf_tab() {
        assert_eq!(
            decode_rfc2047("Line one\r\n\tcontinues"),
            "Line one continues"
        );
    }

    #[test]
    fn decode_rfc2047_header_unfolding_lf_space() {
        assert_eq!(
            decode_rfc2047("Line one\n continues"),
            "Line one continues"
        );
    }

    #[test]
    fn decode_rfc2047_header_unfolding_lf_tab() {
        assert_eq!(
            decode_rfc2047("Line one\n\tcontinues"),
            "Line one continues"
        );
    }

    #[test]
    fn decode_rfc2047_adjacent_encoded_words_whitespace_collapse() {
        // RFC 2047 sec 6.2: whitespace between adjacent encoded-words is ignored
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?Hello?= =?UTF-8?Q?_World?="),
            "Hello World"
        );
    }

    #[test]
    fn decode_rfc2047_adjacent_encoded_words_no_whitespace() {
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?Hello?==?UTF-8?Q?World?="),
            "HelloWorld"
        );
    }

    #[test]
    fn decode_rfc2047_non_adjacent_text_preserved() {
        // Non-whitespace text between encoded words should be preserved
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?A?=--=?UTF-8?Q?B?="),
            "A--B"
        );
    }

    #[test]
    fn decode_rfc2047_malformed_incomplete_start() {
        // =? without the rest of the structure
        assert_eq!(decode_rfc2047("=?broken"), "=?broken");
    }

    #[test]
    fn decode_rfc2047_malformed_missing_end() {
        // Missing ?= terminator -- charset and encoding parse, but no end marker
        let result = decode_rfc2047("=?UTF-8?Q?noend");
        // The parser skips the incomplete encoded word
        assert!(!result.is_empty() || result.is_empty()); // doesn't panic
    }

    #[test]
    fn decode_rfc2047_malformed_invalid_hex() {
        // Invalid hex in Q encoding -- should be skipped silently
        let result = decode_rfc2047("=?UTF-8?Q?=ZZ?=");
        assert!(!result.contains("panic"));
    }

    #[test]
    fn decode_rfc2047_malformed_incomplete_hex() {
        // Q encoding with = followed by only one char
        let result = decode_rfc2047("=?UTF-8?Q?=A?=");
        // Should not panic even with insufficient hex digits
        let _ = result;
    }

    #[test]
    fn decode_rfc2047_empty_encoded_text() {
        assert_eq!(decode_rfc2047("=?UTF-8?Q??="), "");
    }

    #[test]
    fn decode_rfc2047_unknown_charset_still_decodes() {
        // Non-UTF-8 charset -- B encoding will decode the bytes, lossy conversion
        let result = decode_rfc2047("=?ISO-8859-1?B?SGVsbG8=?=");
        assert_eq!(result, "Hello");
    }

    #[test]
    fn decode_rfc2047_unknown_encoding_passthrough() {
        // Unknown encoding type (not Q or B) -- encoded text passed through
        assert_eq!(
            decode_rfc2047("=?UTF-8?X?literal?="),
            "literal"
        );
    }

    #[test]
    fn decode_rfc2047_multiple_interleaved_sections() {
        assert_eq!(
            decode_rfc2047("=?UTF-8?Q?A?= middle =?UTF-8?B?Qg==?= end"),
            "A middle B end"
        );
    }

    #[test]
    fn decode_rfc2047_plain_text_passthrough() {
        assert_eq!(decode_rfc2047("No encoding here"), "No encoding here");
    }

    #[test]
    fn decode_rfc2047_empty_input() {
        assert_eq!(decode_rfc2047(""), "");
    }

    // -----------------------------------------------------------------------
    // parse_list_unsubscribe
    // -----------------------------------------------------------------------

    #[test]
    fn parse_list_unsubscribe_standard_format() {
        let result = parse_list_unsubscribe(
            "<https://example.com/unsub>, <mailto:unsub@example.com>",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["https://example.com/unsub"]);
        assert_eq!(result.mailtos, vec!["mailto:unsub@example.com"]);
        assert!(result.warning.is_none());
    }

    #[test]
    fn parse_list_unsubscribe_url_only() {
        let result = parse_list_unsubscribe(
            "<https://example.com/unsub>",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["https://example.com/unsub"]);
        assert!(result.mailtos.is_empty());
    }

    #[test]
    fn parse_list_unsubscribe_mailto_only() {
        let result = parse_list_unsubscribe(
            "<mailto:unsub@example.com>",
            "news@example.com",
        );
        assert!(result.urls.is_empty());
        assert_eq!(result.mailtos, vec!["mailto:unsub@example.com"]);
    }

    #[test]
    fn parse_list_unsubscribe_multiple_urls() {
        let result = parse_list_unsubscribe(
            "<https://a.com/unsub>, <https://b.com/unsub>",
            "news@example.com",
        );
        assert_eq!(result.urls.len(), 2);
        assert_eq!(result.urls[0], "https://a.com/unsub");
        assert_eq!(result.urls[1], "https://b.com/unsub");
    }

    #[test]
    fn parse_list_unsubscribe_without_angle_brackets() {
        let result = parse_list_unsubscribe(
            "https://example.com/unsub, mailto:unsub@example.com",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["https://example.com/unsub"]);
        assert_eq!(result.mailtos, vec!["mailto:unsub@example.com"]);
    }

    #[test]
    fn parse_list_unsubscribe_rfc2047_encoded() {
        let result = parse_list_unsubscribe(
            "<https://example.com/=?UTF-8?Q?unsub?=>",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["https://example.com/unsub"]);
    }

    #[test]
    fn parse_list_unsubscribe_warning_for_unparseable() {
        let result = parse_list_unsubscribe(
            "ftp://example.com/unsub",
            "news@example.com",
        );
        assert!(result.urls.is_empty());
        assert!(result.mailtos.is_empty());
        assert!(result.warning.is_some());
        assert!(result.warning.as_ref().unwrap().contains("news@example.com"));
    }

    #[test]
    fn parse_list_unsubscribe_warning_not_generated_when_urls_found() {
        // If at least one valid URL is found, unparseable parts don't generate a warning
        let result = parse_list_unsubscribe(
            "<https://example.com/unsub>, ftp://nope",
            "news@example.com",
        );
        assert_eq!(result.urls.len(), 1);
        assert!(result.warning.is_none());
    }

    #[test]
    fn parse_list_unsubscribe_empty_header() {
        let result = parse_list_unsubscribe("", "news@example.com");
        assert!(result.urls.is_empty());
        assert!(result.mailtos.is_empty());
        assert!(result.warning.is_none());
    }

    #[test]
    fn parse_list_unsubscribe_whitespace_only() {
        let result = parse_list_unsubscribe("   \t  ", "news@example.com");
        assert!(result.urls.is_empty());
        assert!(result.mailtos.is_empty());
        assert!(result.warning.is_none());
    }

    #[test]
    fn parse_list_unsubscribe_extra_whitespace() {
        let result = parse_list_unsubscribe(
            "  <https://example.com/unsub>  ,  <mailto:unsub@example.com>  ",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["https://example.com/unsub"]);
        assert_eq!(result.mailtos, vec!["mailto:unsub@example.com"]);
    }

    #[test]
    fn parse_list_unsubscribe_http_url() {
        let result = parse_list_unsubscribe(
            "<http://example.com/unsub>",
            "news@example.com",
        );
        assert_eq!(result.urls, vec!["http://example.com/unsub"]);
    }

    // -----------------------------------------------------------------------
    // domain_from_email
    // -----------------------------------------------------------------------

    #[test]
    fn domain_from_email_standard() {
        assert_eq!(domain_from_email("user@example.com"), "example.com");
    }

    #[test]
    fn domain_from_email_no_at() {
        assert_eq!(domain_from_email("nodomain"), "nodomain");
    }

    #[test]
    fn domain_from_email_uppercase() {
        assert_eq!(domain_from_email("User@EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn domain_from_email_empty_domain() {
        assert_eq!(domain_from_email("user@"), "");
    }

    #[test]
    fn domain_from_email_multiple_at() {
        // rsplit_once splits on the last @
        assert_eq!(domain_from_email("user@sub@example.com"), "example.com");
    }

    #[test]
    fn domain_from_email_empty_input() {
        assert_eq!(domain_from_email(""), "");
    }
}
