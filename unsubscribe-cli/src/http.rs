use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect;
use unsubscribe_core::{HttpClient, HttpResponse};
use url::Url;

/// Maximum number of redirect hops, matching legacy behavior.
const MAX_REDIRECTS: usize = 5;

/// Maximum response body size read from any single request, in bytes.
///
/// Enforced by capping the underlying byte stream (`Read::take`), so an
/// oversized or malicious response is never buffered in full.
const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Address classification (pure functions -- no reqwest, no I/O)
// ---------------------------------------------------------------------------

/// Returns true if `ip` must never be reached by an unattended unsubscribe
/// request: loopback, private (RFC 1918), link-local (including the
/// `169.254.169.254` cloud metadata address), carrier-grade NAT
/// (RFC 6598), "this network" (0.0.0.0/8), reserved (240.0.0.0/4),
/// multicast, broadcast, or an IPv6 unique-local/link-local range.
/// IPv4-mapped IPv6 addresses are unwrapped and classified as IPv4.
///
/// This is the single source of truth for "is this address safe to
/// connect to" -- used both to reject literal-IP URLs before any network
/// activity and to filter addresses returned by DNS resolution.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => is_blocked_ipv4(mapped),
            None => is_blocked_ipv6(v6),
        },
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // covers 169.254.169.254
        || ip.is_multicast()
        || ip.is_broadcast()
        || is_cgnat(ip)
        || is_current_network(ip)
        || is_reserved(ip)
}

/// 100.64.0.0/10 (RFC 6598 carrier-grade NAT).
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

/// 0.0.0.0/8 ("this network", RFC 791/1122) -- a superset of the single
/// unspecified address `0.0.0.0`.
fn is_current_network(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

/// 240.0.0.0/4 (reserved for future use, RFC 1112).
fn is_reserved(ip: Ipv4Addr) -> bool {
    (ip.octets()[0] & 0xf0) == 0xf0
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unique_local(ip)
        || is_unicast_link_local(ip)
}

/// fc00::/7 (unique local addresses).
fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 (link-local unicast).
fn is_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

// ---------------------------------------------------------------------------
// URL-level pre-flight checks (pure -- no network activity)
// ---------------------------------------------------------------------------

/// Reason a URL or resolved address was refused before (or during) a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockReason {
    UnsupportedScheme,
    EmbeddedCredentials,
    PrivateAddress,
}

impl BlockReason {
    fn detail(self) -> &'static str {
        match self {
            BlockReason::UnsupportedScheme => "blocked: unsupported URL scheme",
            BlockReason::EmbeddedCredentials => "blocked: URL contains embedded credentials",
            BlockReason::PrivateAddress => "blocked: private network address",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SsrfBlocked(BlockReason);

impl fmt::Display for SsrfBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.detail())
    }
}

impl std::error::Error for SsrfBlocked {}

/// Walks an error's `source()` chain looking for a block we raised
/// ourselves (from [`SsrfDnsResolver`] or the redirect policy in
/// [`ReqwestHttpClient::new`]), which reqwest re-wraps in its own error
/// types on the way back out of `send()`.
fn find_ssrf_blocked(err: &(dyn std::error::Error + 'static)) -> Option<BlockReason> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(blocked) = e.downcast_ref::<SsrfBlocked>() {
            return Some(blocked.0);
        }
        current = e.source();
    }
    None
}

/// Checks a URL against every requirement that can be decided without a
/// network round trip: scheme, embedded credentials, and (when the host is
/// already a literal IP) address classification.
///
/// This is applied both before the first request and, via the redirect
/// policy, to every redirect target -- a domain name is additionally
/// checked against its resolved address by [`SsrfDnsResolver`], which
/// reqwest consults on every connection it makes, including redirects.
/// Literal-IP hosts skip DNS resolution entirely (reqwest connects
/// directly), so this pre-flight check is the only enforcement point for
/// them.
fn check_url(url: &Url) -> Result<(), SsrfBlocked> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(SsrfBlocked(BlockReason::UnsupportedScheme));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SsrfBlocked(BlockReason::EmbeddedCredentials));
    }
    let literal_ip = match url.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        Some(url::Host::Domain(_)) | None => None,
    };
    if let Some(ip) = literal_ip
        && is_blocked_ip(ip)
    {
        return Err(SsrfBlocked(BlockReason::PrivateAddress));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS resolver: enforces the address check on the address actually connected to
// ---------------------------------------------------------------------------

/// Resolves hostnames and filters out any address in [`is_blocked_ip`].
///
/// reqwest calls this resolver for every hostname it connects to -- the
/// initial request and each redirect hop that targets a domain name -- so
/// the check runs against the address that will actually be dialed, not a
/// separate lookup that could race a second lookup reqwest performs
/// (a DNS-rebinding TOCTOU gap). If every resolved address is blocked, or
/// none remain, resolution fails and the request is refused.
struct SsrfDnsResolver;

impl Resolve for SsrfDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let result = (host.as_str(), 0)
            .to_socket_addrs()
            .map(|addrs| {
                let filtered: Vec<_> = addrs.filter(|addr| !is_blocked_ip(addr.ip())).collect();
                filtered
            })
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .and_then(|addrs| {
                if addrs.is_empty() {
                    Err(Box::new(SsrfBlocked(BlockReason::PrivateAddress))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(Box::new(addrs.into_iter()) as Addrs)
                }
            });
        Box::pin(std::future::ready(result))
    }
}

// ---------------------------------------------------------------------------
// HttpClient adapter
// ---------------------------------------------------------------------------

/// Reqwest-based HTTP client adapter for the `HttpClient` trait.
///
/// Uses a 60-second timeout and 5-redirect limit to match legacy behavior.
///
/// Unsubscribe URLs come from attacker-controlled email headers and, with
/// the planned unattended scheduler, will be fetched with nobody watching
/// the result. This adapter refuses to request loopback, private,
/// link-local, CGNAT, and other non-public address ranges: the check runs
/// against the resolved address (via [`SsrfDnsResolver`]) and is re-applied
/// on every redirect hop (via the custom redirect policy below), so a
/// public hostname that resolves to -- or redirects to -- an internal
/// address is blocked rather than followed. There is no configuration
/// switch to disable this.
///
/// A future iOS adapter built on `URLSession` will need equivalent
/// protection. `URLSession` has no direct equivalent of a pluggable DNS
/// resolver; the likely approach is a custom `URLProtocol` that resolves
/// and validates the address itself before handing off the connection, or
/// low-level `NWConnection` plumbing.
pub struct ReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self> {
        let redirect_policy = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            match check_url(attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(e) => attempt.error(e),
            }
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(redirect_policy)
            .dns_resolver(Arc::new(SsrfDnsResolver))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self { client })
    }

    /// Parses and pre-flight-checks a URL before any request is built.
    fn checked_url(url: &str) -> Result<Url> {
        let parsed = Url::parse(url).with_context(|| format!("invalid URL: {url}"))?;
        check_url(&parsed).map_err(anyhow::Error::from)?;
        Ok(parsed)
    }

    /// Maps a `send()` failure to an `anyhow::Error`.
    ///
    /// A block raised during the request itself -- resolved-address
    /// rejection in [`SsrfDnsResolver`], or a blocked redirect target from
    /// the policy in [`Self::new`] -- arrives here wrapped in reqwest's own
    /// error types. Promote it back to the top-level message so
    /// `UnsubscribeResult::detail` shows "blocked: ..." rather than a
    /// generic "request failed" wrapper; any other failure keeps that
    /// existing wrapper.
    fn map_send_error(err: reqwest::Error, action: &str, url: &str) -> anyhow::Error {
        match find_ssrf_blocked(&err) {
            Some(reason) => anyhow::anyhow!("{} ({url})", reason.detail()),
            None => anyhow::Error::new(err).context(format!("{action} request failed: {url}")),
        }
    }

    /// Reads a response into a `HttpResponse`, capping the body so an
    /// oversized response is never buffered in full.
    ///
    /// Single point where a reqwest `Response` becomes a core `HttpResponse`.
    /// Every response carries the URL it ended on so unsubscribe history can
    /// record where a redirect chain actually landed.
    fn finish_response(resp: reqwest::blocking::Response) -> Result<HttpResponse> {
        let status = resp.status().as_u16();
        let final_url = Some(resp.url().to_string());
        let mut limited = resp.take(MAX_BODY_BYTES + 1);
        let mut buf = Vec::new();
        limited
            .read_to_end(&mut buf)
            .context("failed to read response body")?;
        if buf.len() as u64 > MAX_BODY_BYTES {
            bail!("blocked: response body exceeds {MAX_BODY_BYTES}-byte limit");
        }
        let body = String::from_utf8_lossy(&buf).into_owned();

        Ok(HttpResponse {
            status,
            body,
            final_url,
        })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse> {
        let checked = Self::checked_url(url)?;
        let resp = self
            .client
            .get(checked)
            .send()
            .map_err(|e| Self::map_send_error(e, "GET", url))?;

        Self::finish_response(resp)
    }

    fn get_with_headers(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let checked = Self::checked_url(url)?;
        let mut builder = self.client.get(checked);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder
            .send()
            .map_err(|e| Self::map_send_error(e, "GET", url))?;

        Self::finish_response(resp)
    }

    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<HttpResponse> {
        let checked = Self::checked_url(url)?;
        let resp = self
            .client
            .post(checked)
            .form(params)
            .send()
            .map_err(|e| Self::map_send_error(e, "POST form", url))?;

        Self::finish_response(resp)
    }

    fn post_body(&self, url: &str, content_type: &str, body: &str) -> Result<HttpResponse> {
        let checked = Self::checked_url(url)?;
        let resp = self
            .client
            .post(checked)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .map_err(|e| Self::map_send_error(e, "POST body", url))?;

        Self::finish_response(resp)
    }

    fn post_body_with_headers(
        &self,
        url: &str,
        content_type: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let checked = Self::checked_url(url)?;
        let mut builder = self
            .client
            .post(checked)
            .header("Content-Type", content_type)
            .body(body.to_string());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder
            .send()
            .map_err(|e| Self::map_send_error(e, "POST body", url))?;

        Self::finish_response(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::str::FromStr;

    use unsubscribe_core::{FolderMessage, SenderInfo, UnsubscribeMethod, unsubscribe};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("test IPv4 literal"))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("test IPv6 literal"))
    }

    fn assert_all_blocked(label: &str, addrs: &[IpAddr]) {
        for ip in addrs {
            assert!(is_blocked_ip(*ip), "{label}: {ip} should be blocked");
        }
    }

    fn assert_all_allowed(label: &str, addrs: &[IpAddr]) {
        for ip in addrs {
            assert!(!is_blocked_ip(*ip), "{label}: {ip} should be allowed");
        }
    }

    /// Runs `check_url` on a parsed URL and returns the reason, if any.
    fn block_reason(url: &str) -> Option<BlockReason> {
        let parsed = Url::parse(url).unwrap_or_else(|e| panic!("test URL {url} should parse: {e}"));
        check_url(&parsed).err().map(|SsrfBlocked(reason)| reason)
    }

    fn assert_blocked_url(url: &str, expected: BlockReason) {
        assert_eq!(
            block_reason(url),
            Some(expected),
            "{url} should be refused as {expected:?}"
        );
    }

    fn assert_allowed_url(url: &str) {
        assert_eq!(block_reason(url), None, "{url} should be allowed");
    }

    /// Drives a future that is known to be ready on first poll, so the
    /// resolver can be exercised without pulling in an async runtime.
    fn poll_ready<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("resolver future was not ready on first poll"),
        }
    }

    fn resolve(host: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
        let name = Name::from_str(host).expect("test host should be a valid DNS name");
        poll_ready(SsrfDnsResolver.resolve(name)).map(|addrs| addrs.map(|a| a.ip()).collect())
    }

    /// Error type with a `source()`, for exercising [`find_ssrf_blocked`]'s
    /// chain walk at depth.
    #[derive(Debug)]
    struct Wrapped(Box<dyn std::error::Error + Send + Sync>);

    impl fmt::Display for Wrapped {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }

    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    fn synthetic_response(status: u16, body: Vec<u8>) -> reqwest::blocking::Response {
        let raw = http::Response::builder()
            .status(status)
            .body(body)
            .expect("synthetic response should build");
        reqwest::blocking::Response::from(raw)
    }

    fn sender_with_url(url: &str) -> SenderInfo {
        SenderInfo {
            display_name: "Acme Newsletter".to_string(),
            email: "news@acme.test".to_string(),
            domain: "acme.test".to_string(),
            unsubscribe_urls: vec![url.to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count: 1,
            messages: Vec::<FolderMessage>::new(),
            last_seen: None,
        }
    }

    // -----------------------------------------------------------------------
    // Address classification -- IPv4 blocked ranges
    // -----------------------------------------------------------------------

    #[test]
    fn ipv4_loopback_is_blocked() {
        assert_all_blocked(
            "loopback 127.0.0.0/8",
            &[
                v4("127.0.0.1"),
                v4("127.0.0.0"),
                v4("127.255.255.254"),
                v4("127.255.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_rfc1918_private_ranges_are_blocked() {
        assert_all_blocked(
            "RFC 1918",
            &[
                v4("10.0.0.0"),
                v4("10.0.0.1"),
                v4("10.255.255.255"),
                v4("172.16.0.0"),
                v4("172.16.0.1"),
                v4("172.31.255.255"),
                v4("192.168.0.0"),
                v4("192.168.1.1"),
                v4("192.168.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_link_local_including_cloud_metadata_is_blocked() {
        assert_all_blocked(
            "169.254.0.0/16",
            &[
                v4("169.254.0.0"),
                v4("169.254.0.1"),
                // The AWS/GCP/Azure instance metadata endpoint -- the single
                // most-targeted SSRF destination.
                v4("169.254.169.254"),
                v4("169.254.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_cgnat_range_is_blocked() {
        assert_all_blocked(
            "RFC 6598 100.64.0.0/10",
            &[
                v4("100.64.0.0"),
                v4("100.64.0.1"),
                v4("100.100.100.100"),
                v4("100.127.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_current_network_range_is_blocked() {
        assert_all_blocked(
            "0.0.0.0/8",
            &[
                v4("0.0.0.0"),
                v4("0.0.0.1"),
                // Not just the unspecified address: the whole /8 is "this
                // network" and several stacks route 0.x as loopback.
                v4("0.1.2.3"),
                v4("0.255.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_reserved_and_broadcast_are_blocked() {
        assert_all_blocked(
            "240.0.0.0/4 plus broadcast",
            &[
                v4("240.0.0.0"),
                v4("240.0.0.1"),
                v4("250.1.2.3"),
                v4("255.255.255.254"),
                v4("255.255.255.255"),
            ],
        );
    }

    #[test]
    fn ipv4_multicast_is_blocked() {
        assert_all_blocked(
            "224.0.0.0/4",
            &[
                v4("224.0.0.0"),
                v4("224.0.0.1"),
                v4("232.1.2.3"),
                v4("239.255.255.255"),
            ],
        );
    }

    // -----------------------------------------------------------------------
    // Address classification -- IPv4 allowed, and range boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn ordinary_public_ipv4_is_allowed() {
        assert_all_allowed(
            "public",
            &[
                v4("8.8.8.8"),
                v4("1.1.1.1"),
                v4("93.184.216.34"),
                v4("203.0.113.5"),
                v4("198.51.100.7"),
            ],
        );
    }

    #[test]
    fn rfc1918_boundaries_admit_the_neighbouring_addresses() {
        assert_all_allowed(
            "just outside RFC 1918",
            &[
                v4("9.255.255.255"),
                v4("11.0.0.0"),
                v4("172.15.255.255"),
                v4("172.32.0.0"),
                v4("192.167.255.255"),
                v4("192.169.0.0"),
            ],
        );
        assert_all_blocked(
            "RFC 1918 edges",
            &[
                v4("10.0.0.0"),
                v4("10.255.255.255"),
                v4("172.16.0.0"),
                v4("172.31.255.255"),
            ],
        );
    }

    #[test]
    fn cgnat_boundaries_admit_the_neighbouring_addresses() {
        assert_all_allowed(
            "just outside 100.64.0.0/10",
            &[v4("100.63.255.255"), v4("100.128.0.0")],
        );
        assert_all_blocked(
            "100.64.0.0/10 edges",
            &[v4("100.64.0.0"), v4("100.127.255.255")],
        );
    }

    #[test]
    fn current_network_boundary_admits_the_next_address() {
        assert!(is_blocked_ip(v4("0.255.255.255")), "0.255.255.255 is 0/8");
        assert!(
            !is_blocked_ip(v4("1.0.0.0")),
            "1.0.0.0 is the first public /8"
        );
    }

    #[test]
    fn loopback_boundary_admits_the_neighbouring_addresses() {
        assert_all_allowed(
            "just outside 127/8",
            &[v4("126.255.255.255"), v4("128.0.0.0")],
        );
    }

    #[test]
    fn link_local_boundary_admits_the_neighbouring_addresses() {
        assert_all_allowed(
            "just outside 169.254/16",
            &[v4("169.253.255.255"), v4("169.255.0.0")],
        );
    }

    #[test]
    fn multicast_and_reserved_boundaries_meet_without_a_gap() {
        // 223.255.255.255 is the last public unicast address; everything from
        // 224.0.0.0 up is multicast and then reserved, with no hole between.
        assert!(!is_blocked_ip(v4("223.255.255.255")));
        assert!(is_blocked_ip(v4("224.0.0.0")));
        assert!(is_blocked_ip(v4("239.255.255.255")));
        assert!(is_blocked_ip(v4("240.0.0.0")));
    }

    // -----------------------------------------------------------------------
    // Address classification -- IPv6
    // -----------------------------------------------------------------------

    #[test]
    fn ipv6_loopback_and_unspecified_are_blocked() {
        assert_all_blocked("::1 and ::", &[v6("::1"), v6("::")]);
    }

    #[test]
    fn ipv6_link_local_is_blocked() {
        assert_all_blocked(
            "fe80::/10",
            &[
                v6("fe80::"),
                v6("fe80::1"),
                v6("fe80::a00:27ff:fe4e:66a1"),
                v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ],
        );
    }

    #[test]
    fn ipv6_unique_local_is_blocked() {
        assert_all_blocked(
            "fc00::/7",
            &[
                v6("fc00::"),
                v6("fc00::1"),
                v6("fd12:3456::1"),
                v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ],
        );
    }

    #[test]
    fn ipv6_multicast_is_blocked() {
        assert_all_blocked(
            "ff00::/8",
            &[
                v6("ff00::"),
                v6("ff01::1"),
                v6("ff02::1"),
                v6("ff05::c"),
                v6("ffff::1"),
            ],
        );
    }

    #[test]
    fn ordinary_public_ipv6_is_allowed() {
        assert_all_allowed(
            "public",
            &[
                v6("2001:4860:4860::8888"),
                v6("2606:4700:4700::1111"),
                v6("2a00:1450:4009:81f::200e"),
            ],
        );
    }

    #[test]
    fn ipv6_range_boundaries_admit_the_neighbouring_addresses() {
        // fc00::/7 runs fc00..fdff, fe80::/10 runs fe80..febf.
        assert_all_allowed(
            "just outside the blocked v6 ranges",
            &[
                v6("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                v6("fe00::1"),
                v6("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ],
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_unwrapped_and_classified_as_ipv4() {
        assert_all_blocked(
            "::ffff:0:0/96 wrapping a blocked v4",
            &[
                v6("::ffff:127.0.0.1"),
                v6("::ffff:192.168.1.1"),
                v6("::ffff:10.0.0.1"),
                v6("::ffff:169.254.169.254"),
                v6("::ffff:0.0.0.0"),
                // Same address written in hextet form.
                v6("::ffff:7f00:1"),
            ],
        );
        assert_all_allowed(
            "::ffff:0:0/96 wrapping a public v4",
            &[v6("::ffff:8.8.8.8"), v6("::ffff:93.184.216.34")],
        );
    }

    /// Pins a known limitation: the deprecated IPv4-*compatible* form
    /// (`::a.b.c.d`, RFC 4291 s2.5.5.1) is not unwrapped, only the
    /// IPv4-*mapped* form is. Modern stacks do not auto-tunnel these to the
    /// embedded IPv4 address, so this is not currently reachable, but if
    /// unwrapping is ever widened this test should be updated deliberately.
    #[test]
    fn deprecated_ipv4_compatible_ipv6_is_not_unwrapped() {
        assert!(!is_blocked_ip(v6("::7f00:1")));
    }

    // -----------------------------------------------------------------------
    // URL pre-checks -- scheme
    // -----------------------------------------------------------------------

    #[test]
    fn non_http_schemes_are_refused() {
        for url in [
            "file:///etc/passwd",
            "ftp://ftp.example.com/pub",
            "gopher://example.com:70/1",
            "javascript:alert(1)",
            "data:text/plain,hello",
            "mailto:unsub@example.com",
            "ws://example.com/socket",
        ] {
            assert_blocked_url(url, BlockReason::UnsupportedScheme);
        }
    }

    #[test]
    fn http_and_https_schemes_are_accepted() {
        assert_allowed_url("http://example.com/unsubscribe");
        assert_allowed_url("https://example.com/unsubscribe?token=abc123");
    }

    // -----------------------------------------------------------------------
    // URL pre-checks -- embedded credentials
    // -----------------------------------------------------------------------

    #[test]
    fn urls_with_embedded_credentials_are_refused() {
        for url in [
            "https://user:pass@example.com/unsub",
            "https://user@example.com/unsub",
            "https://:pass@example.com/unsub",
        ] {
            assert_blocked_url(url, BlockReason::EmbeddedCredentials);
        }
    }

    #[test]
    fn an_at_sign_in_the_path_or_query_is_not_a_credential() {
        assert_allowed_url("https://example.com/unsub/user@example.com");
        assert_allowed_url("https://example.com/unsub?email=user@example.com");
    }

    // -----------------------------------------------------------------------
    // URL pre-checks -- IP-literal hosts
    // -----------------------------------------------------------------------

    /// WHATWG URL parsing normalises decimal, hex, octal and short-form IPv4
    /// hosts into a real `Host::Ipv4`. `check_url` depends on that: if the
    /// parser ever left these as `Host::Domain`, they would bypass the literal
    /// check and be handed to DNS instead.
    #[test]
    fn obfuscated_ipv4_literal_hosts_normalise_to_the_loopback_address() {
        let loopback = Some(url::Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        for url in [
            "http://127.0.0.1/",
            "http://2130706433/",   // decimal
            "http://0x7f.0.0.1/",   // hex leading octet
            "http://0x7f000001/",   // hex, single part
            "http://017700000001/", // octal, single part
            "http://127.1/",        // short form
        ] {
            let parsed = Url::parse(url).unwrap_or_else(|e| panic!("{url} should parse: {e}"));
            assert_eq!(
                parsed.host(),
                loopback,
                "{url} should normalise to 127.0.0.1"
            );
        }
    }

    #[test]
    fn obfuscated_ipv4_literal_hosts_are_refused() {
        for url in [
            "http://127.0.0.1/",
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://0x7f000001/",
            "http://017700000001/",
            "http://127.1/",
            "http://0/", // normalises to 0.0.0.0
            "http://10.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert_blocked_url(url, BlockReason::PrivateAddress);
        }
    }

    #[test]
    fn public_ipv4_literal_hosts_are_allowed() {
        assert_allowed_url("http://93.184.216.34/unsub");
        assert_allowed_url("https://8.8.8.8:8443/unsub");
    }

    #[test]
    fn bracketed_ipv6_literal_hosts_are_refused() {
        for url in [
            "http://[::1]/",
            "http://[::1]:8080/admin",
            "http://[::]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[fd12:3456::1]/",
            "http://[ff02::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:192.168.1.1]/",
        ] {
            assert_blocked_url(url, BlockReason::PrivateAddress);
        }
    }

    #[test]
    fn bracketed_public_ipv6_literal_hosts_are_allowed() {
        assert_allowed_url("https://[2606:4700:4700::1111]/unsub");
        assert_allowed_url("https://[2001:4860:4860::8888]:8443/unsub");
    }

    /// `localhost` is a domain name, so the pre-flight check cannot classify
    /// it -- enforcement for it lives in [`SsrfDnsResolver`]. This pins where
    /// the responsibility sits, so a change in either half is visible.
    #[test]
    fn localhost_passes_the_pre_flight_check_and_is_left_to_the_resolver() {
        assert_allowed_url("http://localhost:8080/");
        assert_allowed_url("http://metadata.google.internal/");
    }

    // -----------------------------------------------------------------------
    // DNS resolver filtering
    // -----------------------------------------------------------------------

    #[test]
    fn resolver_refuses_a_name_whose_every_address_is_blocked() {
        // `localhost` resolves from the hosts file -- no network required.
        let err = resolve("localhost").expect_err("localhost must not resolve to a usable address");
        assert_eq!(err.to_string(), "blocked: private network address");
    }

    #[test]
    fn resolver_refuses_literal_blocked_addresses() {
        for host in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "0.0.0.0"] {
            match resolve(host) {
                Err(e) => assert_eq!(e.to_string(), "blocked: private network address", "{host}"),
                Ok(addrs) => panic!("{host} resolved to {addrs:?} instead of being refused"),
            }
        }
    }

    #[test]
    fn resolver_passes_through_public_addresses() {
        // A literal address is resolved by `to_socket_addrs` without a DNS
        // lookup, which keeps this hermetic.
        let addrs = resolve("93.184.216.34").expect("a public address should resolve");
        assert_eq!(addrs, vec![v4("93.184.216.34")]);
    }

    // -----------------------------------------------------------------------
    // Error-chain inspection
    // -----------------------------------------------------------------------

    #[test]
    fn find_ssrf_blocked_finds_a_top_level_block() {
        let err = SsrfBlocked(BlockReason::UnsupportedScheme);
        assert_eq!(
            find_ssrf_blocked(&err),
            Some(BlockReason::UnsupportedScheme)
        );
    }

    #[test]
    fn find_ssrf_blocked_finds_a_block_nested_in_the_source_chain() {
        // reqwest re-wraps our error several layers deep before `send()`
        // returns it.
        let inner = Wrapped(Box::new(SsrfBlocked(BlockReason::PrivateAddress)));
        let outer = Wrapped(Box::new(inner));
        assert_eq!(find_ssrf_blocked(&outer), Some(BlockReason::PrivateAddress));
    }

    #[test]
    fn find_ssrf_blocked_returns_none_for_an_unrelated_chain() {
        let inner = std::io::Error::new(ErrorKind::ConnectionRefused, "connection refused");
        let outer = Wrapped(Box::new(Wrapped(Box::new(inner))));
        assert_eq!(find_ssrf_blocked(&outer), None);
    }

    // -----------------------------------------------------------------------
    // Response body cap
    // -----------------------------------------------------------------------

    #[test]
    fn a_body_under_the_cap_is_returned_verbatim() {
        let resp = ReqwestHttpClient::finish_response(synthetic_response(200, b"ok".to_vec()))
            .expect("a small body should be accepted");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "ok");
    }

    #[test]
    fn a_body_exactly_at_the_cap_is_accepted() {
        let body = vec![b'a'; MAX_BODY_BYTES as usize];
        let resp = ReqwestHttpClient::finish_response(synthetic_response(200, body))
            .expect("a body exactly at the limit should be accepted");
        assert_eq!(resp.body.len(), MAX_BODY_BYTES as usize);
    }

    #[test]
    fn a_body_one_byte_over_the_cap_is_refused() {
        let body = vec![b'a'; MAX_BODY_BYTES as usize + 1];
        let err = ReqwestHttpClient::finish_response(synthetic_response(200, body))
            .expect_err("a body over the limit should be refused");
        assert_eq!(
            err.to_string(),
            "blocked: response body exceeds 2097152-byte limit"
        );
    }

    #[test]
    fn a_grossly_oversized_body_is_refused_rather_than_buffered() {
        let body = vec![b'a'; MAX_BODY_BYTES as usize * 4];
        let err = ReqwestHttpClient::finish_response(synthetic_response(200, body))
            .expect_err("a 8 MiB body should be refused");
        assert!(err.to_string().starts_with("blocked:"), "{err}");
    }

    #[test]
    fn a_non_utf8_body_is_decoded_lossily_rather_than_failing() {
        let resp =
            ReqwestHttpClient::finish_response(synthetic_response(200, vec![0xff, 0xfe, b'h']))
                .expect("invalid UTF-8 must not fail the request");
        assert!(resp.body.ends_with('h'), "{:?}", resp.body);
    }

    #[test]
    fn the_response_records_the_url_it_ended_on() {
        let resp = ReqwestHttpClient::finish_response(synthetic_response(301, Vec::new()))
            .expect("an empty body should be accepted");
        assert_eq!(resp.status, 301);
        assert!(resp.final_url.is_some(), "final_url should be populated");
    }

    // -----------------------------------------------------------------------
    // End-to-end refusal behaviour
    // -----------------------------------------------------------------------

    /// Binds a real listener so the test can assert nothing ever dialled it.
    fn idle_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("listener should go non-blocking");
        let port = listener.local_addr().expect("local addr").port();
        (listener, port)
    }

    fn assert_no_connection(listener: &TcpListener, context: &str) {
        match listener.accept() {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Ok((_, peer)) => panic!("{context}: the client connected from {peer}"),
            Err(e) => panic!("{context}: unexpected accept error: {e}"),
        }
    }

    #[test]
    fn a_get_to_a_loopback_literal_is_refused_without_connecting() {
        let (listener, port) = idle_listener();
        let client = ReqwestHttpClient::new().expect("client should build");

        let err = client
            .get(&format!("http://127.0.0.1:{port}/unsub"))
            .expect_err("a loopback URL must be refused");

        assert_eq!(err.to_string(), "blocked: private network address");
        assert_no_connection(&listener, "loopback literal");
    }

    #[test]
    fn a_get_to_localhost_is_refused_by_the_resolver_with_a_blocked_message() {
        let (listener, port) = idle_listener();
        let client = ReqwestHttpClient::new().expect("client should build");
        let url = format!("http://localhost:{port}/unsub");

        // A domain name clears the pre-flight check, so this exercises the
        // resolver and the error-chain promotion in `map_send_error`.
        let err = client.get(&url).expect_err("localhost must be refused");

        let message = err.to_string();
        assert!(
            message.starts_with("blocked: private network address"),
            "expected a promoted block message, got: {message}"
        );
        assert!(
            message.contains(&url),
            "the message should name the URL: {message}"
        );
        assert_no_connection(&listener, "localhost via resolver");
    }

    #[test]
    fn every_request_method_refuses_a_blocked_url() {
        let client = ReqwestHttpClient::new().expect("client should build");
        let url = "http://169.254.169.254/latest/meta-data/".to_string();

        let attempts: Vec<(&str, Result<HttpResponse>)> = vec![
            ("get", client.get(&url)),
            (
                "get_with_headers",
                client.get_with_headers(&url, &[("X-A", "1")]),
            ),
            (
                "post_form",
                client.post_form(&url, &[("List-Unsubscribe", "One-Click")]),
            ),
            ("post_body", client.post_body(&url, "text/plain", "x")),
            (
                "post_body_with_headers",
                client.post_body_with_headers(&url, "text/plain", "x", &[("X-A", "1")]),
            ),
        ];

        for (name, result) in attempts {
            let err = result
                .err()
                .unwrap_or_else(|| panic!("{name} should refuse {url}"));
            assert_eq!(
                err.to_string(),
                "blocked: private network address",
                "{name}"
            );
        }
    }

    #[test]
    fn an_unparseable_url_is_reported_as_invalid_rather_than_blocked() {
        let client = ReqwestHttpClient::new().expect("client should build");
        let err = client
            .get("not a url at all")
            .expect_err("a malformed URL should fail");
        assert!(
            err.to_string().contains("invalid URL"),
            "expected a parse failure, got: {err}"
        );
    }

    /// A refusal must surface as a failed `UnsubscribeResult` -- the run
    /// continues and the reason is recorded, rather than the batch aborting.
    #[test]
    fn a_blocked_url_yields_a_failed_result_and_does_not_abort_the_run() {
        let (listener, port) = idle_listener();
        let client = ReqwestHttpClient::new().expect("client should build");

        let blocked = sender_with_url(&format!("http://127.0.0.1:{port}/unsub"));
        let metadata = sender_with_url("http://169.254.169.254/latest/meta-data/");
        let senders = [&blocked, &metadata];

        let results = unsubscribe(&senders, &client, None);

        assert_eq!(results.len(), 2, "every sender should produce a result");
        for result in &results {
            assert!(!result.success, "a blocked URL must not count as success");
            assert_eq!(result.method, UnsubscribeMethod::Get);
            assert!(
                result.detail.contains("blocked:"),
                "the detail should say why: {}",
                result.detail
            );
            assert_eq!(result.http_status, None);
        }
        assert_no_connection(&listener, "core unsubscribe run");
    }
}
