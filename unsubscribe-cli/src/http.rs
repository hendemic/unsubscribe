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
    /// Single point where a reqwest `Response` becomes a core `HttpResponse`
    /// -- e.g. `resp.url()` for a future `final_url` field belongs here.
    fn finish_response(resp: reqwest::blocking::Response) -> Result<HttpResponse> {
        let status = resp.status().as_u16();
        let mut limited = resp.take(MAX_BODY_BYTES + 1);
        let mut buf = Vec::new();
        limited
            .read_to_end(&mut buf)
            .context("failed to read response body")?;
        if buf.len() as u64 > MAX_BODY_BYTES {
            bail!("blocked: response body exceeds {MAX_BODY_BYTES}-byte limit");
        }
        let body = String::from_utf8_lossy(&buf).into_owned();

        Ok(HttpResponse { status, body })
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
