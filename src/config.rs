//! Deployment configuration read from the environment, and the client-IP resolution it governs.
//!
//! The only setting here is [`TRUSTED_PROXIES_ENV`], but it is a security control rather than a
//! convenience: it decides whether `X-Forwarded-For` and `X-Real-IP` — headers any client can write
//! freely — are allowed to influence the address that `api_keys.bound_ips` is matched against.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;

/// Comma-separated list of IPs, CIDRs, or **hostnames** whose members are allowed to set
/// `X-Forwarded-For` and `X-Real-IP` (e.g. `TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5,traefik`).
///
/// **Unset means trust nothing**, which is the safe default but *not* the convenient one: behind a
/// reverse proxy with this unset, every request resolves to the proxy's own address, so a key bound
/// to a real client CIDR will be rejected with `403`. That is the correct failure direction — the
/// alternative is silently honouring a header the client controls — but it does mean a proxied
/// deployment **must** set this variable. See [`resolve_client_ip`].
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

/// How long a resolved hostname's addresses stay usable before being re-resolved.
///
/// Short on purpose. A container that is recreated keeps its name and gets a new address, and until
/// this expires the old address is still trusted while the new one is not — the first is a (brief)
/// over-trust of an address the orchestrator has probably already reassigned, the second is a
/// visible `403`. 30s keeps both windows small without turning every request into a DNS lookup.
const HOSTNAME_TTL: Duration = Duration::from_secs(30);

/// A `TRUSTED_PROXIES` entry: either a fixed network or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// A literal address or CIDR range, matched directly.
    Network(IpNetwork),
    /// A hostname (`traefik`, `proxy.internal`) resolved via DNS when a peer is checked.
    ///
    /// Kept as a name rather than resolved once at startup because that is the entire point: in
    /// Docker and Kubernetes a service name outlives the address behind it, and a container
    /// restart that changes the IP must not silently stop the proxy from being trusted.
    Hostname(String),
}

/// A hostname's resolved addresses and when they were resolved.
type CachedLookup = (Vec<IpAddr>, Instant);

/// The whole trusted-proxy configuration, including the DNS cache shared across requests.
///
/// Cheap to clone (everything shared is behind an [`Arc`]), so it can live in `AppState` and be
/// cloned per request like the rest of it.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    matchers: Arc<Vec<ProxyMatcher>>,
    /// hostname -> (addresses, resolved-at). Guarded by a plain `RwLock`: entries are tiny, the
    /// lock is never held across an `.await`, and the read path (the common one) does not block.
    cache: Arc<RwLock<HashMap<String, CachedLookup>>>,
}

impl TrustedProxies {
    /// Builds from an already-parsed matcher list.
    pub fn new(matchers: Vec<ProxyMatcher>) -> Self {
        Self { matchers: Arc::new(matchers), cache: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Reads and parses [`TRUSTED_PROXIES_ENV`], warning about entries that could not be parsed.
    pub fn from_env() -> Self {
        let Ok(raw) = std::env::var(TRUSTED_PROXIES_ENV) else {
            return Self::default();
        };

        let (matchers, rejected) = parse_trusted_proxies(&raw);
        if !rejected.is_empty() {
            tracing::error!(
                "Ignoring {} unusable {} entr{}: {:?}. These hosts will NOT be trusted to set \
                 X-Forwarded-For.",
                rejected.len(),
                TRUSTED_PROXIES_ENV,
                if rejected.len() == 1 { "y" } else { "ies" },
                rejected
            );
        }
        Self::new(matchers)
    }

    /// Whether anything at all is trusted. An empty configuration ignores forwarding headers.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// The configured matchers, for startup logging.
    pub fn matchers(&self) -> &[ProxyMatcher] {
        &self.matchers
    }

    /// Whether `ip` is one of the trusted proxies, resolving hostnames as needed.
    ///
    /// Literal networks are checked first and short-circuit, so the common all-CIDR configuration
    /// never touches DNS. Hostname entries are only consulted when no network matched.
    pub async fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);

        let mut hostnames = Vec::new();
        for matcher in self.matchers.iter() {
            match matcher {
                ProxyMatcher::Network(net) if net.contains(ip) => return true,
                ProxyMatcher::Network(_) => {}
                ProxyMatcher::Hostname(name) => hostnames.push(name),
            }
        }

        for name in hostnames {
            if self.resolve(name).await.contains(&ip) {
                return true;
            }
        }

        false
    }

    /// Returns a hostname's addresses, resolving and caching on a miss or an expired entry.
    ///
    /// A resolution failure caches nothing and returns empty: the peer is simply not trusted this
    /// time, and the next request retries. Caching the failure would keep a proxy untrusted through
    /// a transient DNS blip long after it recovered.
    async fn resolve(&self, hostname: &str) -> Vec<IpAddr> {
        if let Ok(cache) = self.cache.read()
            && let Some((addrs, at)) = cache.get(hostname)
            && at.elapsed() < HOSTNAME_TTL
        {
            return addrs.clone();
        }

        // Port 0 — `lookup_host` requires one and it is irrelevant to an address comparison.
        let resolved: Vec<IpAddr> = match tokio::net::lookup_host((hostname, 0)).await {
            Ok(addrs) => addrs.map(|a| normalize_ip(a.ip())).collect(),
            Err(e) => {
                tracing::warn!(
                    "Could not resolve {} entry {hostname:?}: {e}. That proxy is not trusted until \
                     resolution succeeds.",
                    TRUSTED_PROXIES_ENV
                );
                return Vec::new();
            }
        };

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(hostname.to_owned(), (resolved.clone(), Instant::now()));
        }
        resolved
    }
}

/// Parses a `TRUSTED_PROXIES` value into matchers, returning the entries that were unusable.
///
/// Three spellings are accepted, tried in order: a CIDR range (`172.16.0.0/12`), a bare address
/// (`127.0.0.1`, promoted to a single-host network so nobody has to remember `/32`), and otherwise
/// a hostname (`traefik`) resolved at request time.
///
/// Because anything non-numeric becomes a hostname, a *typo* is no longer dropped at parse time —
/// it becomes a name that never resolves, which fails in the same safe direction (that peer is not
/// trusted) and is reported by [`TrustedProxies::resolve`] when it is actually consulted. Only
/// entries that cannot even be a hostname are rejected here.
pub fn parse_trusted_proxies(raw: &str) -> (Vec<ProxyMatcher>, Vec<String>) {
    let mut matchers = Vec::new();
    let mut rejected = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Ok(net) = entry.parse::<IpNetwork>() {
            matchers.push(ProxyMatcher::Network(net));
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            matchers.push(ProxyMatcher::Network(IpNetwork::from(addr)));
        } else if is_plausible_hostname(entry) {
            matchers.push(ProxyMatcher::Hostname(entry.to_owned()));
        } else {
            rejected.push(entry.to_owned());
        }
    }

    (matchers, rejected)
}

/// Whether `entry` could be a DNS name, so obvious garbage is rejected at startup rather than
/// becoming a name that quietly never resolves.
///
/// Deliberately permissive — it rejects shapes that cannot be hostnames rather than trying to be
/// the authority on valid DNS. A near-miss CIDR like `10.0.0.0/99` is caught here (the `/`), which
/// matters: silently treating it as a hostname would hide a real configuration error.
fn is_plausible_hostname(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= 253
        && !entry.starts_with('-')
        && !entry.starts_with('.')
        && !entry.ends_with('-')
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Normalizes an IPv4-mapped IPv6 address (`::ffff:192.168.1.1`) down to its plain IPv4 form.
///
/// Dual-stack listeners and reverse proxies routinely surface IPv4 clients this way. Without this,
/// such a peer would fail to match an IPv4 CIDR in either `bound_ips` or `TRUSTED_PROXIES` — the
/// first causing a spurious `403`, the second silently downgrading a trusted proxy to an untrusted
/// one.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Reports whether `ip` falls inside any of the *literal* trusted networks.
///
/// Used only when walking the `X-Forwarded-For` chain to skip intermediate proxies. Hostname
/// matchers are deliberately not consulted there: that walk runs per header entry, and firing a DNS
/// lookup for each would put resolution latency on the request path for no security gain — the
/// decision that matters (is the *peer* trusted?) has already been made by
/// [`TrustedProxies::contains`], which does resolve hostnames. The consequence is narrow: a chained
/// hop identified only by hostname is treated as a client rather than skipped, which resolves to
/// that hop's address instead of the one behind it. That is the conservative direction — it never
/// trusts an address further left than it should.
fn is_literal_network(ip: IpAddr, trusted: &TrustedProxies) -> bool {
    trusted.matchers().iter().any(|m| match m {
        ProxyMatcher::Network(net) => net.contains(ip),
        ProxyMatcher::Hostname(_) => false,
    })
}

/// Determines the client address to authorize against `bound_ips`.
///
/// **The forwarding headers are only consulted when `peer` — the immediate TCP peer, which cannot
/// be forged — is itself inside `trusted`.** Any other client gets its TCP address used verbatim,
/// no matter what it claims in `X-Forwarded-For`. This is the whole point: `X-Forwarded-For` is a
/// plain request header, so honouring it from an arbitrary peer turns `bound_ips` from a network
/// restriction into a self-asserted one that any caller can satisfy by typing an allowed address
/// into a header.
///
/// When the peer *is* trusted, the header is walked **right to left, skipping addresses that are
/// themselves trusted proxies**, and the first remaining address is the client. Rightmost-first is
/// what makes the prefix unforgeable: each proxy appends the address it actually saw, so entries to
/// the left of the last trusted hop are hearsay supplied by the client. Skipping trusted entries is
/// what makes a *chain* of proxies work — with `client → P1 → P2 → us`, the header reads
/// `client, P1` and the rightmost entry is `P1`, a proxy rather than the client.
///
/// `X-Real-IP` (single-valued, no chain) is consulted only when `X-Forwarded-For` is absent, and
/// under exactly the same trust precondition.
///
/// Falls back to `peer` whenever the headers are absent, unparseable, or contain nothing but
/// trusted proxies — never to an unvalidated claim.
pub async fn resolve_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &TrustedProxies,
) -> IpAddr {
    let peer = normalize_ip(peer);

    // The load-bearing check. Everything below is unreachable for an untrusted caller. This is the
    // one place hostnames are resolved, matching `simply_hook_executor`'s rule that the *peer* —
    // and only the peer — decides whether a forwarding header is evidence.
    if !trusted.contains(peer).await {
        return peer;
    }

    if let Some(forwarded) = headers.get("X-Forwarded-For").and_then(|h| h.to_str().ok()) {
        let client = forwarded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .rev()
            .find(|ip| !is_literal_network(*ip, trusted));

        if let Some(client) = client {
            return client;
        }
        // An X-Forwarded-For listing only trusted proxies (or nothing parseable) tells us nothing
        // about the client; fall through rather than inventing one.
    }

    if let Some(real_ip) = headers
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }

    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                axum::http::HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    fn nets(entries: &str) -> TrustedProxies {
        let (matchers, rejected) = parse_trusted_proxies(entries);
        assert!(rejected.is_empty(), "fixture entries must all be usable: {rejected:?}");
        TrustedProxies::new(matchers)
    }

    /// The literal networks in a parsed configuration, for assertions about parsing itself.
    fn only_networks(entries: &str) -> Vec<IpNetwork> {
        parse_trusted_proxies(entries)
            .0
            .into_iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(n) => Some(n),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address literal parses")
    }

    #[test]
    fn bare_addresses_and_cidrs_both_parse() {
        let networks = only_networks("10.0.0.0/8, 192.168.1.5 ,, ::1");
        assert_eq!(networks.len(), 3, "empty entries are skipped, not counted");
        assert!(networks[1].contains(ip("192.168.1.5")), "a bare address becomes a /32");
        assert!(!networks[1].contains(ip("192.168.1.6")), "...and covers only itself");
    }

    /// Anything that is not an address or CIDR but *could* be a DNS name becomes a hostname
    /// matcher; only shapes that cannot be a hostname at all are rejected outright.
    #[test]
    fn entries_are_classified_as_network_or_hostname_and_garbage_is_rejected() {
        let (matchers, rejected) =
            parse_trusted_proxies("10.0.0.0/8, traefik, proxy.internal ,999.1.1.1");
        assert!(rejected.is_empty(), "all four are usable spellings");
        assert_eq!(
            matchers,
            vec![
                ProxyMatcher::Network("10.0.0.0/8".parse().expect("valid CIDR")),
                ProxyMatcher::Hostname("traefik".to_owned()),
                ProxyMatcher::Hostname("proxy.internal".to_owned()),
                // Not a valid address, but a legal DNS label — treated as a name, which fails safe
                // by never resolving rather than being silently trusted.
                ProxyMatcher::Hostname("999.1.1.1".to_owned()),
            ]
        );

        // A near-miss CIDR must NOT be quietly demoted to a hostname: the `/` makes it impossible
        // as a DNS name, so it surfaces as a configuration error instead of a silent non-match.
        let (matchers, rejected) = parse_trusted_proxies("10.0.0.0/99, 10.0.0.0/8");
        assert_eq!(rejected, vec!["10.0.0.0/99".to_owned()]);
        assert_eq!(matchers.len(), 1, "only the well-formed CIDR is kept");

        // Other impossible shapes.
        let (_, rejected) = parse_trusted_proxies("-leading, trailing-, .dotted, has space");
        assert_eq!(rejected.len(), 4);
    }

    /// A hostname entry must not accidentally satisfy the *literal* network path — that is what
    /// keeps `is_literal_network` (used inside the chain walk) from doing DNS.
    #[test]
    fn hostname_entries_contribute_no_literal_networks() {
        assert!(only_networks("traefik, proxy.internal").is_empty());
        assert_eq!(only_networks("traefik, 172.16.0.0/12").len(), 1);
    }

    /// `localhost` resolves on every platform this runs on, so it exercises the real DNS path —
    /// cache miss, resolution, and a second call served from the cache.
    #[tokio::test]
    async fn a_hostname_entry_is_resolved_and_matched() {
        let trusted = nets("localhost");

        assert!(trusted.contains(ip("127.0.0.1")).await, "localhost must match the loopback peer");
        // Served from cache the second time; the result must be identical.
        assert!(trusted.contains(ip("127.0.0.1")).await);

        assert!(!trusted.contains(ip("203.0.113.9")).await, "an unrelated address must not match");
    }

    /// A name that cannot resolve leaves the peer untrusted rather than erroring or trusting it.
    #[tokio::test]
    async fn an_unresolvable_hostname_trusts_nobody() {
        let trusted = nets("this-host-does-not-exist.invalid");
        assert!(!trusted.contains(ip("127.0.0.1")).await);
        assert!(!trusted.contains(ip("10.0.0.1")).await);
    }

    /// Docker/Traefik shape: a container name alongside the bridge network CIDR. Either may match.
    #[tokio::test]
    async fn docker_style_configuration_matches_by_cidr_or_by_name() {
        let trusted = nets("172.16.0.0/12, localhost");

        assert!(trusted.contains(ip("172.17.0.5")).await, "docker bridge CIDR matches");
        assert!(trusted.contains(ip("127.0.0.1")).await, "the named service matches");
        assert!(!trusted.contains(ip("192.0.2.7")).await, "anything else does not");
    }

    /// A trusted peer identified purely by hostname must still have its forwarding header honoured
    /// — the DNS path has to be wired into resolution, not just into `contains`.
    #[tokio::test]
    async fn a_hostname_identified_proxy_may_declare_the_client() {
        let trusted = nets("localhost");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("127.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));

        // ...and a peer that does not resolve to that name still cannot.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted).await, ip("203.0.113.9"));
    }

    /// The core anti-spoofing property: with no trusted proxies configured, the forwarding headers
    /// are inert no matter what they say.
    #[tokio::test]
    async fn forwarding_headers_are_ignored_when_nothing_is_trusted() {
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8"), ("X-Real-IP", "8.8.8.8")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &TrustedProxies::default()).await, ip("203.0.113.9"));
    }

    /// The same, but from a peer that is merely *not on the list* while others are — the check is
    /// per-peer, not "is anything configured at all".
    #[tokio::test]
    async fn an_untrusted_peer_cannot_spoof_even_when_proxies_are_configured() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.1"), ("X-Real-IP", "10.0.0.1")]);

        // A hostile client claiming to be the trusted proxy itself still gets its own address used.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted).await, ip("203.0.113.9"));

        // ...including when it claims an address inside a key's bound CIDR.
        let hdrs = headers(&[("X-Forwarded-For", "192.168.1.1")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted).await, ip("203.0.113.9"));
    }

    #[tokio::test]
    async fn a_trusted_peer_may_declare_the_client() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));
    }

    /// Rightmost-first is what makes a client-supplied prefix unforgeable: a client that sends
    /// `X-Forwarded-For: 8.8.8.8` gets its real address appended by the proxy, and only that
    /// appended entry is honoured.
    #[tokio::test]
    async fn a_client_supplied_prefix_is_ignored_in_favour_of_the_proxy_appended_entry() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));
    }

    /// A chain of trusted proxies: the rightmost entries are proxies, and the first non-proxy
    /// address walking leftwards is the real client.
    #[tokio::test]
    async fn trusted_hops_are_skipped_walking_right_to_left() {
        let trusted = nets("10.0.0.0/8,172.16.0.0/12");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));

        // A forged address to the left of the real client is still never reached.
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));
    }

    /// A header naming nothing but proxies carries no information about the client, so the peer is
    /// used rather than an arbitrary pick from the chain.
    #[tokio::test]
    async fn an_all_proxy_chain_falls_back_to_the_peer() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.2, 10.0.0.3")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("10.0.0.1"));
    }

    #[tokio::test]
    async fn garbage_headers_fall_back_to_the_peer_rather_than_failing_open() {
        let trusted = nets("10.0.0.0/8");
        for value in ["", "   ", "not-an-ip", ",,,", "8.8.8.8.8"] {
            let hdrs = headers(&[("X-Forwarded-For", value)]);
            assert_eq!(
                resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await,
                ip("10.0.0.1"),
                "unparseable X-Forwarded-For {value:?} must fall back to the peer"
            );
        }
    }

    #[tokio::test]
    async fn real_ip_is_honoured_only_from_a_trusted_peer_and_only_without_xff() {
        let trusted = nets("10.0.0.0/8");

        let hdrs = headers(&[("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted).await, ip("203.0.113.9"));

        // X-Forwarded-For wins when both are present, so a proxy that sets both cannot be played
        // off against itself.
        let hdrs = headers(&[("X-Forwarded-For", "198.51.100.7"), ("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted).await, ip("198.51.100.7"));
    }

    /// An IPv4-mapped peer must still match an IPv4 `TRUSTED_PROXIES` entry — otherwise a
    /// dual-stack listener silently demotes a configured proxy to untrusted.
    #[tokio::test]
    async fn ipv4_mapped_addresses_are_normalized_on_both_sides() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "::ffff:203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("::ffff:10.0.0.1"), &hdrs, &trusted).await, ip("203.0.113.50"));
    }
}
