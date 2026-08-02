//! Deployment configuration read from the environment, and the client-IP resolution it governs.
//!
//! The only setting here is [`TRUSTED_PROXIES_ENV`], but it is a security control rather than a
//! convenience: it decides whether `X-Forwarded-For` and `X-Real-IP` — headers any client can write
//! freely — are allowed to influence the address that `api_keys.bound_ips` is matched against.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tokio::sync::RwLock;

/// Default listen address: every interface.
const DEFAULT_BIND_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Default listen port.
const DEFAULT_BIND_PORT: u16 = 3000;

/// Resolves the socket address the HTTP server binds to, from `BIND_HOST`/`HOST` and `PORT`.
///
/// Reads the environment and delegates to [`parse_bind_addr`], which holds the logic so it can be
/// unit-tested without mutating process-global state.
///
/// The address was previously hardcoded to `0.0.0.0:3000`, which meant an operator had no way to
/// confine the service to a loopback or management interface short of a firewall — and no way to
/// run a second instance on one host, which the test suite needs in order to assert startup
/// behaviour at all.
pub fn resolve_bind_addr() -> SocketAddr {
    // `BIND_HOST` wins over `HOST` because `HOST` is a widely-used variable that some environments
    // set to something entirely unrelated (a hostname, a build target triple); an operator who sets
    // the explicit name should not have it silently overridden by ambient configuration.
    let host = std::env::var("BIND_HOST").or_else(|_| std::env::var("HOST")).ok();
    let port = std::env::var("PORT").ok();
    parse_bind_addr(host.as_deref(), port.as_deref())
}

/// Builds a listen address from optional raw `host`/`port` strings.
///
/// Both are parsed leniently: an unparseable value logs a warning and falls back to the default
/// rather than aborting startup, matching how the rest of this module treats malformed overrides.
///
/// A host must be a **literal IP address**. Resolving a hostname here could yield several addresses
/// with no principled way to choose between them, and binding the wrong interface is a security
/// problem rather than a convenience one — the opposite of `TRUSTED_PROXIES`, where a name is
/// exactly what is wanted because every address it resolves to is equally trusted.
///
/// Port `0` is passed through deliberately: the OS then assigns an ephemeral free port, which is
/// what a socket-activated deployment or a test harness wants.
pub fn parse_bind_addr(host: Option<&str>, port: Option<&str>) -> SocketAddr {
    let ip = match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(raw) => match raw.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(
                    "Invalid bind host {raw:?} (expected a literal IP address such as 0.0.0.0, \
                     127.0.0.1, or ::) — falling back to {DEFAULT_BIND_HOST}"
                );
                DEFAULT_BIND_HOST
            }
        },
        None => DEFAULT_BIND_HOST,
    };

    let port = match port.map(str::trim).filter(|p| !p.is_empty()) {
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                tracing::warn!(
                    "Invalid PORT {raw:?} — falling back to {DEFAULT_BIND_PORT}"
                );
                DEFAULT_BIND_PORT
            }
        },
        None => DEFAULT_BIND_PORT,
    };

    SocketAddr::new(ip, port)
}

/// Comma-separated list of IPs, CIDRs, or **hostnames** whose members are allowed to set
/// `X-Forwarded-For` and `X-Real-IP` (e.g. `TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5,traefik`).
///
/// **Unset means trust nothing**, which is the safe default but *not* the convenient one: behind a
/// reverse proxy with this unset, every request resolves to the proxy's own address, so a key bound
/// to a real client CIDR will be rejected with `403`. That is the correct failure direction — the
/// alternative is silently honouring a header the client controls — but it does mean a proxied
/// deployment **must** set this variable. See [`resolve_client_ip`].
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

/// How long a successful hostname resolution is reused before being looked up again.
///
/// Short on purpose. A container that is recreated keeps its name and gets a new address, and until
/// this expires the old address is still trusted while the new one is not — the first is a (brief)
/// over-trust of an address the orchestrator has probably already reassigned, the second a visible
/// `403`. 30s keeps both windows small without turning every request into a DNS lookup.
const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a *failed* resolution is remembered before being retried — negative caching.
///
/// Deliberately much shorter than [`POSITIVE_TTL`], because a name that is failing is one an
/// operator is probably in the middle of fixing, but deliberately non-zero, which is the point:
/// without it, every request arriving while a configured hostname is unresolvable triggers its own
/// DNS lookup. A hot path behind a dead name then turns this service into a resolution amplifier —
/// one inbound request becomes one outbound query, at whatever rate the caller chooses — which is a
/// DoS both against the resolver and against this process's own latency. With it, the cost is
/// bounded to one query per name per interval no matter how much traffic arrives.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// How long after boot an initially-unresolvable hostname is given before the failure is reported
/// as persistent.
///
/// A daemon and its reverse proxy usually start together, and the proxy's DNS record may not exist
/// for the first few seconds of the daemon's life. Aborting startup over that would turn an
/// ordinary boot race into a crash loop — and a crash loop is strictly worse than running, because a
/// service that is up with one proxy entry disabled still serves every other caller correctly,
/// while one that is down serves nobody. The entry stays untrusted for the duration (fail closed,
/// for that entry only), and the outcome is logged either way.
const BOOT_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// A `TRUSTED_PROXIES` entry: either a fixed network or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// A literal address or CIDR range, matched directly.
    Network(IpNetwork),
    /// A hostname (`traefik`, `proxy.internal`) resolved via DNS.
    ///
    /// Kept as a name rather than resolved once at startup because that is the entire point: in
    /// Docker and Kubernetes a service name outlives the address behind it, and a container
    /// restart that changes the IP must not silently stop the proxy from being trusted.
    Hostname(String),
}

impl std::fmt::Display for ProxyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(network) => write!(f, "{network}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// One hostname's last resolution attempt.
#[derive(Clone)]
struct HostnameState {
    /// What the name resolved to, empty when the lookup failed.
    addresses: Vec<IpNetwork>,
    /// When the attempt ran.
    attempted_at: Instant,
    /// Whether it produced at least one address.
    resolved: bool,
}

impl HostnameState {
    /// Whether this attempt may still be reused, per the positive/negative TTL split.
    fn is_fresh(&self, positive: Duration, negative: Duration) -> bool {
        let ttl = if self.resolved { positive } else { negative };
        self.attempted_at.elapsed() < ttl
    }
}

/// The merged view every request is matched against, plus the per-hostname state behind it.
#[derive(Default)]
struct ResolutionCache {
    /// Literal networks merged with whatever the hostnames currently resolve to.
    snapshot: Arc<Vec<IpNetwork>>,
    /// Per-hostname attempt state, which is what makes negative caching per-name rather than
    /// all-or-nothing: one dead entry must not force the healthy ones to be re-resolved on its
    /// short retry interval.
    hosts: HashMap<String, HostnameState>,
    /// Whether `snapshot` reflects the current `hosts` map.
    built: bool,
}

/// The set of peers whose forwarding headers are believed.
///
/// Holds the parsed `TRUSTED_PROXIES` specification plus a short-lived cache of resolved hostnames.
/// Cloning shares the cache, so every handler sees one resolution rather than each maintaining its
/// own.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    /// The configuration exactly as written, for logging.
    matchers: Arc<Vec<ProxyMatcher>>,
    /// Literal entries, precomputed. Also the complete answer when no hostnames are configured —
    /// the common case, served for the cost of an `Arc` clone and no lock at all.
    networks: Arc<Vec<IpNetwork>>,
    /// Hostname entries awaiting resolution.
    hostnames: Arc<Vec<String>>,
    /// Reuse window for a successful lookup.
    positive_ttl: Duration,
    /// Reuse window for a failed lookup.
    negative_ttl: Duration,
    cache: Arc<RwLock<ResolutionCache>>,
}

impl std::fmt::Debug for ResolutionCache {
    /// Renders nothing of substance: a `{:?}` of application state should describe what the
    /// operator configured, not which addresses a name happened to resolve to a moment ago.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<resolution cache>")
    }
}

impl TrustedProxies {
    /// Builds from an already-parsed matcher list.
    pub fn new(matchers: Vec<ProxyMatcher>) -> Self {
        let networks: Vec<IpNetwork> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(net) => Some(*net),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect();
        let hostnames: Vec<String> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Hostname(name) => Some(name.clone()),
                ProxyMatcher::Network(_) => None,
            })
            .collect();

        Self {
            matchers: Arc::new(matchers),
            networks: Arc::new(networks),
            hostnames: Arc::new(hostnames),
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            cache: Arc::new(RwLock::new(ResolutionCache::default())),
        }
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

    /// Overrides both DNS reuse windows. Test-facing: a suite cannot wait 30 seconds to observe
    /// that a re-resolution happened, nor 5 to observe that one was suppressed.
    #[cfg(test)]
    pub fn with_ttls(mut self, positive: Duration, negative: Duration) -> Self {
        self.positive_ttl = positive;
        self.negative_ttl = negative;
        self
    }

    /// Whether anything at all is trusted. An empty configuration ignores forwarding headers.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// The configured matchers, for startup logging.
    pub fn matchers(&self) -> &[ProxyMatcher] {
        &self.matchers
    }

    /// The networks to match this request against, resolving hostnames when their cache entry has
    /// expired.
    ///
    /// Returns an [`Arc`] rather than a fresh `Vec` so the steady-state cost is a refcount bump.
    /// The no-hostname case — every deployment that names its proxies by address — never touches
    /// the lock or the resolver at all.
    ///
    /// Resolving the *whole set* into one flat list, rather than testing hostnames lazily on a
    /// per-address basis, is what lets [`resolve_client_ip`] treat a hostname-identified proxy
    /// exactly like a CIDR one while walking the `X-Forwarded-For` chain. A lazy design cannot do
    /// that without a DNS lookup per header entry, and so ends up skipping only the literal hops —
    /// which silently reports the inner proxy as the client in precisely the containerized topology
    /// hostname support exists to serve.
    pub async fn resolved(&self) -> Arc<Vec<IpNetwork>> {
        if self.hostnames.is_empty() {
            return Arc::clone(&self.networks);
        }

        {
            let cache = self.cache.read().await;
            if cache.built
                && self
                    .hostnames
                    .iter()
                    .all(|name| {
                        cache
                            .hosts
                            .get(name)
                            .is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl))
                    })
            {
                return Arc::clone(&cache.snapshot);
            }
        }

        // Re-check under the write lock: several requests can queue behind one expiry, and only the
        // first should pay for the lookup. This is the other half of the anti-amplification
        // property — negative caching bounds retries over time, this bounds them across concurrent
        // requests at one instant.
        let mut cache = self.cache.write().await;
        self.refresh_locked(&mut cache).await;
        Arc::clone(&cache.snapshot)
    }

    /// Re-resolves every hostname whose cached attempt has expired, then rebuilds the snapshot.
    async fn refresh_locked(&self, cache: &mut ResolutionCache) {
        for name in self.hostnames.iter() {
            if cache
                .hosts
                .get(name)
                .is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl))
            {
                continue;
            }

            let addresses = resolve_hostname(name).await;
            let resolved = !addresses.is_empty();
            cache.hosts.insert(
                name.clone(),
                HostnameState { addresses, attempted_at: Instant::now(), resolved },
            );
        }

        let mut merged = (*self.networks).clone();
        for name in self.hostnames.iter() {
            if let Some(state) = cache.hosts.get(name) {
                merged.extend(state.addresses.iter().copied());
            }
        }
        cache.snapshot = Arc::new(merged);
        cache.built = true;
    }

    /// Resolves every configured hostname once at boot, reporting the names that failed.
    ///
    /// Returns the list of unresolvable entries so the caller can decide what to say about them.
    /// It never returns an error and never panics: a name that does not resolve is simply not
    /// trusted, which is the safe direction, and is a per-entry outcome rather than a service-wide
    /// one.
    pub async fn prime(&self) -> Vec<String> {
        if self.hostnames.is_empty() {
            return Vec::new();
        }

        let mut cache = self.cache.write().await;
        // Force a real attempt rather than reusing whatever a concurrent request just cached.
        cache.hosts.clear();
        self.refresh_locked(&mut cache).await;

        self.hostnames
            .iter()
            .filter(|name| !cache.hosts.get(*name).is_some_and(|s| s.resolved))
            .cloned()
            .collect()
    }

    /// Primes the set at boot and, if anything failed to resolve, retries once after
    /// [`BOOT_GRACE_PERIOD`] on a detached task.
    ///
    /// The service is fully operational throughout — the unresolved entries are simply untrusted
    /// until they resolve, and normal per-request refresh will pick them up whenever they start
    /// working. The grace retry exists so the *logs* distinguish a boot race that healed itself
    /// from a genuine misconfiguration, without an operator having to correlate timestamps.
    pub fn prime_with_grace(&self) {
        let proxies = self.clone();
        tokio::spawn(async move {
            let failed = proxies.prime().await;
            if failed.is_empty() {
                if !proxies.hostnames.is_empty() {
                    tracing::info!(
                        "All {} {} hostname entr{} resolved at startup.",
                        proxies.hostnames.len(),
                        TRUSTED_PROXIES_ENV,
                        if proxies.hostnames.len() == 1 { "y" } else { "ies" }
                    );
                }
                return;
            }

            tracing::error!(
                "{} hostname entr{} did not resolve at startup: {:?}. Those peers are NOT trusted \
                 and their forwarding headers will be ignored; every other entry is unaffected and \
                 the service is serving normally. Retrying in {}s.",
                TRUSTED_PROXIES_ENV,
                if failed.len() == 1 { "y" } else { "ies" },
                failed,
                BOOT_GRACE_PERIOD.as_secs()
            );

            tokio::time::sleep(BOOT_GRACE_PERIOD).await;
            let still_failing = proxies.prime().await;
            if still_failing.is_empty() {
                tracing::info!(
                    "All {} hostname entries resolved after the {}s grace period; \
                     they are trusted from now on.",
                    TRUSTED_PROXIES_ENV,
                    BOOT_GRACE_PERIOD.as_secs()
                );
            } else {
                tracing::error!(
                    "{} hostname entr{} still unresolvable after the {}s grace period: {:?}. \
                     Continuing to serve with {} entr{} disabled — check the name and the \
                     resolver. Resolution is retried automatically; no restart is required.",
                    TRUSTED_PROXIES_ENV,
                    if still_failing.len() == 1 { "y" } else { "ies" },
                    BOOT_GRACE_PERIOD.as_secs(),
                    still_failing,
                    still_failing.len(),
                    if still_failing.len() == 1 { "y" } else { "ies" }
                );
            }
        });
    }
}

/// Resolves one hostname to the host routes it currently names.
///
/// A failure yields nothing rather than propagating: an unresolvable name means "this proxy is not
/// currently trusted", which is the safe direction to fail in. A DNS outage must never be able to
/// *widen* what the daemon believes, and a container that is down should stop being trusted rather
/// than keep a stale grant alive.
async fn resolve_hostname(hostname: &str) -> Vec<IpNetwork> {
    // Port 0: `lookup_host` wants a socket address, but only the address half is used.
    match tokio::net::lookup_host((hostname, 0u16)).await {
        Ok(addrs) => {
            let networks: Vec<IpNetwork> =
                addrs.map(|addr| IpNetwork::from(normalize_ip(addr.ip()))).collect();
            if networks.is_empty() {
                tracing::warn!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to no addresses; it is not \
                     trusted until it does."
                );
            } else {
                tracing::debug!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to {}",
                    networks.iter().map(|n| n.ip().to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            networks
        }
        Err(e) => {
            tracing::warn!(
                "Could not resolve TRUSTED_PROXIES hostname {hostname:?}: {e}. It is not trusted \
                 until resolution succeeds."
            );
            Vec::new()
        }
    }
}

/// Parses a `TRUSTED_PROXIES` value into matchers, returning the entries that were unusable.
///
/// Three spellings are accepted, tried in order: a CIDR range (`172.16.0.0/12`), a bare address
/// (`127.0.0.1`, promoted to a single-host network so nobody has to remember `/32`), and otherwise
/// a hostname (`traefik`) resolved at request time.
///
/// A malformed entry is dropped with a warning rather than aborting startup. The failure mode is
/// deliberately the safe one: a dropped entry means a proxy is *not* trusted, so requests through it
/// are evaluated against its own address instead of a header it forwarded.
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
/// Deliberately strict about the two shapes that are *nearly* addresses. An entry reaching this
/// point already failed to parse as an address and as a CIDR, and the ways that happens are a typo
/// and a hostname:
///
/// - Anything containing `/` or `:` is refused, since those characters appear only in prefix and
///   IPv6 syntax — so a near-miss CIDR like `10.0.0.0/99` surfaces as the configuration error it is
///   rather than a name that silently never matches.
/// - Anything made only of digits and dots is refused for the same reason: `10.0.0.256` is a
///   mistyped IPv4 literal, not a hostname, and treating it as one would hide the typo behind a
///   perfectly quiet non-match.
fn is_plausible_hostname(entry: &str) -> bool {
    if entry.is_empty() || entry.len() > 253 {
        return false;
    }
    if entry.starts_with('-') || entry.starts_with('.') || entry.ends_with('-') {
        return false;
    }
    if entry.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    entry
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

/// Reports whether `ip` falls inside any of the `trusted` networks.
fn is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    trusted.iter().any(|net| net.contains(ip))
}

/// Determines the client address to authorize against `bound_ips`, and to record in the audit trail.
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
/// `trusted` is the resolved snapshot from [`TrustedProxies::resolved`], so hostname-configured and
/// CIDR-configured hops are indistinguishable here and both are skipped.
///
/// `X-Real-IP` (single-valued, no chain) is consulted only when `X-Forwarded-For` is absent or
/// yields nothing, under exactly the same trust precondition.
///
/// Falls back to `peer` whenever the headers are absent, unparseable, or contain nothing but
/// trusted proxies — never to an unvalidated claim.
///
/// This function is byte-for-byte the same algorithm as `simply_hook_executor`'s; see
/// `scripts/verify_convergence.sh`, which diffs the two mechanically so drift is caught by CI
/// rather than by the next audit.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[IpNetwork],
) -> IpAddr {
    let peer = normalize_ip(peer);

    // The load-bearing check. Everything below is unreachable for an untrusted caller.
    if !is_trusted(peer, trusted) {
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
            .find(|ip| !is_trusted(*ip, trusted));

        if let Some(client) = client {
            return client;
        }
        // A header listing only trusted proxies (or nothing parseable) says nothing about the
        // client; fall through rather than inventing one.
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

    fn proxies(entries: &str) -> TrustedProxies {
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

    #[test]
    fn entries_are_classified_as_network_or_hostname_and_garbage_is_rejected() {
        let (matchers, rejected) = parse_trusted_proxies("10.0.0.0/8, traefik, proxy.internal");
        assert!(rejected.is_empty(), "all three are usable spellings");
        assert_eq!(
            matchers,
            vec![
                ProxyMatcher::Network("10.0.0.0/8".parse().expect("valid CIDR")),
                ProxyMatcher::Hostname("traefik".to_owned()),
                ProxyMatcher::Hostname("proxy.internal".to_owned()),
            ]
        );

        // A near-miss CIDR must NOT be quietly demoted to a hostname: the `/` makes it impossible
        // as a DNS name, so it surfaces as a configuration error instead of a silent non-match.
        let (matchers, rejected) = parse_trusted_proxies("10.0.0.0/99, 10.0.0.0/8");
        assert_eq!(rejected, vec!["10.0.0.0/99".to_owned()]);
        assert_eq!(matchers.len(), 1, "only the well-formed CIDR is kept");

        // Nor may a mistyped IPv4 literal become a hostname — the same reasoning, and the case the
        // peer service already rejected while this one did not.
        for typo in ["999.1.1.1", "10.0.0.256", "1.2.3.4.5", "10..0.1"] {
            let (matchers, rejected) = parse_trusted_proxies(typo);
            assert!(matchers.is_empty(), "{typo:?} must not become a matcher");
            assert_eq!(rejected, vec![typo.to_owned()], "{typo:?} must be reported");
        }

        // Other impossible shapes.
        let (_, rejected) = parse_trusted_proxies("-leading, trailing-, .dotted, has space");
        assert_eq!(rejected.len(), 4);
    }

    #[test]
    fn hostname_entries_contribute_no_literal_networks() {
        assert!(only_networks("traefik, proxy.internal").is_empty());
        assert_eq!(only_networks("traefik, 172.16.0.0/12").len(), 1);
    }

    #[tokio::test]
    async fn resolution_is_a_no_op_when_only_addresses_are_configured() {
        let trusted = proxies("127.0.0.1,10.0.0.0/8");
        let resolved = trusted.resolved().await;
        assert_eq!(resolved.len(), 2);
        assert!(is_trusted(ip("10.1.2.3"), &resolved));
        // Same allocation each time: the no-hostname path must not rebuild or lock anything.
        assert!(Arc::ptr_eq(&resolved, &trusted.resolved().await));
    }

    /// `localhost` resolves on every platform this runs on, so it exercises the real DNS path —
    /// cache miss, resolution, and a second call served from the cache.
    #[tokio::test]
    async fn a_hostname_entry_is_resolved_and_matched() {
        let trusted = proxies("localhost");
        let resolved = trusted.resolved().await;

        assert!(
            is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
            "localhost should resolve to a loopback address: {resolved:?}"
        );
        // Served from cache the second time: the same allocation, no second lookup.
        assert!(Arc::ptr_eq(&resolved, &trusted.resolved().await));

        assert!(!is_trusted(ip("203.0.113.9"), &resolved), "an unrelated address must not match");
    }

    /// Docker/Traefik shape: a container name alongside the bridge network CIDR. Either may match.
    #[tokio::test]
    async fn docker_style_configuration_matches_by_cidr_or_by_name() {
        let trusted = proxies("172.16.0.0/12, localhost").resolved().await;

        assert!(is_trusted(ip("172.17.0.5"), &trusted), "docker bridge CIDR matches");
        assert!(is_trusted(ip("127.0.0.1"), &trusted), "the named service matches");
        assert!(!is_trusted(ip("192.0.2.7"), &trusted), "anything else does not");
    }

    /// Failing closed matters: a DNS outage must never be able to *widen* what is trusted, and it
    /// must not take the healthy entries down with it.
    #[tokio::test]
    async fn an_unresolvable_hostname_trusts_nobody_but_disables_only_itself() {
        let trusted = proxies("this-host-does-not-exist.invalid, 10.0.0.0/8");
        let resolved = trusted.resolved().await;

        assert!(is_trusted(ip("10.1.2.3"), &resolved), "the literal entry still applies");
        assert_eq!(resolved.len(), 1, "the unresolvable name contributes nothing: {resolved:?}");
        assert!(!is_trusted(ip("127.0.0.1"), &resolved));
    }

    /// Negative caching: a name that cannot resolve must not be looked up again on the very next
    /// request. Without this, traffic arriving while a hostname is down becomes one DNS query per
    /// request — a resolution storm this service would be amplifying on someone else's behalf.
    #[tokio::test]
    async fn a_failed_resolution_is_negatively_cached_rather_than_retried_per_request() {
        let trusted = proxies("this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::from_secs(30));

        let first = trusted.resolved().await;
        // Within the negative TTL every further call is served from cache — same allocation, so no
        // second lookup happened.
        assert!(Arc::ptr_eq(&first, &trusted.resolved().await));
        assert!(Arc::ptr_eq(&first, &trusted.resolved().await));
        assert!(first.is_empty());
    }

    /// ...but the negative entry does expire, so a name that starts working is picked up without a
    /// restart. That is the property that makes container addresses usable at all.
    #[tokio::test]
    async fn a_negative_entry_expires_so_recovery_needs_no_restart() {
        let trusted = proxies("this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::ZERO);

        let first = trusted.resolved().await;
        assert!(!Arc::ptr_eq(&first, &trusted.resolved().await), "a zero negative TTL re-resolves");
    }

    /// ...and so does a *successful* one, which is the direction that actually carries risk.
    ///
    /// [`POSITIVE_TTL`] is the window during which a recreated container keeps its **old** address
    /// trusted — an address the orchestrator may already have handed to something else. An entry
    /// that never lapsed would be a standing grant to whoever inherited it, clearable only by
    /// restarting the service. `AGENT.MD` accepts 30s precisely *because* it expires.
    ///
    /// Both halves are asserted, because each alone is too weak:
    ///
    /// - [`HostnameState::is_fresh`] is checked directly against a synthesized `attempted_at`, so
    ///   the predicate is pinned with no dependence on wall-clock timing. The third assertion is the
    ///   load-bearing one: a *resolved* entry must be governed by the positive TTL even when the
    ///   negative TTL is enormous, which is what stops the two windows from being silently swapped.
    /// - `resolved()` is then driven end to end, since `is_fresh` being correct buys nothing if the
    ///   cache never consults it.
    ///
    /// The sleep is four times the TTL rather than a hair over it: this suite runs in parallel, and
    /// a margin measured in whole multiples is what keeps the test from failing on a loaded machine.
    #[tokio::test]
    async fn a_successful_resolution_is_re_queried_once_its_positive_ttl_expires() {
        const POSITIVE: Duration = Duration::from_millis(50);
        const NEGATIVE: Duration = Duration::from_secs(5);

        let fresh = HostnameState {
            addresses: vec![IpNetwork::from(ip("127.0.0.1"))],
            attempted_at: Instant::now(),
            resolved: true,
        };
        assert!(fresh.is_fresh(POSITIVE, NEGATIVE), "an attempt made just now is reusable");

        let lapsed = HostnameState {
            attempted_at: Instant::now()
                .checked_sub(POSITIVE)
                .expect("the monotonic clock is older than the TTL"),
            ..fresh.clone()
        };
        assert!(!lapsed.is_fresh(POSITIVE, NEGATIVE), "an attempt one full TTL old is stale");
        assert!(
            !lapsed.is_fresh(POSITIVE, Duration::from_secs(3600)),
            "a resolved entry must expire on the positive TTL, never on the negative one"
        );

        // End to end: the cache must actually act on that.
        let trusted = proxies("localhost").with_ttls(POSITIVE, NEGATIVE);
        let first = trusted.resolved().await;
        assert!(
            !first.is_empty(),
            "localhost must resolve, or this test would be exercising the negative path instead"
        );

        tokio::time::sleep(POSITIVE * 4).await;

        // A new allocation means `refresh_locked` ran: `resolved()` hands back the *same* `Arc`
        // whenever every entry is still fresh, so pointer inequality is the re-query.
        assert!(
            !Arc::ptr_eq(&first, &trusted.resolved().await),
            "an expired positive entry must be looked up again rather than trusted indefinitely"
        );
    }

    /// A healthy name must not be dragged onto the short negative interval by an unhealthy one
    /// sharing the configuration — the reason attempt state is tracked per hostname.
    #[tokio::test]
    async fn a_healthy_hostname_keeps_its_positive_ttl_alongside_a_failing_one() {
        let trusted = proxies("localhost, this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::ZERO);

        let resolved = trusted.resolved().await;
        assert!(
            is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
            "the healthy entry resolved"
        );
        // The failing entry is re-attempted (zero negative TTL), and `localhost` is still trusted
        // afterwards — it was reused from cache rather than being re-resolved and possibly lost.
        let again = trusted.resolved().await;
        assert!(is_trusted(ip("127.0.0.1"), &again) || is_trusted(ip("::1"), &again));
    }

    /// Boot priming reports exactly which entries failed, so the caller can log a specific name
    /// rather than a generic "something is wrong".
    #[tokio::test]
    async fn priming_reports_only_the_entries_that_failed() {
        assert!(proxies("10.0.0.0/8").prime().await.is_empty(), "no hostnames, nothing to report");
        assert!(proxies("localhost").prime().await.is_empty(), "a resolvable name is not reported");

        let failed = proxies("localhost, this-host-does-not-exist.invalid, 10.0.0.0/8")
            .prime()
            .await;
        assert_eq!(failed, vec!["this-host-does-not-exist.invalid".to_owned()]);
    }

    /// The service must come up regardless — priming is diagnostics, never a gate.
    #[tokio::test]
    async fn priming_a_wholly_unresolvable_configuration_still_leaves_a_usable_set() {
        let trusted = proxies("this-host-does-not-exist.invalid, 192.0.2.0/24");
        let failed = trusted.prime().await;
        assert_eq!(failed.len(), 1);

        let resolved = trusted.resolved().await;
        assert!(is_trusted(ip("192.0.2.7"), &resolved), "the literal entry serves normally");
    }

    /// The core anti-spoofing property: with no trusted proxies configured, the forwarding headers
    /// are inert no matter what they say.
    #[test]
    fn forwarding_headers_are_ignored_when_nothing_is_trusted() {
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8"), ("X-Real-IP", "8.8.8.8")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &[]), ip("203.0.113.9"));
    }

    /// The same, but from a peer that is merely *not on the list* while others are — the check is
    /// per-peer, not "is anything configured at all".
    #[test]
    fn an_untrusted_peer_cannot_spoof_even_when_proxies_are_configured() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.1"), ("X-Real-IP", "10.0.0.1")]);

        // A hostile client claiming to be the trusted proxy itself still gets its own address used.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // ...including when it claims an address inside a key's bound CIDR.
        let hdrs = headers(&[("X-Forwarded-For", "192.168.1.1")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_peer_may_declare_the_client() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// Rightmost-first is what makes a client-supplied prefix unforgeable: a client that sends
    /// `X-Forwarded-For: 8.8.8.8` gets its real address appended by the proxy, and only that
    /// appended entry is honoured.
    #[test]
    fn a_client_supplied_prefix_is_ignored_in_favour_of_the_proxy_appended_entry() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A chain of trusted proxies: the rightmost entries are proxies, and the first non-proxy
    /// address walking leftwards is the real client.
    #[test]
    fn trusted_hops_are_skipped_walking_right_to_left() {
        let trusted = only_networks("10.0.0.0/8,172.16.0.0/12");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));

        // A forged address to the left of the real client is still never reached.
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// The convergence fix: a hop identified by *hostname* must be skipped exactly like a CIDR one.
    /// Resolving the whole set up front is what makes this possible — the previous lazy design
    /// consulted only literal networks during the walk and so reported the inner proxy as the
    /// client in a chained container topology.
    #[tokio::test]
    async fn a_hostname_identified_hop_is_skipped_like_a_cidr_hop() {
        // `localhost` stands in for a container name; it resolves to the loopback address, which
        // therefore appears in the chain as a trusted hop that must be peeled.
        let trusted = proxies("localhost, 172.16.0.0/12").resolved().await;

        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 127.0.0.1")]);
        assert_eq!(
            resolve_client_ip(ip("172.16.0.9"), &hdrs, &trusted),
            ip("203.0.113.50"),
            "the name-resolved hop must be peeled, not reported as the client"
        );

        // Both orders of the chain behave the same way.
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 127.0.0.1")]);
        assert_eq!(resolve_client_ip(ip("127.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A trusted peer identified purely by hostname must still have its forwarding header honoured.
    #[tokio::test]
    async fn a_hostname_identified_proxy_may_declare_the_client() {
        let trusted = proxies("localhost").resolved().await;
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("127.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));

        // ...and a peer that does not resolve to that name still cannot.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));
    }

    /// A header naming nothing but proxies carries no information about the client, so the peer is
    /// used rather than an arbitrary pick from the chain.
    #[test]
    fn an_all_proxy_chain_falls_back_to_the_peer() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.2, 10.0.0.3")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn garbage_headers_fall_back_to_the_peer_rather_than_failing_open() {
        let trusted = only_networks("10.0.0.0/8");
        for value in ["", "   ", "not-an-ip", ",,,", "8.8.8.8.8"] {
            let hdrs = headers(&[("X-Forwarded-For", value)]);
            assert_eq!(
                resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted),
                ip("10.0.0.1"),
                "unparseable X-Forwarded-For {value:?} must fall back to the peer"
            );
        }
    }

    #[test]
    fn real_ip_is_honoured_only_from_a_trusted_peer_and_only_without_xff() {
        let trusted = only_networks("10.0.0.0/8");

        let hdrs = headers(&[("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // X-Forwarded-For wins when both are present, so a proxy that sets both cannot be played
        // off against itself.
        let hdrs = headers(&[("X-Forwarded-For", "198.51.100.7"), ("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("198.51.100.7"));
    }

    #[test]
    fn bind_addr_defaults_to_all_interfaces_on_3000() {
        assert_eq!(parse_bind_addr(None, None).to_string(), "0.0.0.0:3000");
        // Empty strings are treated as "unset", so an unset variable in a unit or compose file
        // behaves the same as an absent one.
        assert_eq!(parse_bind_addr(Some(""), Some("  ")).to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn bind_addr_honors_host_and_port_overrides() {
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("8080")).to_string(), "127.0.0.1:8080");
        assert_eq!(
            parse_bind_addr(Some(" 127.0.0.1 "), Some(" 8080 ")).to_string(),
            "127.0.0.1:8080"
        );
        // Port 0 is passed through so the OS can assign an ephemeral port.
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("0")).to_string(), "127.0.0.1:0");
        // IPv6 literals bind too.
        let addr = parse_bind_addr(Some("::1"), Some("9000"));
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn bind_addr_falls_back_on_malformed_values() {
        // A hostname is not a literal IP and is rejected rather than resolved — several addresses
        // with no principled way to choose, and binding the wrong interface is a security problem.
        assert_eq!(parse_bind_addr(Some("localhost"), Some("8080")).to_string(), "0.0.0.0:8080");
        assert_eq!(
            parse_bind_addr(Some("127.0.0.1"), Some("not-a-port")).to_string(),
            "127.0.0.1:3000"
        );
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("70000")).to_string(), "127.0.0.1:3000");
        assert_eq!(parse_bind_addr(Some("999.1.1.1"), Some("-1")).to_string(), "0.0.0.0:3000");
    }

    /// An IPv4-mapped peer must still match an IPv4 `TRUSTED_PROXIES` entry — otherwise a
    /// dual-stack listener silently demotes a configured proxy to untrusted.
    #[test]
    fn ipv4_mapped_addresses_are_normalized_on_both_sides() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "::ffff:203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("::ffff:10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }
}
