//! Deployment configuration read from the environment, and the client-IP resolution it governs.
//!
//! The only setting here is [`TRUSTED_PROXIES_ENV`], but it is a security control rather than a
//! convenience: it decides whether `X-Forwarded-For` and `X-Real-IP` — headers any client can write
//! freely — are allowed to influence the address that `api_keys.bound_ips` is matched against.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

/// Comma-separated list of IPs or CIDRs whose members are allowed to set `X-Forwarded-For` and
/// `X-Real-IP` (e.g. `TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5`).
///
/// **Unset means trust nothing**, which is the safe default but *not* the convenient one: behind a
/// reverse proxy with this unset, every request resolves to the proxy's own address, so a key bound
/// to a real client CIDR will be rejected with `403`. That is the correct failure direction — the
/// alternative is silently honouring a header the client controls — but it does mean a proxied
/// deployment **must** set this variable. See [`resolve_client_ip`].
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

/// Parses a `TRUSTED_PROXIES` value into networks, returning the entries that failed to parse.
///
/// A bare address (`10.0.0.1`) is accepted as a single-host network, since requiring `/32` on every
/// entry is a footgun with no upside. Unparseable entries are *dropped* rather than aborting the
/// whole list: dropping one narrows who is trusted (fails closed), while rejecting the list
/// wholesale would either trust nobody — silently breaking a working deployment over a typo in an
/// unrelated entry — or, worse, tempt a future change into trusting everybody.
///
/// The rejects are returned rather than logged here so the caller decides how loudly to complain;
/// [`trusted_proxies_from_env`] warns once at startup.
pub fn parse_trusted_proxies(raw: &str) -> (Vec<IpNetwork>, Vec<String>) {
    let mut networks = Vec::new();
    let mut rejected = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        // `IpNetwork` parses CIDR form; a bare address is promoted to a single-host network.
        match entry
            .parse::<IpNetwork>()
            .or_else(|_| entry.parse::<IpAddr>().map(IpNetwork::from))
        {
            Ok(net) => networks.push(net),
            Err(_) => rejected.push(entry.to_owned()),
        }
    }

    (networks, rejected)
}

/// Reads and parses [`TRUSTED_PROXIES_ENV`], warning about any entries that could not be parsed.
pub fn trusted_proxies_from_env() -> Vec<IpNetwork> {
    let Ok(raw) = std::env::var(TRUSTED_PROXIES_ENV) else {
        return Vec::new();
    };

    let (networks, rejected) = parse_trusted_proxies(&raw);
    if !rejected.is_empty() {
        tracing::error!(
            "Ignoring {} unparseable {} entr{}: {:?}. These hosts will NOT be trusted to set \
             X-Forwarded-For.",
            rejected.len(),
            TRUSTED_PROXIES_ENV,
            if rejected.len() == 1 { "y" } else { "ies" },
            rejected
        );
    }
    networks
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

    fn nets(entries: &str) -> Vec<IpNetwork> {
        parse_trusted_proxies(entries).0
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address literal parses")
    }

    #[test]
    fn bare_addresses_and_cidrs_both_parse() {
        let (networks, rejected) = parse_trusted_proxies("10.0.0.0/8, 192.168.1.5 ,, ::1");
        assert!(rejected.is_empty(), "all entries are valid");
        assert_eq!(networks.len(), 3, "empty entries are skipped, not counted");
        assert!(networks[1].contains(ip("192.168.1.5")), "a bare address becomes a /32");
        assert!(!networks[1].contains(ip("192.168.1.6")), "...and covers only itself");
    }

    #[test]
    fn unparseable_entries_are_dropped_not_promoted_to_trust() {
        let (networks, rejected) = parse_trusted_proxies("10.0.0.0/8,not-an-ip,999.1.1.1");
        assert_eq!(rejected, vec!["not-an-ip".to_owned(), "999.1.1.1".to_owned()]);
        assert_eq!(networks.len(), 1, "only the valid entry is trusted");
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
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.1"), ("X-Real-IP", "10.0.0.1")]);

        // A hostile client claiming to be the trusted proxy itself still gets its own address used.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // ...including when it claims an address inside a key's bound CIDR.
        let hdrs = headers(&[("X-Forwarded-For", "192.168.1.1")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_peer_may_declare_the_client() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// Rightmost-first is what makes a client-supplied prefix unforgeable: a client that sends
    /// `X-Forwarded-For: 8.8.8.8` gets its real address appended by the proxy, and only that
    /// appended entry is honoured.
    #[test]
    fn a_client_supplied_prefix_is_ignored_in_favour_of_the_proxy_appended_entry() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A chain of trusted proxies: the rightmost entries are proxies, and the first non-proxy
    /// address walking leftwards is the real client.
    #[test]
    fn trusted_hops_are_skipped_walking_right_to_left() {
        let trusted = nets("10.0.0.0/8,172.16.0.0/12");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));

        // A forged address to the left of the real client is still never reached.
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A header naming nothing but proxies carries no information about the client, so the peer is
    /// used rather than an arbitrary pick from the chain.
    #[test]
    fn an_all_proxy_chain_falls_back_to_the_peer() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.2, 10.0.0.3")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn garbage_headers_fall_back_to_the_peer_rather_than_failing_open() {
        let trusted = nets("10.0.0.0/8");
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
        let trusted = nets("10.0.0.0/8");

        let hdrs = headers(&[("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // X-Forwarded-For wins when both are present, so a proxy that sets both cannot be played
        // off against itself.
        let hdrs = headers(&[("X-Forwarded-For", "198.51.100.7"), ("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("198.51.100.7"));
    }

    /// An IPv4-mapped peer must still match an IPv4 `TRUSTED_PROXIES` entry — otherwise a
    /// dual-stack listener silently demotes a configured proxy to untrusted.
    #[test]
    fn ipv4_mapped_addresses_are_normalized_on_both_sides() {
        let trusted = nets("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "::ffff:203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("::ffff:10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }
}
