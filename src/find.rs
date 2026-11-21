//! Local-network enumeration, clamped to /24s.
//!
//! Same policy as the other scanners: every local IPv4 network is clamped to
//! a /24 (never a corporate /16). `--subnet` overrides the detection.

use if_addrs::get_if_addrs;
use std::net::Ipv4Addr;

/// One /24 worth of addresses, 1..=254 (skip .0 and .255).
pub fn hosts_in(prefix: [u8; 3]) -> Vec<Ipv4Addr> {
    (1..=254)
        .map(|last| Ipv4Addr::new(prefix[0], prefix[1], prefix[2], last))
        .collect()
}

/// The /24 prefixes of every local IPv4 address, deduplicated.
pub fn local_prefixes() -> Vec<[u8; 3]> {
    let mut out = Vec::new();
    for iface in get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            if v4.ip.is_loopback() || v4.ip.is_link_local() {
                continue;
            }
            let o = v4.ip.octets();
            out.push([o[0], o[1], o[2]]);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parse a subnet argument: `192.168.1` (prefix) or `192.168.1.0/24`.
pub fn parse_prefix(value: &str) -> Option<[u8; 3]> {
    let prefix = value.split('/').next()?;
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let a: u8 = parts[0].parse().ok()?;
    let b: u8 = parts[1].parse().ok()?;
    let c: u8 = parts[2].parse().ok()?;
    Some([a, b, c])
}

/// Expand the effective subnet list: explicit `--subnet` entries or the
/// detected local /24s.
pub fn effective_prefixes(subnets: &[String]) -> Vec<[u8; 3]> {
    if subnets.is_empty() {
        return local_prefixes();
    }
    let mut out = Vec::new();
    for value in subnets {
        if let Some(prefix) = parse_prefix(value) {
            out.push(prefix);
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefix_and_cidr() {
        assert_eq!(parse_prefix("192.168.1"), Some([192, 168, 1]));
        assert_eq!(parse_prefix("192.168.1.0/24"), Some([192, 168, 1]));
        assert_eq!(parse_prefix("10.0"), None);
        assert_eq!(parse_prefix("999.1.1"), None);
    }

    #[test]
    fn clamps_to_254_hosts() {
        assert_eq!(hosts_in([10, 11, 99]).len(), 254);
    }
}
