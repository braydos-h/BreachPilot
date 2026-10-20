//! bp-allowlist: target allowlist enforcement (IP / CIDR / domain / *.wildcard).
//! Mirrors tools/kernel/allowlist.py + tools/validation_utils.py matcher.
//! Empty union fails closed when required is true. Domains never match CIDR.

use std::net::IpAddr;
use std::str::FromStr;

fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    IpAddr::from_str(t).ok()
}

/// True when child is a strict dot-boundary subdomain of parent.
pub fn is_subdomain(child: &str, parent: &str) -> bool {
    let c = normalize(child);
    let p = normalize(parent);
    if c.is_empty() || p.is_empty() || c == p {
        return false;
    }
    c.len() > p.len() + 1 && c.ends_with(&format!(".{p}"))
}

fn match_one(target: &str, entry: &str) -> bool {
    let t = normalize(target);
    let e = normalize(entry);
    if e.is_empty() || t.is_empty() {
        return false;
    }
    // CIDR entry: IP targets only, never domains.
    if let Ok(net) = e.parse::<IpNet>() {
        let tip = match parse_ip(&t) {
            Some(ip) => ip,
            None => return false,
        };
        return net.contains(tip);
    }
    // Exact IP entry.
    if let Some(eip) = parse_ip(&e) {
        return parse_ip(&t).map(|tip| tip == eip).unwrap_or(false);
    }
    // Wildcard *.example.com: subdomains only.
    if let Some(base) = e.strip_prefix("*.") {
        return t.len() > base.len() + 1 && t.ends_with(&format!(".{base}"));
    }
    // Exact domain.
    t == e
}

/// Minimal CIDR parser (v4 + v6) without external deps.
#[derive(Debug, Clone, Copy)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl FromStr for IpNet {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_s, pre_s) = s.split_once('/').ok_or(())?;
        let addr: IpAddr = ip_s.parse().map_err(|_| ())?;
        let prefix: u8 = pre_s.parse().map_err(|_| ())?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(());
        }
        Ok(Self { addr, prefix })
    }
}

impl IpNet {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let shift = 32 - self.prefix;
                let mask = if shift == 32 { 0 } else { u32::MAX << shift };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let shift = 128 - self.prefix;
                let (n, a) = (u128::from(net), u128::from(addr));
                let mask = if shift == 128 { 0 } else { u128::MAX << shift };
                (n & mask) == (a & mask)
            }
            _ => false,
        }
    }
}

/// Check a single target against entries.
pub fn check(target: &str, entries: &[String], required: bool) -> bool {
    if normalize(target).is_empty() {
        return false;
    }
    if entries.is_empty() {
        return !required;
    }
    entries.iter().any(|e| match_one(target, e))
}

/// Check that every target is authorized.
pub fn check_all(targets: &[String], entries: &[String], required: bool) -> bool {
    if targets.is_empty() {
        return !required;
    }
    targets.iter().all(|t| check(t, entries, required))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn exact_ip() {
        assert!(check("10.0.0.5", &s(&["10.0.0.5"]), true));
        assert!(!check("10.0.0.6", &s(&["10.0.0.5"]), true));
    }

    #[test]
    fn cidr_v4() {
        assert!(check("10.0.0.99", &s(&["10.0.0.0/24"]), true));
        assert!(!check("10.0.1.1", &s(&["10.0.0.0/24"]), true));
        // Domains never match CIDR (no implicit DNS grant).
        assert!(!check("evil.com", &s(&["10.0.0.0/8"]), true));
    }

    #[test]
    fn wildcard_dot_boundary() {
        assert!(check("a.example.com", &s(&["*.example.com"]), true));
        assert!(!check("example.com", &s(&["*.example.com"]), true));
        assert!(!check("notevil.com", &s(&["*.evil.com"]), true));
    }

    #[test]
    fn empty_fails_closed() {
        assert!(!check("10.0.0.1", &[], true));
        assert!(check("10.0.0.1", &[], false));
        assert!(!check_all(&[], &s(&["10.0.0.0/8"]), true));
    }

    #[test]
    fn subdomain_strict() {
        assert!(is_subdomain("a.example.com", "example.com"));
        assert!(!is_subdomain("example.com", "example.com"));
        assert!(!is_subdomain("notexample.com", "example.com"));
    }
}
