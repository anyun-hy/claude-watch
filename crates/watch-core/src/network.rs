//! Versioned Python 3.14 address classification, excluding multicast for egress.
//! Updating this table is a policy change and requires explicit differential fixtures.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_prefix(ip: u32, network: u32, bits: u32) -> bool {
    ip >> (32 - bits) == network >> (32 - bits)
}
fn v4_public(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    if n == 0xc0000009 || n == 0xc000000a {
        return true;
    }
    ![
        (0, 8),
        (0x0a000000, 8),
        (0x7f000000, 8),
        (0xa9fe0000, 16),
        (0xac100000, 12),
        (0xc0000000, 24),
        (0xc0000200, 24),
        (0xc0a80000, 16),
        (0xc6120000, 15),
        (0xc6336400, 24),
        (0xcb007100, 24),
        (0xf0000000, 4),
        (0x64400000, 10),
        (0xe0000000, 4),
    ]
    .iter()
    .any(|&(network, bits)| v4_prefix(n, network, bits))
}
fn v6_prefix(ip: Ipv6Addr, network: &str, bits: u32) -> bool {
    let Ok(network) = network.parse::<Ipv6Addr>() else {
        return false;
    };
    u128::from(ip) >> (128 - bits) == u128::from(network) >> (128 - bits)
}
fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return v4_public(mapped);
    }
    if ip.is_multicast() {
        return false;
    }
    if [
        ("2001:1::1", 128),
        ("2001:1::2", 128),
        ("2001:3::", 32),
        ("2001:4:112::", 48),
        ("2001:20::", 28),
        ("2001:30::", 28),
    ]
    .iter()
    .any(|&(net, bits)| v6_prefix(ip, net, bits))
    {
        return true;
    }
    ![
        ("::", 128),
        ("::1", 128),
        ("64:ff9b:1::", 48),
        ("100::", 64),
        ("2001::", 23),
        ("2001:db8::", 32),
        ("2002::", 16),
        ("3fff::", 20),
        ("fc00::", 7),
        ("fe80::", 10),
    ]
    .iter()
    .any(|&(net, bits)| v6_prefix(ip, net, bits))
}

pub fn public_unicast(value: &str) -> Option<String> {
    let ip = value.parse::<IpAddr>().ok()?;
    match ip {
        IpAddr::V4(v4) => v4_public(v4).then(|| v4.to_string()),
        IpAddr::V6(v6) => v6_public(v6).then(|| v6.to_string()),
    }
}

/// Destination metadata also excludes the reserved ranges used by Python 3.14.
pub fn public_destination(value: &str) -> Option<String> {
    let ip = value.parse::<IpAddr>().ok()?;
    let normalized = public_unicast(value)?;
    if let IpAddr::V6(v) = ip {
        if v.to_ipv4_mapped().is_none()
            && [
                ("::", 8),
                ("100::", 8),
                ("200::", 7),
                ("400::", 6),
                ("800::", 5),
                ("1000::", 4),
                ("4000::", 3),
                ("6000::", 3),
                ("8000::", 3),
                ("a000::", 3),
                ("c000::", 3),
                ("e000::", 4),
                ("f000::", 5),
                ("f800::", 6),
                ("fe00::", 9),
            ]
            .iter()
            .any(|&(network, bits)| v6_prefix(v, network, bits))
        {
            return None;
        }
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_egress_and_preserves_special_exceptions() {
        for ip in [
            "127.0.0.1",
            "100.64.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "ff02::1",
            "::",
            "::1",
            "2001:db8::1",
            "fc00::1",
        ] {
            assert_eq!(public_unicast(ip), None, "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.0.9",
            "192.0.0.10",
            "2001:4860:4860::8888",
            "2001:3::1",
        ] {
            assert_eq!(public_unicast(ip), Some(ip.into()));
        }
        assert_eq!(
            public_unicast("::ffff:8.8.8.8"),
            Some("::ffff:8.8.8.8".into())
        );
    }
}
