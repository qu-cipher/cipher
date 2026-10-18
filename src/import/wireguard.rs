//! WireGuard `.conf` files (the wg-quick format) → [`Profile::WireGuard`].

use crate::engine::singbox::{
    config::endpoint::{WireguardEndpoint, WireguardPeer},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, uri::split_host_port};
use crate::profile::Profile;

pub(crate) const DEFAULT_ALLOWED_IPS: [&str; 2] = ["0.0.0.0/0", "::/0"];

/// AmneziaWG obfuscation keys. sing-box can't speak AmneziaWG, so these configs would never connect.
const AMNEZIA_KEYS: [&str; 9] = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse_wireguard_conf(text: &str, name: &str) -> Result<Profile, ImportError> {
    let mut endpoint = WireguardEndpoint { tag: PROXY_TAG.into(), ..Default::default() };
    let mut section = Section::None;

    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    endpoint.peers.push(WireguardPeer::default());
                    Section::Peer
                }
                _ => Section::None,
            };
            continue;
        }

        // Keys are base64 and end in `=`, so split on the first one only.
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match section {
            Section::Interface => match key.as_str() {
                "privatekey" => endpoint.private_key = value.into(),
                "address" => endpoint.address.extend(list(value).map(interface_address)),
                "mtu" => endpoint.mtu = Some(number(value, "MTU")?),
                "listenport" => endpoint.listen_port = Some(number(value, "ListenPort")?),
                key if AMNEZIA_KEYS.contains(&key) => {
                    return Err(ImportError::Unsupported("AmneziaWG config".into()));
                }
                // DNS, Table, PostUp, … don't apply: sing-box handles DNS and routing.
                _ => {}
            },
            Section::Peer => {
                let peer = endpoint.peers.last_mut().expect("pushed when [Peer] was read");
                match key.as_str() {
                    "publickey" => peer.public_key = value.into(),
                    "presharedkey" => peer.pre_shared_key = Some(value.into()),
                    "allowedips" => peer.allowed_ips.extend(list(value).map(String::from)),
                    "persistentkeepalive" => peer.persistent_keepalive_interval = Some(number(value, "PersistentKeepalive")?),
                    "endpoint" => {
                        let (host, port) = split_host_port(value)?;
                        peer.address = host.into();
                        peer.port = number(port, "Endpoint port")?;
                    }
                    _ => {}
                }
            }
            Section::None => {}
        }
    }

    if endpoint.private_key.is_empty() {
        return Err(ImportError::Missing("[Interface] PrivateKey"));
    }
    if endpoint.address.is_empty() {
        return Err(ImportError::Missing("[Interface] Address"));
    }
    if endpoint.peers.is_empty() {
        return Err(ImportError::Missing("[Peer] section"));
    }
    for peer in &mut endpoint.peers {
        if peer.public_key.is_empty() {
            return Err(ImportError::Missing("[Peer] PublicKey"));
        }
        if peer.address.is_empty() {
            return Err(ImportError::Missing("[Peer] Endpoint"));
        }
        if peer.allowed_ips.is_empty() {
            peer.allowed_ips = DEFAULT_ALLOWED_IPS.map(String::from).to_vec();
        }
    }

    Ok(Profile::WireGuard { name: name.into(), endpoint })
}

/// Bare interface IPs get a host prefix (`10.0.0.2` → `10.0.0.2/32`).
pub(crate) fn interface_address(address: &str) -> String {
    match (address.contains('/'), address.contains(':')) {
        (true, _) => address.into(),
        (false, true) => format!("{address}/128"),
        (false, false) => format!("{address}/32"),
    }
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty())
}

fn number<T: std::str::FromStr>(value: &str, what: &str) -> Result<T, ImportError> {
    value.parse().map_err(|_| ImportError::Invalid(format!("{what} `{value}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "\
[Interface]
# laptop
PrivateKey = eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
Address = 10.0.0.2, fd00::2/128
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
PresharedKey = 31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=
Endpoint = [2001:db8::1]:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";

    #[test]
    fn parses_wg_quick_conf() {
        let Profile::WireGuard { name, endpoint } = parse_wireguard_conf(CONF, "Home").unwrap() else {
            panic!("not a WireGuard profile");
        };
        assert_eq!(name, "Home");
        assert_eq!(endpoint.private_key, "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=");
        assert_eq!(endpoint.address, ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(endpoint.mtu, Some(1380));

        let peer = &endpoint.peers[0];
        assert_eq!(peer.public_key, "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=");
        assert_eq!(peer.pre_shared_key.as_deref(), Some("31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM="));
        assert_eq!(peer.address, "2001:db8::1");
        assert_eq!(peer.port, 51820);
        assert_eq!(peer.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(peer.persistent_keepalive_interval, Some(25));
    }

    #[test]
    fn rejects_incomplete_conf() {
        let no_peer = "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/32\n";
        assert!(matches!(parse_wireguard_conf(no_peer, "x"), Err(ImportError::Missing("[Peer] section"))));

        let no_endpoint = format!("{no_peer}[Peer]\nPublicKey = def=\n");
        assert!(matches!(parse_wireguard_conf(&no_endpoint, "x"), Err(ImportError::Missing("[Peer] Endpoint"))));
    }

    #[test]
    fn rejects_amneziawg() {
        let conf = CONF.replace("MTU = 1380", "Jc = 4\nJmin = 40");
        assert!(matches!(parse_wireguard_conf(&conf, "x"), Err(ImportError::Unsupported(_))));
    }
}
