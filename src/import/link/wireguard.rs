use crate::engine::singbox::{
    config::endpoint::{WireguardEndpoint, WireguardPeer},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, uri::ShareLink, wireguard::{DEFAULT_ALLOWED_IPS, interface_address}};
use crate::profile::Profile;

/// `wireguard://<private key>@host:port?publickey=…&address=10.0.0.2/32,…&mtu=…&reserved=1,2,3#name`
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let private_key = link.userinfo.clone().filter(|k| !k.is_empty()).ok_or(ImportError::Missing("private key"))?;
    let public_key = link
        .get("publickey")
        .or(link.get("peer_public_key"))
        .ok_or(ImportError::Missing("peer public key"))?;

    let address: Vec<String> = link
        .get("address")
        .or(link.get("ip"))
        .ok_or(ImportError::Missing("interface address"))?
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(interface_address)
        .collect();

    let reserved = match link.get("reserved") {
        Some(reserved) => Some(
            reserved
                .split(',')
                .map(|b| b.trim().parse())
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| ImportError::Invalid(format!("reserved `{reserved}`")))?,
        ),
        None => None,
    };

    let endpoint = WireguardEndpoint {
        tag: PROXY_TAG.into(),
        address,
        private_key,
        mtu: link.get("mtu").and_then(|m| m.parse().ok()),
        peers: vec![WireguardPeer {
            address: link.host.clone(),
            port: link.port()?,
            public_key: public_key.into(),
            pre_shared_key: link.get("presharedkey").map(Into::into),
            allowed_ips: DEFAULT_ALLOWED_IPS.map(String::from).to_vec(),
            reserved,
            ..Default::default()
        }],
        ..Default::default()
    };
    Ok(Profile::WireGuard { name: link.display_name(), endpoint })
}
