use crate::engine::singbox::{
    config::{
        outbound::{Outbound, hysteria::Hysteria2Outbound},
        shared::Hysteria2Obfs,
    },
    generate::PROXY_TAG,
};
use crate::import::{ImportError, link, uri::{ShareLink, port_ranges}};
use crate::profile::Profile;

/// `hy2://password@host:443,20000-30000/?sni=…&obfs=salamander&obfs-password=…#name`
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let password = link.userinfo.clone().unwrap_or_default();

    let obfs = match link.get("obfs") {
        None | Some("none") => None,
        Some("salamander") => Some(Hysteria2Obfs {
            obfs_type: "salamander".into(),
            password: link.get("obfs-password").ok_or(ImportError::Missing("obfs password"))?.into(),
        }),
        Some(other) => return Err(ImportError::Unsupported(format!("obfs `{other}`"))),
    };

    // Port hopping comes either in the authority (`443,20000-30000`) or as `mport`.
    let server_ports = port_ranges(&link.port).or_else(|| link.get("mport").and_then(port_ranges));

    let outbound = Outbound::Hysteria2(Hysteria2Outbound {
        tag: PROXY_TAG.into(),
        server: link.host.clone(),
        server_port: link.port()?,
        server_ports,
        password,
        obfs,
        // Hysteria2 is always TLS.
        tls: link::tls(&link.query, "tls")?,
        ..Default::default()
    });
    Ok(link::proxy(link.display_name(), outbound))
}
