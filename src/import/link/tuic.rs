use crate::engine::singbox::{
    config::outbound::{Outbound, tuic::TuicOutbound},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, link, uri::ShareLink};
use crate::profile::Profile;

/// `tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=…#name`
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let userinfo = link.userinfo.clone().filter(|u| !u.is_empty()).ok_or(ImportError::Missing("uuid"))?;
    let (uuid, password) = match userinfo.split_once(':') {
        Some((uuid, password)) => (uuid.to_owned(), Some(password.to_owned())),
        None => (userinfo, link.get("password").map(Into::into)),
    };

    // TUIC is always TLS (QUIC), and servers almost always expect the h3 ALPN.
    let mut tls = link::tls(&link.query, "tls")?.ok_or(ImportError::Unsupported("TUIC without TLS".into()))?;
    tls.alpn.get_or_insert_with(|| vec!["h3".into()]);

    let outbound = Outbound::Tuic(TuicOutbound {
        tag: PROXY_TAG.into(),
        server: link.host.clone(),
        server_port: link.port()?,
        uuid,
        password,
        congestion_control: link.get("congestion_control").or(link.get("congestion-control")).map(Into::into),
        udp_relay_mode: link.get("udp_relay_mode").or(link.get("udp-relay-mode")).map(Into::into),
        tls,
        ..Default::default()
    });
    Ok(link::proxy(link.display_name(), outbound))
}
