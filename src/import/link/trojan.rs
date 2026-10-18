use crate::engine::singbox::{
    config::outbound::{Outbound, trojan::TrojanOutbound},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, link, uri::ShareLink};
use crate::profile::Profile;

/// `trojan://password@host:port?sni=…&type=ws&…#name` (TLS unless `security=none`)
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let password = link.userinfo.clone().filter(|p| !p.is_empty()).ok_or(ImportError::Missing("password"))?;

    let outbound = Outbound::Trojan(TrojanOutbound {
        tag: PROXY_TAG.into(),
        server: link.host.clone(),
        server_port: link.port()?,
        password,
        tls: link::tls(&link.query, "tls")?,
        transport: link::transport(&link.query)?,
        ..Default::default()
    });
    Ok(link::proxy(link.display_name(), outbound))
}
