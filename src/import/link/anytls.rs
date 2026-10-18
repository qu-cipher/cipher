use crate::engine::singbox::{
    config::outbound::{Outbound, anytls::AnyTlsOutbound},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, link, uri::ShareLink};
use crate::profile::Profile;

/// `anytls://password@host:port?sni=…&insecure=1#name` (always TLS)
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let password = link.userinfo.clone().filter(|p| !p.is_empty()).ok_or(ImportError::Missing("password"))?;
    let tls = link::tls(&link.query, "tls")?.ok_or(ImportError::Unsupported("AnyTLS without TLS".into()))?;

    let outbound = Outbound::AnyTls(AnyTlsOutbound {
        tag: PROXY_TAG.into(),
        server: link.host.clone(),
        server_port: link.port()?,
        password,
        tls,
        ..Default::default()
    });
    Ok(link::proxy(link.display_name(), outbound))
}
