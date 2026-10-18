use crate::engine::singbox::{
    config::outbound::{Outbound, vless::{VlessFlow, VlessOutbound}},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, link, uri::ShareLink};
use crate::profile::Profile;

/// `vless://uuid@host:port?security=reality&pbk=…&type=ws&…#name`
pub fn parse(link: &ShareLink) -> Result<Profile, ImportError> {
    let uuid = link.userinfo.clone().filter(|u| !u.is_empty()).ok_or(ImportError::Missing("uuid"))?;

    if let Some(encryption) = link.get("encryption") && encryption != "none" {
        return Err(ImportError::Unsupported("VLESS encryption".into()));
    }

    let flow = match link.get("flow") {
        None => None,
        Some(flow) if flow.starts_with("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
        Some(other) => return Err(ImportError::Unsupported(format!("flow `{other}`"))),
    };

    let outbound = Outbound::Vless(VlessOutbound {
        tag: PROXY_TAG.into(),
        server: link.host.clone(),
        server_port: link.port()?,
        uuid,
        flow,
        packet_encoding: link.get("packetencoding").map(Into::into),
        tls: link::tls(&link.query, "none")?,
        transport: link::transport(&link.query)?,
        ..Default::default()
    });
    Ok(link::proxy(link.display_name(), outbound))
}
