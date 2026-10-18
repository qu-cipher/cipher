use crate::engine::singbox::{
    config::outbound::{Outbound, vmess::VmessOutbound},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, decode_base64, link::{self, Params}};
use crate::profile::Profile;
use serde_json::Value;

/// `vmess://base64({"add":…,"port":…,"id":…,"net":"ws",…})` (the v2rayN format)
pub fn parse(link: &str) -> Result<Profile, ImportError> {
    let (_, body) = link.split_once("://").unwrap_or_default();
    let body = body.split('#').next().unwrap_or_default();

    let json = decode_base64(body).ok_or_else(|| ImportError::Invalid("vmess link (not base64)".into()))?;
    let value: Value = serde_json::from_str(&json).map_err(|_| ImportError::Invalid("vmess JSON".into()))?;

    // Fields are strings or numbers depending on who generated the link.
    let field = |key: &str| match value.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };

    let server = field("add").ok_or(ImportError::Missing("server address"))?;
    let server_port = field("port")
        .and_then(|p| p.parse().ok())
        .ok_or(ImportError::Missing("port"))?;
    let uuid = field("id").ok_or(ImportError::Missing("uuid"))?;
    let net = field("net").unwrap_or_else(|| "tcp".into());

    // Map onto the share-link parameter names so the TLS/transport code is shared.
    let mut params = Params::new();
    let mut set = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            params.insert(key.into(), value);
        }
    };
    set("type", Some(net.clone()));
    set("headertype", field("type"));
    set("host", field("host"));
    set("security", field("tls"));
    set("sni", field("sni"));
    set("alpn", field("alpn"));
    set("fp", field("fp"));
    if net == "grpc" {
        set("servicename", field("path"));
    } else {
        set("path", field("path"));
    }

    let outbound = Outbound::Vmess(VmessOutbound {
        tag: PROXY_TAG.into(),
        server: server.clone(),
        server_port,
        uuid,
        security: Some(field("scy").unwrap_or_else(|| "auto".into())),
        alter_id: field("aid").and_then(|a| a.parse().ok()).filter(|&a| a > 0),
        tls: link::tls(&params, "none")?,
        transport: link::transport(&params)?,
        ..Default::default()
    });
    let name = field("ps").unwrap_or_else(|| format!("{server}:{server_port}"));
    Ok(link::proxy(name, outbound))
}
