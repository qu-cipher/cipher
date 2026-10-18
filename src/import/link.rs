//! Share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `wireguard://`, `ovpn://`) → [`Profile`].

use crate::engine::singbox::config::{
    outbound::Outbound,
    shared::{
        TlsOutbound, TransportOptions,
        tls::{RealityOutbound, UtlsFingerprint, UtlsOutbound},
        transport::{GrpcTransport, HttpTransport, HttpUpgradeTransport, QuicTransport, WsTransport},
    },
};
use crate::import::{ImportError, uri::{ShareLink, parse_query}};
use crate::profile::Profile;
use std::collections::HashMap;

mod vless;
mod vmess;
mod trojan;
mod shadowsocks;
mod hysteria2;
mod tuic;
mod anytls;
mod wireguard;

#[cfg(test)]
mod tests;

/// Query-style parameters shared by the link formats (keys lowercase).
pub(crate) type Params = HashMap<String, String>;

pub fn parse_link(link: &str) -> Result<Profile, ImportError> {
    let link = link.trim();
    let (scheme, _) = link.split_once("://").ok_or_else(|| ImportError::Invalid("link".into()))?;

    match scheme.to_ascii_lowercase().as_str() {
        // These are (partly) base64, not URIs.
        "vmess" => vmess::parse(link),
        "ss" => shadowsocks::parse(link),
        "ovpn" | "openvpn" => crate::import::openvpn::parse_ovpn_link(link),

        "vless" => vless::parse(&ShareLink::parse(link)?),
        "trojan" => trojan::parse(&ShareLink::parse(link)?),
        "hysteria2" | "hy2" => hysteria2::parse(&ShareLink::parse(link)?),
        "tuic" => tuic::parse(&ShareLink::parse(link)?),
        "anytls" => anytls::parse(&ShareLink::parse(link)?),
        "wireguard" | "wg" => wireguard::parse(&ShareLink::parse(link)?),
        other => Err(ImportError::UnsupportedScheme(other.into())),
    }
}

pub(crate) fn proxy(name: String, outbound: Outbound) -> Profile {
    Profile::Proxy { name, outbound }
}

pub(crate) fn get<'a>(params: &'a Params, key: &str) -> Option<&'a str> {
    params.get(key).map(String::as_str).filter(|v| !v.is_empty())
}

fn flag(params: &Params, key: &str) -> bool {
    matches!(get(params, key), Some("1" | "true"))
}

fn list(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty()).map(String::from).collect()
}

/// `security` / `sni` / `alpn` / `fp` / `pbk` / `sid` / `allowInsecure` → TLS options.
/// `default_security` applies when the link has no `security` param.
pub(crate) fn tls(params: &Params, default_security: &str) -> Result<Option<TlsOutbound>, ImportError> {
    let security = get(params, "security").unwrap_or(default_security).to_ascii_lowercase();

    let reality = match security.as_str() {
        "none" | "" => return Ok(None),
        "tls" | "xtls" => None,
        "reality" => Some(RealityOutbound {
            enabled: true,
            public_key: get(params, "pbk").ok_or(ImportError::Missing("reality public key (pbk)"))?.into(),
            short_id: get(params, "sid").map(Into::into),
        }),
        other => return Err(ImportError::Unsupported(format!("security `{other}`"))),
    };

    // Reality only works with a uTLS fingerprint.
    let fingerprint = get(params, "fp")
        .map(fingerprint)
        .or(reality.as_ref().map(|_| UtlsFingerprint::Chrome));

    Ok(Some(TlsOutbound {
        enabled: Some(true),
        server_name: get(params, "sni").or(get(params, "peer")).map(Into::into),
        insecure: ["allowinsecure", "allow_insecure", "insecure"].iter().any(|k| flag(params, k)).then_some(true),
        alpn: get(params, "alpn").map(list),
        utls: fingerprint.map(|fingerprint| UtlsOutbound { enabled: true, fingerprint }),
        reality,
        ..Default::default()
    }))
}

/// Unknown fingerprints (e.g. Xray-only ones) fall back to Chrome rather than failing the import.
fn fingerprint(fp: &str) -> UtlsFingerprint {
    serde_json::from_value(serde_json::Value::String(fp.to_ascii_lowercase())).unwrap_or(UtlsFingerprint::Chrome)
}

/// `type` / `host` / `path` / `serviceName` / `headerType` → V2Ray transport. Plain TCP → `None`.
pub(crate) fn transport(params: &Params) -> Result<Option<TransportOptions>, ImportError> {
    let kind = get(params, "type").unwrap_or("tcp").to_ascii_lowercase();
    let host = get(params, "host");
    let path = get(params, "path").map(String::from);

    let transport = match kind.as_str() {
        "tcp" | "raw" | "none" => match get(params, "headertype") {
            Some("http") => TransportOptions::Http(HttpTransport {
                host: host.map(list),
                path,
                ..Default::default()
            }),
            _ => return Ok(None),
        },
        "ws" | "websocket" => TransportOptions::Ws(websocket(host, path)),
        "grpc" => TransportOptions::Grpc(GrpcTransport {
            service_name: get(params, "servicename").map(Into::into),
            ..Default::default()
        }),
        "http" | "h2" => TransportOptions::Http(HttpTransport {
            host: host.map(list),
            path,
            ..Default::default()
        }),
        "httpupgrade" => TransportOptions::HttpUpgrade(HttpUpgradeTransport {
            host: host.map(Into::into),
            path,
            ..Default::default()
        }),
        "quic" => TransportOptions::Quic(QuicTransport {}),
        other => return Err(ImportError::Unsupported(format!("transport `{other}`"))),
    };
    Ok(Some(transport))
}

/// Xray puts WebSocket early data in the path (`/ws?ed=2048`); sing-box has explicit fields.
fn websocket(host: Option<&str>, path: Option<String>) -> WsTransport {
    let mut ws = WsTransport {
        headers: host.map(|host| HashMap::from([("Host".to_owned(), host.to_owned())])),
        ..Default::default()
    };

    if let Some(path) = path {
        match path.split_once('?') {
            Some((base, query)) => {
                let early_data = parse_query(query).get("ed").and_then(|ed| ed.parse().ok());
                if early_data.is_some() {
                    ws.max_early_data = early_data;
                    ws.early_data_header_name = Some("Sec-WebSocket-Protocol".into());
                    ws.path = Some(base.into());
                } else {
                    ws.path = Some(path);
                }
            }
            None => ws.path = Some(path),
        }
    }
    ws
}
