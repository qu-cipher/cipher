//! Serde model of an Xray-core outbound: the four proxy protocols Xray runs for us and the stream
//! settings (transport + TLS) they share. Field names follow Xray's camelCase JSON.
//! Checked with `xray run -test` (26.9.9): `allowInsecure` no longer exists, and plain VLESS
//! (no TLS, no VLESS encryption) and plain Trojan are refused unless the server address is private.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XrayOutbound {
    #[serde(default)]
    pub tag: String,

    #[serde(flatten)]
    pub protocol: Protocol,

    #[serde(rename = "streamSettings", default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamSettings>,
}

/// `"protocol": "vless", "settings": {…}`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "settings", rename_all = "lowercase")]
pub enum Protocol {
    Vless(Vnext<VlessUser>),
    Vmess(Vnext<VmessUser>),
    Trojan(Servers<TrojanServer>),
    Shadowsocks(Servers<ShadowsocksServer>),
    /// The direct outbound.
    Freedom(Empty),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Empty {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vnext<U> {
    pub vnext: Vec<VnextServer<U>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VnextServer<U> {
    pub address: String,
    pub port: u16,
    pub users: Vec<U>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlessUser {
    pub id: String,
    /// `none`, or a VLESS encryption key (`mlkem768x25519plus.…`).
    pub encryption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmessUser {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Servers<S> {
    pub servers: Vec<S>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrojanServer {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowsocksServer {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Plain TCP (formerly `tcp`).
    Raw,
    Ws,
    Grpc,
    HttpUpgrade,
    Xhttp,
    Kcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<TlsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<RealitySettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_settings: Option<RawSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<PathHost>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub httpupgrade_settings: Option<PathHost>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_settings: Option<XhttpSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp_settings: Option<KcpSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<Sockopt>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    /// uTLS fingerprint: `chrome`, `firefox`, `safari`, `random`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealitySettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    pub fingerprint: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
}

/// Plain TCP, optionally disguised as HTTP/1.1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawSettings {
    pub header: HttpHeader,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpHeader {
    /// Always `http`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
}

/// WebSocket and HTTPUpgrade.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PathHost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_mode: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<XhttpMode>,
    /// Advanced options (padding, multiplexing, download split), passed through as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KcpSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<KcpHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KcpHeader {
    /// `none`, `srtp`, `utp`, `wechat-video`, `dtls`, `wireguard`, `dns`
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStrategy {
    AsIs,
    UseIP,
    UseIPv4,
    UseIPv6,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sockopt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DomainStrategy>,
}

impl XrayOutbound {
    /// Server address and port.
    pub fn server(&self) -> Option<(&str, u16)> {
        match &self.protocol {
            Protocol::Vless(s) => s.vnext.first().map(|v| (v.address.as_str(), v.port)),
            Protocol::Vmess(s) => s.vnext.first().map(|v| (v.address.as_str(), v.port)),
            Protocol::Trojan(s) => s.servers.first().map(|v| (v.address.as_str(), v.port)),
            Protocol::Shadowsocks(s) => s.servers.first().map(|v| (v.address.as_str(), v.port)),
            Protocol::Freedom(_) => None,
        }
    }

    pub fn network(&self) -> Network {
        self.stream.as_ref().and_then(|s| s.network).unwrap_or(Network::Raw)
    }
}
