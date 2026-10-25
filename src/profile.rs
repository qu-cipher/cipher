use crate::engine::EngineKind;
use crate::engine::singbox::config::{
    endpoint::WireguardEndpoint,
    log::LogLevel,
    outbound::Outbound,
};
use crate::engine::xray::{
    Core,
    config::{Network as XrayNetwork, Protocol as XrayProtocol, XrayOutbound},
};
use crate::routing::Routing;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A connection the user can pick in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Profile {
    /// vless/vmess/trojan/shadowsocks/hysteria2/... run by sing-box.
    Proxy { name: String, outbound: Outbound },
    /// WireGuard, run by sing-box as an endpoint.
    WireGuard { name: String, endpoint: WireguardEndpoint },
    /// An OpenVPN config, run by the openvpn binary.
    OpenVpn {
        name: String,
        #[serde(flatten)]
        config: OpenVpnConfig,
        /// For configs with a bare `auth-user-pass` line (asked for in the UI).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials: Option<Credentials>,
    },
    /// The built-in Psiphon entry: Psiphon's client finds its own servers, sing-box sits in front.
    Psiphon { name: String },
    /// A config only Xray can run (XHTTP, mKCP, VLESS encryption), with sing-box in front.
    Xray { name: String, outbound: XrayOutbound },
}

/// Where an OpenVPN profile's config lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenVpnConfig {
    /// An imported .ovpn file, referenced in place.
    #[serde(rename = "config_path")]
    File(PathBuf),
    /// The .ovpn text itself, from an `ovpn://` link (written to a temp file to connect).
    #[serde(rename = "config")]
    Inline(String),
}

impl OpenVpnConfig {
    pub fn text(&self) -> std::io::Result<String> {
        match self {
            OpenVpnConfig::File(path) => std::fs::read_to_string(path),
            OpenVpnConfig::Inline(text) => Ok(text.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Profile {
    pub fn name(&self) -> &str {
        match self {
            Profile::Proxy { name, .. }
            | Profile::WireGuard { name, .. }
            | Profile::OpenVpn { name, .. }
            | Profile::Psiphon { name }
            | Profile::Xray { name, .. } => name,
        }
    }

    /// Short protocol label for the UI.
    pub fn protocol(&self) -> &'static str {
        match self {
            Profile::Proxy { outbound, .. } => match outbound {
                Outbound::Direct(_) => "direct",
                Outbound::Socks(_) => "socks",
                Outbound::Http(_) => "http",
                Outbound::Shadowsocks(_) => "ss",
                Outbound::Vmess(_) => "vmess",
                Outbound::Vless(_) => "vless",
                Outbound::Trojan(_) => "trojan",
                Outbound::Hysteria2(_) => "hy2",
                Outbound::Tuic(_) => "tuic",
                Outbound::AnyTls(_) => "anytls",
                Outbound::Selector(_) => "selector",
                Outbound::Urltest(_) => "urltest",
            },
            Profile::WireGuard { .. } => "wg",
            Profile::OpenVpn { .. } => "ovpn",
            Profile::Psiphon { .. } => "psiphon",
            Profile::Xray { outbound, .. } => match outbound.protocol {
                XrayProtocol::Vless(_) => "vless",
                XrayProtocol::Vmess(_) => "vmess",
                XrayProtocol::Trojan(_) => "trojan",
                XrayProtocol::Shadowsocks(_) => "ss",
                XrayProtocol::Freedom(_) => "direct",
            },
        }
    }

    /// Group in the Configs list: the protocol's full name, or "Built-In" for the app's own tunnels.
    pub fn group(&self) -> &'static str {
        match self {
            Profile::Proxy { outbound, .. } => match outbound {
                Outbound::Direct(_) => "Direct",
                Outbound::Socks(_) => "SOCKS",
                Outbound::Http(_) => "HTTP",
                Outbound::Shadowsocks(_) => "Shadowsocks",
                Outbound::Vmess(_) => "VMess",
                Outbound::Vless(_) => "VLESS",
                Outbound::Trojan(_) => "Trojan",
                Outbound::Hysteria2(_) => "Hysteria2",
                Outbound::Tuic(_) => "TUIC",
                Outbound::AnyTls(_) => "AnyTLS",
                Outbound::Selector(_) => "Selector",
                Outbound::Urltest(_) => "URLTest",
            },
            Profile::WireGuard { .. } => "WireGuard",
            Profile::OpenVpn { .. } => "OpenVPN",
            Profile::Psiphon { .. } => "Built-In",
            Profile::Xray { outbound, .. } => match outbound.protocol {
                XrayProtocol::Vless(_) => "VLESS",
                XrayProtocol::Vmess(_) => "VMess",
                XrayProtocol::Trojan(_) => "Trojan",
                XrayProtocol::Shadowsocks(_) => "Shadowsocks",
                XrayProtocol::Freedom(_) => "Direct",
            },
        }
    }

    /// Server address for a TCP latency test. `None` for UDP-only protocols,
    /// where a TCP connect says nothing about reachability.
    pub fn tcp_endpoint(&self) -> Option<(String, u16)> {
        if let Profile::Xray { outbound, .. } = self {
            let (server, port) = outbound.server().filter(|_| outbound.network() != XrayNetwork::Kcp)?;
            return Some((server.into(), port));
        }
        let Profile::Proxy { outbound, .. } = self else { return None };
        let (server, port) = match outbound {
            Outbound::Socks(o) => (&o.server, o.server_port),
            Outbound::Http(o) => (&o.server, o.server_port),
            Outbound::Shadowsocks(o) => (&o.server, o.server_port),
            Outbound::Vmess(o) => (&o.server, o.server_port),
            Outbound::Vless(o) => (&o.server, o.server_port),
            Outbound::Trojan(o) => (&o.server, o.server_port),
            Outbound::AnyTls(o) => (&o.server, o.server_port),
            _ => return None,
        };
        Some((server.clone(), port))
    }

    pub fn engine_kind(&self) -> EngineKind {
        match self {
            Profile::Proxy { .. } | Profile::WireGuard { .. } => EngineKind::SingBox,
            Profile::OpenVpn { .. } => EngineKind::OpenVpn,
            Profile::Psiphon { .. } => EngineKind::Psiphon,
            Profile::Xray { .. } => EngineKind::Xray,
        }
    }
}

/// How traffic gets into the VPN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// TUN device: captures all system traffic. Needs admin rights.
    #[default]
    Tunnel,
    /// Local SOCKS5/HTTP proxy, set as the OS proxy while connected.
    SystemProxy,
    /// Local SOCKS5/HTTP proxy only; apps opt in by pointing at it.
    ProxyOnly,
}

impl ConnectionMode {
    pub fn uses_tunnel(self) -> bool {
        self == ConnectionMode::Tunnel
    }
}

/// App-wide connection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: ConnectionMode,
    pub log_level: LogLevel,
    /// DNS-over-HTTPS server reached through the tunnel.
    pub dns_remote: String,
    /// Plain UDP DNS server reached directly (resolves proxy server domains).
    pub dns_direct: String,
    /// Send LAN / private addresses directly instead of through the tunnel.
    pub bypass_lan: bool,
    /// Port of the local SOCKS5/HTTP proxy on 127.0.0.1 (proxy modes, or `tunnel_proxy`).
    pub proxy_port: u16,
    /// Also serve the local proxy in Tunnel mode.
    pub tunnel_proxy: bool,
    /// Split tunneling: routing rules, presets and the default route (sing-box only).
    pub routing: Routing,
    pub psiphon: PsiphonSettings,
    /// Which engine runs VLESS/VMess/Trojan/Shadowsocks configs both engines can run.
    pub core: Core,
    /// Group the Configs list by protocol.
    pub group_configs: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PsiphonSettings {
    /// Psiphon network parameters (`PropagationChannelId`, `SponsorId`, server list URLs and keys),
    /// imported from a Psiphon JSON config. Everything else in the client config is generated.
    pub network: Option<serde_json::Map<String, serde_json::Value>>,
    /// Exit country as an ISO 3166-1 alpha-2 code; empty = the fastest server anywhere.
    pub region: String,
}

impl Settings {
    /// Whether the local SOCKS5/HTTP proxy runs in the current mode.
    pub fn serves_proxy(&self) -> bool {
        !self.mode.uses_tunnel() || self.tunnel_proxy
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            dns_remote: "1.1.1.1".into(),
            dns_direct: "8.8.8.8".into(),
            bypass_lan: true,
            mode: ConnectionMode::Tunnel,
            proxy_port: 2080,
            tunnel_proxy: false,
            routing: Routing::default(),
            psiphon: PsiphonSettings::default(),
            core: Core::SingBox,
            group_configs: true,
        }
    }
}
