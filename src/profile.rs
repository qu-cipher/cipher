use crate::engine::EngineKind;
use crate::engine::singbox::config::{
    endpoint::WireguardEndpoint,
    log::LogLevel,
    outbound::Outbound,
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
            | Profile::OpenVpn { name, .. } => name,
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
        }
    }

    /// Server address for a TCP latency test. `None` for UDP-only protocols,
    /// where a TCP connect says nothing about reachability.
    pub fn tcp_endpoint(&self) -> Option<(String, u16)> {
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
        }
    }
}
