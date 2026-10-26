use self::{
    direct::DirectOutbound,
    socks::SocksOutbound,
    http::HttpOutbound,
    vless::VlessOutbound,
    vmess::VmessOutbound,
    shadowsocks::ShadowsocksOutbound,
    hysteria::Hysteria2Outbound,
    trojan::TrojanOutbound,
    tuic::TuicOutbound,
    anytls::AnyTlsOutbound,
    selector::SelectorOutbound,
    urltest::UrltestOutbound,
};
use super::shared::{TlsOutbound, TransportOptions};
use serde::{Serialize, Deserialize};

pub mod direct;
pub mod socks;
pub mod http;
pub mod vless;
pub mod vmess;
pub mod shadowsocks;
pub mod hysteria;
pub mod trojan;
pub mod tuic;
pub mod anytls;
pub mod selector;
pub mod urltest;

// Blocking is done with a route rule `action: "reject"`, not a `block` outbound
// (removed in sing-box 1.13).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Outbound {
    Direct(DirectOutbound),
    Socks(SocksOutbound),
    Http(HttpOutbound),
    Shadowsocks(ShadowsocksOutbound),
    Vmess(VmessOutbound),
    Vless(VlessOutbound),
    Trojan(TrojanOutbound),
    Hysteria2(Hysteria2Outbound),
    Tuic(TuicOutbound),
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsOutbound),
    Selector(SelectorOutbound),
    Urltest(UrltestOutbound),
}

impl Outbound {
    pub fn tag_mut(&mut self) -> &mut String {
        match self {
            Outbound::Direct(o) => &mut o.tag,
            Outbound::Socks(o) => &mut o.tag,
            Outbound::Http(o) => &mut o.tag,
            Outbound::Shadowsocks(o) => &mut o.tag,
            Outbound::Vmess(o) => &mut o.tag,
            Outbound::Vless(o) => &mut o.tag,
            Outbound::Trojan(o) => &mut o.tag,
            Outbound::Hysteria2(o) => &mut o.tag,
            Outbound::Tuic(o) => &mut o.tag,
            Outbound::AnyTls(o) => &mut o.tag,
            Outbound::Selector(o) => &mut o.tag,
            Outbound::Urltest(o) => &mut o.tag,
        }
    }

    /// TLS options of the TCP-based outbounds (QUIC ones can't fragment the handshake).
    pub fn tcp_tls_mut(&mut self) -> Option<&mut TlsOutbound> {
        match self {
            Outbound::Http(o) => o.tls.as_mut(),
            Outbound::Vmess(o) => o.tls.as_mut(),
            Outbound::Vless(o) => o.tls.as_mut(),
            Outbound::Trojan(o) => o.tls.as_mut(),
            Outbound::AnyTls(o) => Some(&mut o.tls),
            _ => None,
        }
    }

    /// Server address and port, for the outbounds that dial one server.
    pub fn server_mut(&mut self) -> Option<(&mut String, &mut u16)> {
        match self {
            Outbound::Socks(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Http(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Shadowsocks(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Vmess(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Vless(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Trojan(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Hysteria2(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::Tuic(o) => Some((&mut o.server, &mut o.server_port)),
            Outbound::AnyTls(o) => Some((&mut o.server, &mut o.server_port)),
            _ => None,
        }
    }

    /// TLS options of every outbound that has them (TCP and QUIC ones).
    pub fn tls_mut(&mut self) -> Option<&mut TlsOutbound> {
        match self {
            Outbound::Hysteria2(o) => o.tls.as_mut(),
            Outbound::Tuic(o) => Some(&mut o.tls),
            other => other.tcp_tls_mut(),
        }
    }

    pub fn transport_mut(&mut self) -> Option<&mut TransportOptions> {
        match self {
            Outbound::Vmess(o) => o.transport.as_mut(),
            Outbound::Vless(o) => o.transport.as_mut(),
            Outbound::Trojan(o) => o.transport.as_mut(),
            _ => None,
        }
    }

    /// Whether it carries traffic over UDP (QUIC-based protocols) rather than TCP.
    pub fn uses_udp(&self) -> bool {
        matches!(self, Outbound::Hysteria2(_) | Outbound::Tuic(_))
    }
}
