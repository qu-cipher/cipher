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
}
