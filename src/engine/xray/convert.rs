//! sing-box outbound → Xray outbound, for the Xray core setting. `None` when Xray can't run the
//! config the same way; it then stays on sing-box:
//! - insecure TLS (Xray removed `allowInsecure`), h2/QUIC transports (removed from Xray),
//!   multiplex, Shadowsocks plugins and AES-192, VMess alterId > 0;
//! - VLESS and Trojan without TLS (Xray refuses them for public addresses).

use super::config::*;
use crate::engine::singbox::config::{
    outbound::{Outbound, shadowsocks::ShadowsocksMethod, vless::VlessFlow},
    shared::{TlsOutbound, TransportOptions},
};
use std::collections::HashMap;

pub fn from_singbox(outbound: &Outbound) -> Option<XrayOutbound> {
    let (protocol, tls, transport) = match outbound {
        Outbound::Vless(o) => {
            if o.multiplex.is_some() || o.tls.is_none() {
                return None;
            }
            let user = VlessUser {
                id: o.uuid.clone(),
                encryption: "none".into(),
                flow: o.flow.map(|flow| match flow {
                    VlessFlow::XtlsRprxVision => "xtls-rprx-vision".into(),
                }),
            };
            (Protocol::Vless(vnext(&o.server, o.server_port, user)), &o.tls, &o.transport)
        }
        Outbound::Vmess(o) => {
            if o.multiplex.is_some() || o.alter_id.is_some_and(|id| id > 0) {
                return None;
            }
            let user = VmessUser { id: o.uuid.clone(), security: o.security.clone() };
            (Protocol::Vmess(vnext(&o.server, o.server_port, user)), &o.tls, &o.transport)
        }
        Outbound::Trojan(o) => {
            if o.multiplex.is_some() || o.tls.is_none() {
                return None;
            }
            let server = TrojanServer { address: o.server.clone(), port: o.server_port, password: o.password.clone() };
            (Protocol::Trojan(Servers { servers: vec![server] }), &o.tls, &o.transport)
        }
        Outbound::Shadowsocks(o) => {
            // Xray has no AES-192.
            if o.multiplex.is_some() || o.plugin.is_some() || o.method == ShadowsocksMethod::Aes192Gcm {
                return None;
            }
            let method = serde_json::to_value(o.method).ok()?.as_str()?.to_owned();
            let server = ShadowsocksServer { address: o.server.clone(), port: o.server_port, method, password: o.password.clone() };
            (Protocol::Shadowsocks(Servers { servers: vec![server] }), &None, &None)
        }
        _ => return None,
    };

    let mut stream = StreamSettings::default();
    security(tls.as_ref(), &mut stream)?;
    transport_settings(transport.as_ref(), tls.is_some(), &mut stream)?;
    let stream = (stream != StreamSettings::default()).then_some(stream);
    Some(XrayOutbound { tag: String::new(), protocol, stream })
}

fn vnext<U>(server: &str, port: u16, user: U) -> Vnext<U> {
    Vnext { vnext: vec![VnextServer { address: server.into(), port, users: vec![user] }] }
}

fn security(tls: Option<&TlsOutbound>, stream: &mut StreamSettings) -> Option<()> {
    let Some(tls) = tls.filter(|t| t.enabled != Some(false)) else { return Some(()) };
    if tls.insecure == Some(true) {
        return None;
    }
    let fingerprint = tls
        .utls
        .as_ref()
        .filter(|u| u.enabled)
        .and_then(|u| serde_json::to_value(u.fingerprint).ok())
        .and_then(|v| v.as_str().map(str::to_owned));

    match &tls.reality {
        Some(reality) if reality.enabled => {
            stream.security = Some(Security::Reality);
            stream.reality_settings = Some(RealitySettings {
                server_name: tls.server_name.clone(),
                fingerprint: fingerprint.unwrap_or_else(|| "chrome".into()),
                public_key: reality.public_key.clone(),
                short_id: reality.short_id.clone(),
                spider_x: None,
            });
        }
        _ => {
            stream.security = Some(Security::Tls);
            stream.tls_settings = Some(TlsSettings { server_name: tls.server_name.clone(), alpn: tls.alpn.clone(), fingerprint });
        }
    }
    Some(())
}

fn transport_settings(transport: Option<&TransportOptions>, tls: bool, stream: &mut StreamSettings) -> Option<()> {
    let Some(transport) = transport else { return Some(()) };
    match transport {
        TransportOptions::Ws(ws) => {
            let host = ws.headers.as_ref().and_then(|h| h.get("Host").cloned());
            // Xray takes WebSocket early data from the path.
            let path = match (ws.path.clone(), ws.max_early_data) {
                (path, Some(early)) if early > 0 => Some(format!("{}?ed={early}", path.unwrap_or_else(|| "/".into()))),
                (path, _) => path,
            };
            stream.network = Some(Network::Ws);
            stream.ws_settings = Some(PathHost { path, host });
        }
        TransportOptions::Grpc(grpc) => {
            stream.network = Some(Network::Grpc);
            stream.grpc_settings = Some(GrpcSettings { service_name: grpc.service_name.clone(), multi_mode: None });
        }
        TransportOptions::HttpUpgrade(upgrade) => {
            stream.network = Some(Network::HttpUpgrade);
            stream.httpupgrade_settings = Some(PathHost { path: upgrade.path.clone(), host: upgrade.host.clone() });
        }
        // Without TLS this is TCP disguised as HTTP/1.1; with TLS it's h2, which Xray dropped.
        TransportOptions::Http(http) if !tls => {
            let mut headers = HashMap::new();
            if let Some(hosts) = http.host.clone().filter(|h| !h.is_empty()) {
                headers.insert("Host".into(), hosts);
            }
            stream.network = Some(Network::Raw);
            stream.raw_settings = Some(RawSettings {
                header: HttpHeader {
                    kind: "http".into(),
                    request: Some(HttpRequest { path: http.path.clone().into_iter().collect(), headers }),
                },
            });
        }
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::singbox::config::{
        outbound::{shadowsocks::ShadowsocksOutbound, vless::VlessOutbound, trojan::TrojanOutbound},
        shared::{tls::{RealityOutbound, UtlsFingerprint, UtlsOutbound}, transport::{QuicTransport, WsTransport}},
    };
    use serde_json::json;

    fn tls(insecure: bool) -> Option<TlsOutbound> {
        Some(TlsOutbound {
            enabled: Some(true),
            server_name: Some("a.example.com".into()),
            insecure: insecure.then_some(true),
            utls: Some(UtlsOutbound { enabled: true, fingerprint: UtlsFingerprint::Firefox }),
            ..Default::default()
        })
    }

    #[test]
    fn vless_reality_with_vision() {
        let outbound = Outbound::Vless(VlessOutbound {
            server: "a.example.com".into(),
            server_port: 443,
            uuid: "id".into(),
            flow: Some(VlessFlow::XtlsRprxVision),
            tls: Some(TlsOutbound {
                reality: Some(RealityOutbound { enabled: true, public_key: "pbk".into(), short_id: Some("ab".into()) }),
                ..tls(false).unwrap()
            }),
            ..Default::default()
        });
        let xray = serde_json::to_value(from_singbox(&outbound).unwrap()).unwrap();
        assert_eq!(xray["protocol"], "vless");
        assert_eq!(xray["settings"]["vnext"][0]["users"][0], json!({ "id": "id", "encryption": "none", "flow": "xtls-rprx-vision" }));
        assert_eq!(xray["streamSettings"], json!({
            "security": "reality",
            "realitySettings": { "serverName": "a.example.com", "fingerprint": "firefox", "publicKey": "pbk", "shortId": "ab" },
        }));
    }

    #[test]
    fn trojan_ws_with_early_data() {
        let outbound = Outbound::Trojan(TrojanOutbound {
            server: "a.example.com".into(),
            server_port: 443,
            password: "pw".into(),
            tls: tls(false),
            transport: Some(TransportOptions::Ws(WsTransport {
                path: Some("/ws".into()),
                headers: Some(HashMap::from([("Host".into(), "cdn.example.com".into())])),
                max_early_data: Some(2048),
                ..Default::default()
            })),
            ..Default::default()
        });
        let xray = serde_json::to_value(from_singbox(&outbound).unwrap()).unwrap();
        assert_eq!(xray["settings"]["servers"][0], json!({ "address": "a.example.com", "port": 443, "password": "pw" }));
        assert_eq!(xray["streamSettings"]["network"], "ws");
        assert_eq!(xray["streamSettings"]["wsSettings"], json!({ "path": "/ws?ed=2048", "host": "cdn.example.com" }));
        assert_eq!(xray["streamSettings"]["tlsSettings"]["fingerprint"], "firefox");
    }

    #[test]
    fn shadowsocks_method_names_carry_over() {
        let outbound = Outbound::Shadowsocks(ShadowsocksOutbound {
            server: "a.example.com".into(),
            server_port: 8388,
            method: ShadowsocksMethod::Aes256Gcm,
            password: "pw".into(),
            ..Default::default()
        });
        let xray = serde_json::to_value(from_singbox(&outbound).unwrap()).unwrap();
        assert_eq!(xray["settings"]["servers"][0]["method"], "aes-256-gcm");
        assert!(xray.get("streamSettings").is_none());
    }

    #[test]
    fn stays_on_sing_box_when_xray_cant_match_it() {
        let plain_vless = Outbound::Vless(VlessOutbound { server: "a.example.com".into(), server_port: 80, uuid: "id".into(), ..Default::default() });
        let insecure = Outbound::Trojan(TrojanOutbound { server: "a".into(), server_port: 443, password: "pw".into(), tls: tls(true), ..Default::default() });
        let quic = Outbound::Trojan(TrojanOutbound {
            server: "a".into(),
            server_port: 443,
            password: "pw".into(),
            tls: tls(false),
            transport: Some(TransportOptions::Quic(QuicTransport {})),
            ..Default::default()
        });
        let plain_trojan = Outbound::Trojan(TrojanOutbound { server: "a".into(), server_port: 80, password: "pw".into(), ..Default::default() });
        for outbound in [plain_vless, plain_trojan, insecure, quic] {
            assert!(from_singbox(&outbound).is_none(), "{outbound:?}");
        }
    }
}
