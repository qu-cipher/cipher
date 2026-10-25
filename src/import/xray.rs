//! Share links only Xray can run → [`Profile::Xray`]: XHTTP (and its old name SplitHTTP), mKCP,
//! and VLESS encryption. Other links stay sing-box configs (the Xray core setting converts those
//! at connect time instead, see `engine::xray::convert`).
//!
//! `allowInsecure` is dropped: Xray removed it. h2 and QUIC transports are gone from Xray too.

use crate::engine::xray::config::*;
use crate::import::{ImportError, link::{Params, get}};
use crate::profile::Profile;
use std::collections::HashMap;

/// Whether a link's parameters need Xray.
pub fn needed(params: &Params) -> bool {
    let transport = get(params, "type").unwrap_or("tcp").to_ascii_lowercase();
    matches!(transport.as_str(), "xhttp" | "splithttp" | "kcp" | "mkcp")
        || get(params, "encryption").is_some_and(|e| e != "none")
}

/// What identifies the user to the server, per protocol.
pub enum Credentials {
    Vless { id: String, encryption: String, flow: Option<String> },
    Vmess { id: String, security: Option<String> },
    Trojan { password: String },
}

pub fn profile(name: String, credentials: Credentials, address: &str, port: u16, params: &Params) -> Result<Profile, ImportError> {
    let address = address.to_owned();
    let protocol = match credentials {
        Credentials::Vless { id, encryption, flow } => Protocol::Vless(Vnext {
            vnext: vec![VnextServer { address, port, users: vec![VlessUser { id, encryption, flow }] }],
        }),
        Credentials::Vmess { id, security } => Protocol::Vmess(Vnext {
            vnext: vec![VnextServer { address, port, users: vec![VmessUser { id, security }] }],
        }),
        Credentials::Trojan { password } => Protocol::Trojan(Servers { servers: vec![TrojanServer { address, port, password }] }),
    };
    let default_security = if matches!(protocol, Protocol::Trojan(_)) { "tls" } else { "none" };
    let stream = stream_settings(params, default_security)?;
    Ok(Profile::Xray { name, outbound: XrayOutbound { tag: String::new(), protocol, stream: Some(stream) } })
}

fn stream_settings(params: &Params, default_security: &str) -> Result<StreamSettings, ImportError> {
    let mut stream = StreamSettings::default();
    let host = get(params, "host").map(String::from);
    let path = get(params, "path").map(String::from);

    let security = get(params, "security").unwrap_or(default_security).to_ascii_lowercase();
    let server_name = get(params, "sni").or(get(params, "peer")).map(String::from);
    let fingerprint = get(params, "fp").map(str::to_ascii_lowercase);
    match security.as_str() {
        "none" | "" => {}
        "tls" | "xtls" => {
            stream.security = Some(Security::Tls);
            stream.tls_settings = Some(TlsSettings { server_name, alpn: get(params, "alpn").map(list), fingerprint });
        }
        "reality" => {
            stream.security = Some(Security::Reality);
            stream.reality_settings = Some(RealitySettings {
                server_name,
                fingerprint: fingerprint.unwrap_or_else(|| "chrome".into()),
                public_key: get(params, "pbk").ok_or(ImportError::Missing("reality public key (pbk)"))?.into(),
                short_id: get(params, "sid").map(Into::into),
                spider_x: get(params, "spx").map(Into::into),
            });
        }
        other => return Err(ImportError::Unsupported(format!("security `{other}`"))),
    }

    match get(params, "type").unwrap_or("tcp").to_ascii_lowercase().as_str() {
        "tcp" | "raw" | "none" => {
            if get(params, "headertype") == Some("http") {
                let headers = host.map(|h| HashMap::from([("Host".to_owned(), list(&h))])).unwrap_or_default();
                stream.network = Some(Network::Raw);
                stream.raw_settings = Some(RawSettings {
                    header: HttpHeader {
                        kind: "http".into(),
                        request: Some(HttpRequest { path: path.as_deref().map(list).unwrap_or_default(), headers }),
                    },
                });
            }
        }
        "ws" | "websocket" => {
            stream.network = Some(Network::Ws);
            stream.ws_settings = Some(PathHost { path, host });
        }
        "grpc" => {
            stream.network = Some(Network::Grpc);
            stream.grpc_settings = Some(GrpcSettings {
                service_name: get(params, "servicename").map(Into::into),
                multi_mode: (get(params, "mode") == Some("multi")).then_some(true),
            });
        }
        "httpupgrade" => {
            stream.network = Some(Network::HttpUpgrade);
            stream.httpupgrade_settings = Some(PathHost { path, host });
        }
        "xhttp" | "splithttp" => {
            let extra = match get(params, "extra") {
                Some(extra) => Some(serde_json::from_str(extra).map_err(|_| ImportError::Invalid("XHTTP `extra` (not JSON)".into()))?),
                None => None,
            };
            stream.network = Some(Network::Xhttp);
            stream.xhttp_settings = Some(XhttpSettings {
                host,
                path,
                mode: get(params, "mode").and_then(|m| serde_json::from_value(m.into()).ok()),
                extra,
            });
        }
        "kcp" | "mkcp" => {
            stream.network = Some(Network::Kcp);
            stream.kcp_settings = Some(KcpSettings {
                header: get(params, "headertype").filter(|t| *t != "none").map(|t| KcpHeader { kind: t.into() }),
                seed: get(params, "seed").map(Into::into),
            });
        }
        other => return Err(ImportError::Unsupported(format!("transport `{other}` in Xray"))),
    }
    Ok(stream)
}

fn list(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty()).map(String::from).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::import::parse_link;
    use serde_json::{Value, json};

    pub(crate) fn parse(link: &str) -> XrayOutbound {
        match parse_link(link).unwrap() {
            Profile::Xray { outbound, .. } => outbound,
            other => panic!("not an Xray profile: {other:?}"),
        }
    }

    fn value(link: &str) -> Value {
        serde_json::to_value(parse(link)).unwrap()
    }

    const ID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

    /// One of each shape, for `xray run -test` (see engine::xray). All with TLS: Xray refuses plain
    /// VLESS to public addresses, and a fake VLESS encryption key would crash its config loader.
    pub(crate) fn samples() -> Vec<(&'static str, XrayOutbound)> {
        let converted = |link: &str| match parse_link(link).unwrap() {
            Profile::Proxy { outbound, .. } => crate::engine::xray::convert::from_singbox(&outbound).unwrap_or_else(|| panic!("not convertible: {link}")),
            other => panic!("not a sing-box profile: {other:?}"),
        };
        vec![
            ("xhttp-reality", parse(&format!("vless://{ID}@example.com:443?type=xhttp&security=reality&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab&spx=%2F&path=%2Fx&mode=stream-one#X"))),
            ("xhttp-tls-extra", parse(&format!("vless://{ID}@example.com:443?type=xhttp&security=tls&sni=example.com&alpn=h2&fp=firefox&host=cdn.example.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#X"))),
            ("trojan-splithttp", parse("trojan://pw@example.com:443?type=splithttp&sni=example.com&path=%2Fs#T")),
            ("vmess-kcp", parse(&vmess_kcp())),
            ("vless-reality-vision", converted(&format!("vless://{ID}@example.com:443?security=reality&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&flow=xtls-rprx-vision#V"))),
            ("trojan-ws", converted("trojan://pw@example.com:443?type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&sni=example.com#T")),
            ("vless-grpc", converted(&format!("vless://{ID}@example.com:443?type=grpc&serviceName=svc&security=tls&sni=example.com#G"))),
            ("vless-httpupgrade", converted(&format!("vless://{ID}@example.com:443?type=httpupgrade&path=%2Fu&host=example.com&security=tls#U"))),
            // HTTP disguise is plain TCP; with TLS sing-box would read it as h2, which Xray dropped.
            ("vmess-raw-http", converted(&vmess(json!({ "add": "example.com", "port": "80", "id": ID, "net": "tcp", "type": "http", "host": "example.com", "path": "/" })))),
            ("shadowsocks", converted("ss://YWVzLTI1Ni1nY206cHc@example.com:8388#S")),
        ]
    }

    fn vmess(json: Value) -> String {
        format!("vmess://{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.to_string()))
    }

    fn vmess_kcp() -> String {
        vmess(json!({ "v": "2", "ps": "KCP", "add": "203.0.113.9", "port": "4000", "id": ID, "net": "kcp", "type": "wechat-video", "path": "seed1" }))
    }

    #[test]
    fn xhttp_reality_link() {
        let xray = value(&format!(
            "vless://{ID}@example.com:443?type=xhttp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PBK&sid=ab&path=%2Fx&host=cdn.example.com&mode=packet-up&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D#My%20server"
        ));
        assert_eq!(xray["protocol"], "vless");
        assert_eq!(xray["settings"]["vnext"][0], json!({ "address": "example.com", "port": 443, "users": [{ "id": ID, "encryption": "none" }] }));
        assert_eq!(xray["streamSettings"], json!({
            "network": "xhttp",
            "security": "reality",
            "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "PBK", "shortId": "ab" },
            "xhttpSettings": { "host": "cdn.example.com", "path": "/x", "mode": "packet-up", "extra": { "xmux": { "maxConcurrency": "16-32" } } },
        }));
        let Profile::Xray { name, .. } = parse_link(&format!("vless://{ID}@example.com:443?type=xhttp&security=tls#My%20server")).unwrap() else { panic!() };
        assert_eq!(name, "My server");
    }

    #[test]
    fn vless_encryption_and_vmess_kcp() {
        let xray = value(&format!("vless://{ID}@example.com:443?encryption=mlkem768x25519plus.native.0rtt.KEY&flow=xtls-rprx-vision&security=none#E"));
        assert_eq!(xray["settings"]["vnext"][0]["users"][0], json!({ "id": ID, "encryption": "mlkem768x25519plus.native.0rtt.KEY", "flow": "xtls-rprx-vision" }));
        assert!(xray["streamSettings"].get("security").is_none());

        let xray = value(&vmess_kcp());
        assert_eq!(xray["protocol"], "vmess");
        assert_eq!(xray["settings"]["vnext"][0]["users"][0], json!({ "id": ID, "security": "auto" }));
        assert_eq!(xray["streamSettings"], json!({ "network": "kcp", "kcpSettings": { "header": { "type": "wechat-video" }, "seed": "seed1" } }));
    }

    #[test]
    fn trojan_defaults_to_tls_and_bad_extra_is_rejected() {
        let xray = value("trojan://pw@example.com:443?type=xhttp&sni=example.com#T");
        assert_eq!(xray["streamSettings"]["security"], "tls");
        assert_eq!(xray["settings"]["servers"][0], json!({ "address": "example.com", "port": 443, "password": "pw" }));
        assert!(parse_link("trojan://pw@example.com:443?type=xhttp&extra=nope#T").is_err());
    }

    #[test]
    fn only_xray_features_go_to_xray() {
        assert!(matches!(parse_link(&format!("vless://{ID}@example.com:443?type=ws&security=tls#W")).unwrap(), Profile::Proxy { .. }));
        assert!(matches!(parse_link(&format!("vless://{ID}@example.com:443?type=xhttp&security=tls#W")).unwrap(), Profile::Xray { .. }));
    }
}
