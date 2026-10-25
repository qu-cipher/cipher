use super::parse_link;
use crate::engine::singbox::config::{
    outbound::{Outbound, shadowsocks::ShadowsocksMethod, vless::VlessFlow},
    shared::{TransportOptions, tls::UtlsFingerprint},
};
use crate::import::ImportError;
use crate::profile::Profile;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

fn outbound(link: &str) -> (String, Outbound) {
    match parse_link(link).unwrap() {
        Profile::Proxy { name, outbound } => (name, outbound),
        other => panic!("expected a proxy profile, got {other:?}"),
    }
}

#[test]
fn vless_reality() {
    let link = format!(
        "vless://{UUID}@de.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality\
         &sni=www.microsoft.com&fp=firefox&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179e30d4fc2\
         &type=tcp&headerType=none#%F0%9F%87%A9%F0%9F%87%AA%20Germany"
    );
    let (name, Outbound::Vless(vless)) = outbound(&link) else { panic!() };

    assert_eq!(name, "🇩🇪 Germany");
    assert_eq!(vless.server, "de.example.com");
    assert_eq!(vless.server_port, 443);
    assert_eq!(vless.uuid, UUID);
    assert_eq!(vless.flow, Some(VlessFlow::XtlsRprxVision));
    assert!(vless.transport.is_none());

    let tls = vless.tls.unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("www.microsoft.com"));
    assert_eq!(tls.utls.unwrap().fingerprint, UtlsFingerprint::Firefox);
    let reality = tls.reality.unwrap();
    assert_eq!(reality.public_key, "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0");
    assert_eq!(reality.short_id.as_deref(), Some("6ba85179e30d4fc2"));
}

#[test]
fn vless_ws_tls_with_early_data() {
    let link = format!(
        "vless://{UUID}@[2001:db8::1]:8443?security=tls&sni=cdn.example.com&alpn=h2,http/1.1&allowInsecure=1\
         &type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048"
    );
    let (name, Outbound::Vless(vless)) = outbound(&link) else { panic!() };

    assert_eq!(name, "2001:db8::1:8443");
    assert_eq!(vless.server, "2001:db8::1");
    let tls = vless.tls.unwrap();
    assert_eq!(tls.alpn.unwrap(), ["h2", "http/1.1"]);
    assert_eq!(tls.insecure, Some(true));
    assert!(tls.utls.is_none());

    let Some(TransportOptions::Ws(ws)) = vless.transport else { panic!() };
    assert_eq!(ws.path.as_deref(), Some("/ws"));
    assert_eq!(ws.max_early_data, Some(2048));
    assert_eq!(ws.early_data_header_name.as_deref(), Some("Sec-WebSocket-Protocol"));
    assert_eq!(ws.headers.unwrap()["Host"], "cdn.example.com");
}

#[test]
fn vless_rejects_unsupported() {
    let xhttp = format!("vless://{UUID}@x.com:443?type=xhttp");
    assert!(matches!(parse_link(&xhttp), Err(ImportError::Unsupported(_))));

    let reality_without_key = format!("vless://{UUID}@x.com:443?security=reality");
    assert!(matches!(parse_link(&reality_without_key), Err(ImportError::Missing(_))));
}

#[test]
fn vmess_ws_tls() {
    let json = r#"{"v":"2","ps":"US WS","add":"us.example.com","port":"443","id":"bf000d23-0752-40b4-affe-68f7707a9661",
        "aid":0,"scy":"auto","net":"ws","type":"none","host":"us.example.com","path":"/ray","tls":"tls","sni":"us.example.com"}"#;
    let (name, Outbound::Vmess(vmess)) = outbound(&format!("vmess://{}", STANDARD.encode(json))) else { panic!() };

    assert_eq!(name, "US WS");
    assert_eq!(vmess.server_port, 443);
    assert_eq!(vmess.security.as_deref(), Some("auto"));
    assert_eq!(vmess.alter_id, None);
    assert_eq!(vmess.tls.unwrap().server_name.as_deref(), Some("us.example.com"));
    let Some(TransportOptions::Ws(ws)) = vmess.transport else { panic!() };
    assert_eq!(ws.path.as_deref(), Some("/ray"));
}

#[test]
fn vmess_grpc_numeric_port() {
    let json = r#"{"add":"1.2.3.4","port":2053,"id":"bf000d23-0752-40b4-affe-68f7707a9661","net":"grpc","path":"svc","tls":""}"#;
    let (name, Outbound::Vmess(vmess)) = outbound(&format!("vmess://{}", URL_SAFE_NO_PAD.encode(json))) else { panic!() };

    assert_eq!(name, "1.2.3.4:2053");
    assert!(vmess.tls.is_none());
    let Some(TransportOptions::Grpc(grpc)) = vmess.transport else { panic!() };
    assert_eq!(grpc.service_name.as_deref(), Some("svc"));
}

#[test]
fn trojan_defaults_to_tls() {
    let (name, Outbound::Trojan(trojan)) = outbound("trojan://p%40ss@nl.example.com:443?type=grpc&serviceName=TunService#NL")
    else { panic!() };

    assert_eq!(name, "NL");
    assert_eq!(trojan.password, "p@ss");
    assert_eq!(trojan.tls.unwrap().enabled, Some(true));
    let Some(TransportOptions::Grpc(grpc)) = trojan.transport else { panic!() };
    assert_eq!(grpc.service_name.as_deref(), Some("TunService"));
}

#[test]
fn shadowsocks_formats() {
    // SIP002 with base64 userinfo
    let userinfo = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:secret");
    let (name, Outbound::Shadowsocks(ss)) = outbound(&format!("ss://{userinfo}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS"))
    else { panic!() };
    assert_eq!(name, "SS");
    assert_eq!(ss.method, ShadowsocksMethod::Chacha20IetfPoly1305);
    assert_eq!(ss.password, "secret");
    assert_eq!(ss.plugin.as_deref(), Some("obfs-local"));
    assert_eq!(ss.plugin_opts.as_deref(), Some("obfs=http;obfs-host=example.com"));

    // 2022 cipher with percent-encoded plain userinfo
    let (_, Outbound::Shadowsocks(ss)) = outbound("ss://2022-blake3-aes-128-gcm:8JCsPssfgS8tiRwiMlhARg%3D%3D@1.2.3.4:443")
    else { panic!() };
    assert_eq!(ss.method, ShadowsocksMethod::Blake3Aes128Gcm);
    assert_eq!(ss.password, "8JCsPssfgS8tiRwiMlhARg==");

    // legacy: everything base64
    let legacy = STANDARD.encode("aes-256-gcm:pw@[2001:db8::2]:8388");
    let (name, Outbound::Shadowsocks(ss)) = outbound(&format!("ss://{legacy}")) else { panic!() };
    assert_eq!(name, "2001:db8::2:8388");
    assert_eq!(ss.server, "2001:db8::2");
    assert_eq!(ss.method, ShadowsocksMethod::Aes256Gcm);

    let rc4 = format!("ss://{}@1.2.3.4:1", STANDARD.encode("rc4-md5:pw"));
    assert!(matches!(parse_link(&rc4), Err(ImportError::Unsupported(_))));
}

#[test]
fn hysteria2_port_hopping_and_obfs() {
    let (name, Outbound::Hysteria2(hy2)) =
        outbound("hy2://pa55@hy.example.com:443,20000-30000/?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=cry#HY")
    else { panic!() };

    assert_eq!(name, "HY");
    assert_eq!(hy2.server_port, 443);
    assert_eq!(hy2.server_ports.unwrap(), ["443:443", "20000:30000"]);
    assert_eq!(hy2.password, "pa55");
    assert_eq!(hy2.obfs.unwrap().password, "cry");
    let tls = hy2.tls.unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("hy.example.com"));
    assert_eq!(tls.insecure, Some(true));

    let (_, Outbound::Hysteria2(hy2)) = outbound("hysteria2://pw@1.2.3.4:443?mport=1000-2000") else { panic!() };
    assert_eq!(hy2.server_ports.unwrap(), ["1000:2000"]);
}

#[test]
fn tuic_link() {
    let (name, Outbound::Tuic(tuic)) =
        outbound(&format!("tuic://{UUID}:p%40ss@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=quic&sni=tuic.example.com&allow_insecure=1#TUIC"))
    else { panic!() };

    assert_eq!(name, "TUIC");
    assert_eq!(tuic.uuid, UUID);
    assert_eq!(tuic.password.as_deref(), Some("p@ss"));
    assert_eq!(tuic.congestion_control.as_deref(), Some("bbr"));
    assert_eq!(tuic.udp_relay_mode.as_deref(), Some("quic"));
    assert_eq!(tuic.tls.server_name.as_deref(), Some("tuic.example.com"));
    assert_eq!(tuic.tls.insecure, Some(true));
    assert_eq!(tuic.tls.alpn.unwrap(), ["h3"]);
}

#[test]
fn anytls_link() {
    let (name, Outbound::AnyTls(anytls)) = outbound("anytls://secret@a.example.com:443?sni=real.example.com&alpn=h2#AnyTLS")
    else { panic!() };

    assert_eq!(name, "AnyTLS");
    assert_eq!(anytls.password, "secret");
    assert_eq!(anytls.tls.enabled, Some(true));
    assert_eq!(anytls.tls.server_name.as_deref(), Some("real.example.com"));
    assert_eq!(anytls.tls.alpn.unwrap(), ["h2"]);
    assert!(matches!(parse_link("anytls://secret@a.example.com:443?security=none"), Err(ImportError::Unsupported(_))));
}

#[test]
fn wireguard_link() {
    let link = "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@203.0.113.1:51820\
                ?publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&address=10.0.0.2,fd00::2&mtu=1280&reserved=1,2,3#WG";
    let Profile::WireGuard { name, endpoint } = parse_link(link).unwrap() else { panic!() };

    assert_eq!(name, "WG");
    assert_eq!(endpoint.private_key, "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=");
    assert_eq!(endpoint.address, ["10.0.0.2/32", "fd00::2/128"]);
    assert_eq!(endpoint.mtu, Some(1280));
    let peer = &endpoint.peers[0];
    assert_eq!(peer.public_key, "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=");
    assert_eq!(peer.reserved.as_deref(), Some(&[1, 2, 3][..]));
}

#[test]
fn unknown_and_malformed_links() {
    assert!(matches!(parse_link("ssr://abc"), Err(ImportError::UnsupportedScheme(s)) if s == "ssr"));
    assert!(matches!(parse_link("not a link"), Err(ImportError::Invalid(_))));
    assert!(matches!(parse_link("vless://@host:443"), Err(ImportError::Missing("uuid"))));
    assert!(matches!(parse_link(&format!("vless://{UUID}@host:abc")), Err(ImportError::Invalid(_))));
    assert!(matches!(parse_link("vmess://!!!"), Err(ImportError::Invalid(_))));
}

/// Imports one link per protocol, generates the full config and runs `sing-box check` on it.
#[test]
#[ignore = "needs sing-box in PATH"]
fn imported_links_pass_sing_box_check() {
    use crate::engine::singbox::{check, generate::build_config};
    use crate::profile::Settings;

    let vmess = STANDARD.encode(format!(r#"{{"add":"us.example.com","port":"443","id":"{UUID}","net":"ws","path":"/ray","tls":"tls"}}"#));
    let links = [
        format!("vless://{UUID}@de.example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179e30d4fc2"),
        format!("vless://{UUID}@cdn.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048"),
        format!("vless://{UUID}@cdn.example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup"),
        format!("vmess://{vmess}"),
        "trojan://secret@nl.example.com:443?type=grpc&serviceName=TunService".into(),
        format!("ss://{}@1.2.3.4:8388", URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:secret")),
        "hy2://pw@hy.example.com:443,20000-30000/?obfs=salamander&obfs-password=x".into(),
        format!("tuic://{UUID}:pw@tuic.example.com:443?congestion_control=bbr&sni=tuic.example.com"),
        "anytls://secret@a.example.com:443?sni=a.example.com".into(),
        "wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@203.0.113.1:51820?publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&address=10.0.0.2&reserved=1,2,3".into(),
    ];

    let binary = crate::engine::paths::find_binary("sing-box").expect("sing-box not installed");
    let dir = std::env::temp_dir().join("cipher_client_import_check");
    std::fs::create_dir_all(&dir).unwrap();

    for (i, link) in links.iter().enumerate() {
        let profile = parse_link(link).unwrap_or_else(|e| panic!("{link}: {e}"));
        let config = build_config(&profile, &Settings::default(), &dir, &[]).unwrap();
        let path = dir.join(format!("{i}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
        if let Err(e) = check(&binary, &path) {
            panic!("{link}\n→ rejected by sing-box: {e}");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
