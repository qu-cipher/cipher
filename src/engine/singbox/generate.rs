//! Builds a complete client config (TUN + one proxy) from a profile.
//! See docs/singbox-config.md for why each piece is there.

use crate::engine::{EngineError, EngineKind};
use crate::engine::singbox::config::{
    SingBoxConfig,
    dns::{DNS, DnsServer, HttpsDnsServer, PlainDnsServer},
    endpoint::Endpoint,
    experimental::{CacheFile, Experimental},
    inbound::{Inbound, mixed::MixedInbound, tun::{TunInbound, TunStack}},
    log::Log,
    outbound::{Outbound, direct::DirectOutbound},
    route::{Route, RouteRule, RuleAction},
    shared::{DialerOptions, DomainResolver, ListenOptions},
};
use crate::profile::{ConnectionMode, Profile, Settings};
use std::path::Path;

pub const PROXY_TAG: &str = "proxy";
pub const DIRECT_TAG: &str = "direct";
const TUN_TAG: &str = "tun-in";
const MIXED_TAG: &str = "mixed-in";
const DNS_REMOTE_TAG: &str = "remote";
const DNS_LOCAL_TAG: &str = "local";

const SCHEMA_URL: &str = "https://sing-box.sagernet.org/schema.json";
const TUN_ADDRESS: [&str; 2] = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"];
pub const PROXY_LISTEN: &str = "127.0.0.1";

pub fn build_config(profile: &Profile, settings: &Settings, data_dir: &Path) -> Result<SingBoxConfig, EngineError> {
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();

    match profile {
        Profile::Proxy { outbound, .. } => {
            let mut outbound = outbound.clone();
            *outbound.tag_mut() = PROXY_TAG.into();
            outbounds.push(outbound);
        }
        Profile::WireGuard { endpoint, .. } => {
            let mut endpoint = endpoint.clone();
            endpoint.tag = PROXY_TAG.into();
            endpoints.push(Endpoint::Wireguard(endpoint));
        }
        Profile::OpenVpn { .. } => return Err(EngineError::WrongEngine(EngineKind::OpenVpn)),
    }

    outbounds.push(Outbound::Direct(DirectOutbound {
        tag: DIRECT_TAG.into(),
        ..Default::default()
    }));

    Ok(SingBoxConfig {
        schema: Some(SCHEMA_URL.into()),
        log: Some(Log {
            level: Some(settings.log_level),
            timestamp: Some(true),
            ..Default::default()
        }),
        dns: Some(dns(settings)),
        inbounds: inbounds(settings),
        outbounds,
        endpoints,
        route: Some(route(settings)),
        experimental: Some(Experimental {
            cache_file: Some(CacheFile {
                enabled: Some(true),
                path: Some(data_dir.join("cache.db").to_string_lossy().into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        }),
    })
}

fn inbounds(settings: &Settings) -> Vec<Inbound> {
    let mut inbounds = Vec::new();

    if settings.mode.uses_tunnel() {
        inbounds.push(Inbound::Tun(TunInbound {
            tag: Some(TUN_TAG.into()),
            address: Some(TUN_ADDRESS.map(String::from).to_vec()),
            // Userspace TCP: the default stack's kernel hop is blocked by host firewalls.
            stack: Some(TunStack::Gvisor),
            auto_route: Some(true),
            strict_route: Some(true),
            ..Default::default()
        }));
    }

    if settings.serves_proxy() {
        inbounds.push(Inbound::Mixed(MixedInbound {
            tag: Some(MIXED_TAG.into()),
            listen: ListenOptions {
                listen: Some(PROXY_LISTEN.into()),
                listen_port: Some(settings.proxy_port),
                ..Default::default()
            },
            // sing-box sets the OS proxy on start and restores it on a clean exit.
            set_system_proxy: (settings.mode == ConnectionMode::SystemProxy).then_some(true),
            ..Default::default()
        }));
    }

    inbounds
}

// Queries go through the tunnel over DoH. The local server only resolves
// the proxy server's own domain (via `route.default_domain_resolver`).
fn dns(settings: &Settings) -> DNS {
    DNS {
        servers: vec![
            DnsServer::Https(HttpsDnsServer {
                tag: DNS_REMOTE_TAG.into(),
                server: settings.dns_remote.clone(),
                dial: DialerOptions {
                    detour: Some(PROXY_TAG.into()),
                    ..Default::default()
                },
                ..Default::default()
            }),
            DnsServer::Udp(PlainDnsServer {
                tag: DNS_LOCAL_TAG.into(),
                server: settings.dns_direct.clone(),
                ..Default::default()
            }),
        ],
        final_server: Some(DNS_REMOTE_TAG.into()),
        ..Default::default()
    }
}

fn route(settings: &Settings) -> Route {
    let tunnel = settings.mode.uses_tunnel();
    let mut rules = vec![RouteRule {
        action: Some(RuleAction::Sniff),
        ..Default::default()
    }];

    // Only the TUN captures raw DNS packets; proxy clients send domain names.
    if tunnel {
        rules.push(RouteRule {
            protocol: Some(vec!["dns".into()]),
            action: Some(RuleAction::HijackDns),
            ..Default::default()
        });
    }

    if settings.bypass_lan {
        rules.push(RouteRule {
            ip_is_private: Some(true),
            action: Some(RuleAction::Route),
            outbound: Some(DIRECT_TAG.into()),
            ..Default::default()
        });
    }

    Route {
        rules,
        final_outbound: Some(PROXY_TAG.into()),
        // Keeps the proxy's own connections off the TUN (routing loops). Not needed without one.
        auto_detect_interface: tunnel.then_some(true),
        default_domain_resolver: Some(DomainResolver::Tag(DNS_LOCAL_TAG.into())),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::singbox::config::{
        endpoint::{WireguardEndpoint, WireguardPeer},
        outbound::vless::{VlessFlow, VlessOutbound},
        shared::TlsOutbound,
    };
    use serde_json::{Value, json};
    use crate::profile::OpenVpnConfig;

    fn vless_profile() -> Profile {
        Profile::Proxy {
            name: "Germany".into(),
            outbound: Outbound::Vless(VlessOutbound {
                tag: "from-subscription".into(),
                server: "de.example.com".into(),
                server_port: 443,
                uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
                flow: Some(VlessFlow::XtlsRprxVision),
                tls: Some(TlsOutbound {
                    enabled: Some(true),
                    server_name: Some("de.example.com".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    fn wireguard_profile() -> Profile {
        Profile::WireGuard {
            name: "Home".into(),
            endpoint: WireguardEndpoint {
                tag: "wg0".into(),
                address: vec!["10.0.0.2/32".into()],
                private_key: "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=".into(),
                peers: vec![WireguardPeer {
                    address: "203.0.113.1".into(),
                    port: 51820,
                    public_key: "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=".into(),
                    allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
        }
    }

    fn build(profile: &Profile, settings: &Settings) -> Value {
        let config = build_config(profile, settings, Path::new("/data")).unwrap();
        serde_json::to_value(config).unwrap()
    }

    #[test]
    fn proxy_profile_becomes_tagged_outbound() {
        let config = build(&vless_profile(), &Settings::default());

        assert_eq!(config["outbounds"][0]["type"], "vless");
        assert_eq!(config["outbounds"][0]["tag"], PROXY_TAG);
        assert_eq!(config["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(config["outbounds"][1], json!({ "type": "direct", "tag": DIRECT_TAG }));
        assert!(config.get("endpoints").is_none());
    }

    #[test]
    fn wireguard_profile_becomes_endpoint() {
        let config = build(&wireguard_profile(), &Settings::default());

        assert_eq!(config["endpoints"][0]["type"], "wireguard");
        assert_eq!(config["endpoints"][0]["tag"], PROXY_TAG);
        assert_eq!(config["outbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn tun_and_routing_are_set_up() {
        let config = build(&vless_profile(), &Settings::default());

        let tun = &config["inbounds"][0];
        assert_eq!(tun["type"], "tun");
        assert_eq!(tun["stack"], "gvisor");
        assert_eq!(tun["auto_route"], true);
        assert_eq!(tun["strict_route"], true);

        let route = &config["route"];
        assert_eq!(route["final"], PROXY_TAG);
        assert_eq!(route["auto_detect_interface"], true);
        assert_eq!(route["default_domain_resolver"], DNS_LOCAL_TAG);
        assert_eq!(route["rules"][0], json!({ "action": "sniff" }));
        assert_eq!(route["rules"][1], json!({ "action": "hijack-dns", "protocol": ["dns"] }));
        assert_eq!(route["rules"][2]["outbound"], DIRECT_TAG);
    }

    #[test]
    fn remote_dns_goes_through_proxy() {
        let config = build(&vless_profile(), &Settings::default());

        let dns = &config["dns"];
        assert_eq!(dns["final"], DNS_REMOTE_TAG);
        assert_eq!(dns["servers"][0]["type"], "https");
        assert_eq!(dns["servers"][0]["detour"], PROXY_TAG);
        assert_eq!(dns["servers"][1]["type"], "udp");
        assert!(dns["servers"][1].get("detour").is_none());
    }

    #[test]
    fn tunnel_mode_with_extra_proxy_and_no_lan_bypass() {
        let settings = Settings { bypass_lan: false, tunnel_proxy: true, proxy_port: 1080, ..Default::default() };
        let config = build(&vless_profile(), &settings);

        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["inbounds"][1], json!({ "type": "mixed", "tag": MIXED_TAG, "listen": "127.0.0.1", "listen_port": 1080 }));
        assert_eq!(config["route"]["rules"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn proxy_modes_have_no_tun() {
        for (mode, system_proxy) in [(ConnectionMode::SystemProxy, json!(true)), (ConnectionMode::ProxyOnly, Value::Null)] {
            let config = build(&wireguard_profile(), &Settings { mode, ..Default::default() });

            let inbounds = config["inbounds"].as_array().unwrap();
            assert_eq!(inbounds.len(), 1);
            assert_eq!(inbounds[0]["type"], "mixed");
            assert_eq!(inbounds[0]["listen_port"], 2080);
            assert_eq!(inbounds[0]["set_system_proxy"], system_proxy);

            let route = &config["route"];
            assert!(route.get("auto_detect_interface").is_none());
            assert!(!route["rules"].as_array().unwrap().iter().any(|r| r["action"] == "hijack-dns"));
            assert_eq!(route["final"], PROXY_TAG);
        }
    }

    #[test]
    fn openvpn_profile_is_rejected() {
        let profile = Profile::OpenVpn { name: "Work".into(), config: OpenVpnConfig::File("work.ovpn".into()), credentials: None };
        assert!(matches!(
            build_config(&profile, &Settings::default(), Path::new("/data")),
            Err(EngineError::WrongEngine(EngineKind::OpenVpn))
        ));
    }

    /// Runs the real `sing-box check` on generated configs: `cargo test -- --ignored`
    #[test]
    #[ignore = "needs sing-box in PATH"]
    fn generated_configs_pass_sing_box_check() {
        let binary = crate::engine::paths::find_binary("sing-box").expect("sing-box not installed");
        let dir = std::env::temp_dir().join("cipher_client_check");
        std::fs::create_dir_all(&dir).unwrap();

        let modes = [ConnectionMode::Tunnel, ConnectionMode::SystemProxy, ConnectionMode::ProxyOnly];
        for (name, profile) in [("vless", vless_profile()), ("wireguard", wireguard_profile())] {
            for mode in modes {
                let settings = Settings { mode, tunnel_proxy: true, ..Default::default() };
                let config = build_config(&profile, &settings, &dir).unwrap();
                let path = dir.join(format!("{name}-{mode:?}.json"));
                std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

                if let Err(e) = crate::engine::singbox::check(&binary, &path) {
                    panic!("{name} ({mode:?}) config rejected: {e}");
                }
            }
        }
    }
}
