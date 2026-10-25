//! Builds a complete client config (TUN + one proxy) from a profile.
//! See docs/singbox-config.md for why each piece is there.

use crate::engine::{EngineError, EngineKind};
use crate::engine::singbox::config::{
    SingBoxConfig,
    dns::{DNS, DnsRule, DnsServer, HttpsDnsServer, PlainDnsServer},
    endpoint::Endpoint,
    experimental::{CacheFile, Experimental},
    inbound::{Inbound, mixed::MixedInbound, tun::{TunInbound, TunStack}},
    log::Log,
    outbound::{Outbound, direct::DirectOutbound},
    route::{Route, RouteRule, RuleAction, RuleSet},
    shared::{DialerOptions, DomainResolver, ListenOptions},
};
use crate::profile::{ConnectionMode, Profile, Settings};
use crate::routing::Target;
use std::path::Path;

mod routing;

pub const PROXY_TAG: &str = "proxy";
pub const DIRECT_TAG: &str = "direct";
const TUN_TAG: &str = "tun-in";
const MIXED_TAG: &str = "mixed-in";
const DNS_REMOTE_TAG: &str = "remote";
const DNS_LOCAL_TAG: &str = "local";

const SCHEMA_URL: &str = "https://sing-box.sagernet.org/schema.json";
const TUN_ADDRESS: [&str; 2] = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"];
pub const PROXY_LISTEN: &str = "127.0.0.1";

/// Traffic from `direct_processes` always goes direct. A chained engine (Psiphon) needs that
/// in Tunnel mode, or its own connections would loop back into it.
pub fn build_config(
    profile: &Profile,
    settings: &Settings,
    data_dir: &Path,
    direct_processes: &[String],
) -> Result<SingBoxConfig, EngineError> {
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
        Profile::Psiphon { .. } => return Err(EngineError::WrongEngine(EngineKind::Psiphon)),
    }

    outbounds.push(Outbound::Direct(DirectOutbound {
        tag: DIRECT_TAG.into(),
        ..Default::default()
    }));

    // Proxy clients send domain names, so IP rules need them resolved first.
    let routed = routing::build(&settings.routing, !settings.mode.uses_tunnel());

    Ok(SingBoxConfig {
        schema: Some(SCHEMA_URL.into()),
        log: Some(Log {
            level: Some(settings.log_level),
            timestamp: Some(true),
            ..Default::default()
        }),
        dns: Some(dns(settings, routed.dns_rules)),
        inbounds: inbounds(settings),
        outbounds,
        endpoints,
        route: Some(route(settings, direct_processes, routed.rules, routed.rule_sets)),
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
// the proxy server's own domain (via `route.default_domain_resolver`)
// and the domains that routing rules send direct.
fn dns(settings: &Settings, rules: Vec<DnsRule>) -> DNS {
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
        rules,
        final_server: Some(DNS_REMOTE_TAG.into()),
        ..Default::default()
    }
}

fn route(settings: &Settings, direct_processes: &[String], routing_rules: Vec<RouteRule>, rule_set: Vec<RuleSet>) -> Route {
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

    // Before any user rule: these must never be proxied.
    if !direct_processes.is_empty() {
        rules.push(RouteRule {
            process_name: Some(direct_processes.to_vec()),
            action: Some(RuleAction::Route),
            outbound: Some(DIRECT_TAG.into()),
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

    rules.extend(routing_rules);

    let final_outbound = match settings.routing.default {
        Target::Direct => DIRECT_TAG,
        _ => PROXY_TAG,
    };

    Route {
        rules,
        rule_set,
        final_outbound: Some(final_outbound.into()),
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
    use crate::routing::{Preset, Routing, Rule, RuleKind, Target};

    fn rule(kind: RuleKind, values: &[&str], target: Target) -> Rule {
        Rule { enabled: true, kind, values: values.iter().map(|v| v.to_string()).collect(), target }
    }

    /// Every rule kind and preset, for the generator and `sing-box check` tests.
    fn full_routing() -> Routing {
        Routing {
            default: Target::Direct,
            presets: Preset::ALL.to_vec(),
            rules: vec![
                rule(RuleKind::App, &["firefox", "/usr/bin/telegram-desktop"], Target::Proxy),
                rule(RuleKind::Domain, &["example.ir"], Target::Proxy),
                rule(RuleKind::Keyword, &["torrent"], Target::Block),
                rule(RuleKind::Ip, &["10.8.0.0/16"], Target::Direct),
                rule(RuleKind::Port, &["25", "6881:6889"], Target::Block),
                rule(RuleKind::Geosite, &["category-ir"], Target::Direct),
                Rule { enabled: false, ..rule(RuleKind::Domain, &["disabled.com"], Target::Block) },
            ],
        }
    }

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
        let config = build_config(profile, settings, Path::new("/data"), &[]).unwrap();
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
            build_config(&profile, &Settings::default(), Path::new("/data"), &[]),
            Err(EngineError::WrongEngine(EngineKind::OpenVpn))
        ));
    }

    #[test]
    fn routing_rules_follow_lan_bypass_in_order() {
        let settings = Settings { routing: full_routing(), ..Default::default() };
        let config = build(&vless_profile(), &settings);
        let route = &config["route"];
        let rules = route["rules"].as_array().unwrap();

        assert_eq!(route["final"], DIRECT_TAG);
        // sniff, hijack-dns, LAN, then the custom rules (app splits in two), then presets.
        assert_eq!(rules[3], json!({ "action": "route", "outbound": PROXY_TAG, "process_name": ["firefox"] }));
        assert_eq!(rules[4], json!({ "action": "route", "outbound": PROXY_TAG, "process_path": ["/usr/bin/telegram-desktop"] }));
        assert_eq!(rules[5], json!({ "action": "route", "outbound": PROXY_TAG, "domain_suffix": ["example.ir"] }));
        assert_eq!(rules[6], json!({ "action": "reject", "domain_keyword": ["torrent"] }));
        assert_eq!(rules[7], json!({ "action": "route", "outbound": DIRECT_TAG, "ip_cidr": ["10.8.0.0/16"] }));
        assert_eq!(rules[8], json!({ "action": "reject", "port": [25], "port_range": ["6881:6889"] }));
        assert_eq!(rules[10], json!({ "action": "reject", "rule_set": ["geosite-category-ads-all"] }));
        assert!(!rules.iter().any(|r| r["domain_suffix"] == json!(["disabled.com"])));
        // Tunnel mode sees IPs, so nothing is resolved up front.
        assert!(!rules.iter().any(|r| r["action"] == "resolve"));

        let rule_sets = route["rule_set"].as_array().unwrap();
        let tags: Vec<&str> = rule_sets.iter().map(|r| r["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, [
            "geosite-category-ir", "geosite-category-ads-all", "geoip-ir",
            "geosite-cn", "geoip-cn", "geosite-category-ru", "geoip-ru",
        ]);
        assert_eq!(rule_sets[2], json!({
            "type": "remote", "tag": "geoip-ir", "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs",
            "download_detour": PROXY_TAG,
        }));
    }

    #[test]
    fn domain_rules_pick_the_dns_server() {
        let settings = Settings { routing: full_routing(), ..Default::default() };
        let config = build(&vless_profile(), &settings);
        let dns_rules = config["dns"]["rules"].as_array().unwrap();

        assert_eq!(dns_rules[0], json!({ "action": "route", "server": DNS_REMOTE_TAG, "domain_suffix": ["example.ir"] }));
        assert_eq!(dns_rules[1], json!({ "action": "reject", "domain_keyword": ["torrent"] }));
        assert_eq!(dns_rules[2], json!({ "action": "route", "server": DNS_LOCAL_TAG, "rule_set": ["geosite-category-ir"] }));
        assert!(dns_rules.iter().all(|r| r.get("rule_set").is_none_or(|s| s[0].as_str().unwrap().starts_with("geosite-"))));
        assert_eq!(config["dns"]["final"], DNS_REMOTE_TAG);
    }

    #[test]
    fn proxy_modes_resolve_before_the_first_ip_rule() {
        let settings = Settings { mode: ConnectionMode::ProxyOnly, routing: full_routing(), ..Default::default() };
        let config = build(&vless_profile(), &settings);
        let rules = config["route"]["rules"].as_array().unwrap();

        let resolve = rules.iter().position(|r| r["action"] == "resolve").unwrap();
        let first_ip = rules.iter().position(|r| r.get("ip_cidr").is_some()).unwrap();
        assert_eq!(resolve + 1, first_ip);
        assert_eq!(rules.iter().filter(|r| r["action"] == "resolve").count(), 1);

        // No IP rules, nothing to resolve.
        let domains_only = Routing { rules: vec![rule(RuleKind::Domain, &["a.com"], Target::Direct)], ..Default::default() };
        let config = build(&vless_profile(), &Settings { mode: ConnectionMode::ProxyOnly, routing: domains_only, ..Default::default() });
        assert!(!config["route"]["rules"].as_array().unwrap().iter().any(|r| r["action"] == "resolve"));
    }

    #[test]
    fn no_routing_adds_nothing() {
        let config = build(&vless_profile(), &Settings::default());
        assert!(config["route"].get("rule_set").is_none());
        assert!(config["dns"].get("rules").is_none());
        assert_eq!(config["route"]["final"], PROXY_TAG);
    }

    #[test]
    fn settings_without_routing_still_load() {
        let settings: Settings = serde_json::from_str(r#"{ "mode": "proxy_only", "bypass_lan": false }"#).unwrap();
        assert_eq!(settings.routing, Routing::default());
        assert_eq!(settings.mode, ConnectionMode::ProxyOnly);
    }

    /// Runs the real `sing-box check` on generated configs: `cargo test -- --ignored`
    #[test]
    #[ignore = "needs sing-box in PATH"]
    fn generated_configs_pass_sing_box_check() {
        let binary = crate::engine::paths::find_binary("sing-box").expect("sing-box not installed");
        let dir = std::env::temp_dir().join("cipher_client_check");
        std::fs::create_dir_all(&dir).unwrap();

        let modes = [ConnectionMode::Tunnel, ConnectionMode::SystemProxy, ConnectionMode::ProxyOnly];
        // Psiphon's sing-box side: a SOCKS outbound to it, its own process routed direct.
        let psiphon = Profile::Proxy {
            name: "Psiphon Tunnel".into(),
            outbound: Outbound::Socks(crate::engine::singbox::config::outbound::socks::SocksOutbound {
                server: "127.0.0.1".into(),
                server_port: 40123,
                version: Some("5".into()),
                network: Some(crate::engine::singbox::config::shared::Network::Tcp),
                ..Default::default()
            }),
        };
        let bypass = ["psiphon-tunnel-core".to_owned()];
        for (name, profile, direct) in [("vless", vless_profile(), &[][..]), ("wireguard", wireguard_profile(), &[]), ("psiphon", psiphon, &bypass)] {
            for mode in modes {
                for (variant, routing) in [("plain", Routing::default()), ("routed", full_routing())] {
                    let settings = Settings { mode, tunnel_proxy: true, routing, ..Default::default() };
                    let config = build_config(&profile, &settings, &dir, direct).unwrap();
                    let path = dir.join(format!("{name}-{mode:?}-{variant}.json"));
                    std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

                    if let Err(e) = crate::engine::singbox::check(&binary, &path) {
                        panic!("{name} ({mode:?}, {variant}) config rejected: {e}");
                    }
                }
            }
        }
    }
}
