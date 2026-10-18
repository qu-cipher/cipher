//! Subscriptions that serve a whole sing-box config: its proxy outbounds and WireGuard
//! endpoints become profiles. Our own TUN/DNS/route settings replace everything else.

use crate::engine::singbox::config::{endpoint::Endpoint, outbound::Outbound};
use crate::import::subscription::Subscription;
use crate::profile::Profile;
use serde_json::Value;

/// Outbound types that route traffic but aren't servers.
const NOT_SERVERS: [&str; 5] = ["direct", "block", "dns", "selector", "urltest"];

/// `None` if `text` isn't a sing-box config.
pub fn parse_singbox_json(text: &str) -> Option<Subscription> {
    let config: Value = serde_json::from_str(text.trim()).ok()?;
    let outbounds = config.get("outbounds").and_then(Value::as_array);
    let endpoints = config.get("endpoints").and_then(Value::as_array);
    if outbounds.is_none() && endpoints.is_none() {
        return None;
    }

    let mut subscription = Subscription::default();
    for value in outbounds.into_iter().flatten().chain(endpoints.into_iter().flatten()) {
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("?");
        if NOT_SERVERS.contains(&kind) {
            continue;
        }
        match to_profile(value.clone()) {
            Ok(profile) => subscription.profiles.push(profile),
            Err(reason) => subscription.skipped.push(format!("{kind}: {reason}")),
        }
    }
    Some(subscription)
}

fn to_profile(mut value: Value) -> Result<Profile, String> {
    let name = value.get("tag").and_then(Value::as_str).unwrap_or_default().to_owned();

    // A chained proxy points at another outbound by tag, which won't exist on its own.
    if value.get("detour").is_some() {
        return Err("chained through another outbound (detour), not supported".into());
    }
    // These name DNS servers of the original config; ours sets a default resolver instead.
    if let Some(object) = value.as_object_mut() {
        object.remove("domain_resolver");
    }

    if value.get("type").and_then(Value::as_str) == Some("wireguard") {
        // Before sing-box 1.11 WireGuard was an outbound with different fields.
        if value.get("peers").is_none() {
            return Err("old-style WireGuard outbound (sing-box < 1.11), not supported".into());
        }
        let Endpoint::Wireguard(endpoint) = serde_json::from_value(value).map_err(|e| e.to_string())?;
        return Ok(Profile::WireGuard { name: fallback_name(name, "WireGuard"), endpoint });
    }

    let outbound: Outbound = serde_json::from_value(value).map_err(|e| unsupported(&e.to_string()))?;
    Ok(Profile::Proxy { name: fallback_name(name, "Server"), outbound })
}

fn fallback_name(tag: String, default: &str) -> String {
    if tag.trim().is_empty() { default.into() } else { tag }
}

/// serde's "unknown variant `naive`, expected one of …" → "unsupported type".
fn unsupported(error: &str) -> String {
    if error.starts_with("unknown variant") { "unsupported type".into() } else { error.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    #[test]
    fn takes_servers_and_skips_the_rest() {
        let subscription = parse_singbox_json(&fixture("vless_reality.json")).unwrap();
        let names: Vec<_> = subscription.profiles.iter().map(Profile::name).collect();
        let protocols: Vec<_> = subscription.profiles.iter().map(Profile::protocol).collect();
        assert_eq!(names, ["proxy", "vmess-ws", "trojan-grpc", "ss"]);
        assert_eq!(protocols, ["vless", "vmess", "trojan", "ss"]);
        assert!(subscription.skipped.is_empty());
    }

    #[test]
    fn wireguard_endpoints() {
        let subscription = parse_singbox_json(&fixture("wireguard.json")).unwrap();
        assert!(matches!(subscription.profiles.as_slice(), [Profile::WireGuard { .. }]));
    }

    #[test]
    fn unsupported_and_chained_outbounds_are_reported() {
        let json = r#"{"outbounds":[
            {"type":"naive","tag":"n","server":"x","server_port":443},
            {"type":"trojan","tag":"chained","server":"x","server_port":443,"password":"p","detour":"other"},
            {"type":"wireguard","tag":"old","server":"x","server_port":1,"local_address":["10.0.0.2/32"]},
            {"type":"trojan","tag":"ok","server":"x","server_port":443,"password":"p","domain_resolver":"their-dns"}
        ]}"#;
        let subscription = parse_singbox_json(json).unwrap();
        assert_eq!(subscription.profiles.len(), 1);
        assert_eq!(subscription.skipped, [
            "naive: unsupported type",
            "trojan: chained through another outbound (detour), not supported",
            "wireguard: old-style WireGuard outbound (sing-box < 1.11), not supported",
        ]);
    }

    #[test]
    fn not_a_singbox_config() {
        assert!(parse_singbox_json("vless://abc").is_none());
        assert!(parse_singbox_json(r#"{"hello":"world"}"#).is_none());
    }

    /// Every profile lifted from the fixtures must still pass `sing-box check` in our generated config.
    #[test]
    #[ignore = "needs sing-box in PATH"]
    fn imported_profiles_pass_sing_box_check() {
        use crate::engine::singbox::{check, generate::build_config};
        use crate::profile::Settings;

        let binary = crate::engine::paths::find_binary("sing-box").expect("sing-box not installed");
        let dir = std::env::temp_dir().join("cipher_client_json_check");
        std::fs::create_dir_all(&dir).unwrap();
        for file in ["vless_reality.json", "hysteria2.json", "wireguard.json"] {
            for (i, profile) in parse_singbox_json(&fixture(file)).unwrap().profiles.iter().enumerate() {
                let path = dir.join(format!("{file}-{i}.json"));
                let config = build_config(profile, &Settings::default(), &dir).unwrap();
                std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
                if let Err(e) = check(&binary, &path) {
                    panic!("{file} / {}: {e}", profile.name());
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
