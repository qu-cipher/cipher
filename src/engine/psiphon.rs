//! Psiphon: the ConsoleClient (`psiphon-tunnel-core`) finds and connects to Psiphon servers on
//! its own and serves a local SOCKS proxy, with sing-box in front (see `engine::chain`).

use crate::engine::{chain::{self, Chain}, paths, process::Process, Engine, EngineError, Status};
use crate::engine::singbox::config::shared::Network;
use crate::profile::{Profile, Settings};
use serde_json::{Map, Value};
use std::{ffi::OsStr, fs, path::Path};

pub const BINARY: &str = "psiphon-tunnel-core";

/// Psiphon is hidden until there's a network config to ship: Psiphon doesn't publish one for its
/// public servers, integrators request it from the Psiphon team (possibly under a contract).
/// While false there's no Psiphon Tunnel entry, engine row or Psiphon settings.
pub const ENABLED: bool = false;

/// Exit countries Psiphon offers: (ISO code, name). Empty code = fastest server anywhere.
pub const REGIONS: [(&str, &str); 29] = [
    ("", "Fastest"),
    ("AT", "Austria"), ("BE", "Belgium"), ("BG", "Bulgaria"), ("CA", "Canada"), ("CH", "Switzerland"),
    ("CZ", "Czechia"), ("DE", "Germany"), ("DK", "Denmark"), ("EE", "Estonia"), ("ES", "Spain"),
    ("FI", "Finland"), ("FR", "France"), ("GB", "United Kingdom"), ("HU", "Hungary"), ("IE", "Ireland"),
    ("IN", "India"), ("IT", "Italy"), ("JP", "Japan"), ("LV", "Latvia"), ("NL", "Netherlands"),
    ("NO", "Norway"), ("PL", "Poland"), ("RO", "Romania"), ("RS", "Serbia"), ("SE", "Sweden"),
    ("SG", "Singapore"), ("SK", "Slovakia"), ("US", "United States"),
];

/// Fields a network config must have to reach the Psiphon network.
const REQUIRED: [&str; 2] = ["PropagationChannelId", "SponsorId"];

/// Whether a file's text looks like a Psiphon client config.
pub fn looks_like_network(text: &str) -> bool {
    text.contains("\"PropagationChannelId\"")
}

/// Reads the network part of a Psiphon JSON client config.
pub fn parse_network(text: &str) -> Result<Map<String, Value>, String> {
    let Ok(Value::Object(network)) = serde_json::from_str(text) else {
        return Err("not a JSON object".into());
    };
    for field in REQUIRED {
        if !network.get(field).and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty()) {
            return Err(format!("{field} is missing"));
        }
    }
    Ok(network)
}

/// The full client config: the imported network fields, with the local parts set by us.
fn client_config(network: &Map<String, Value>, region: &str, data_root: &Path, socks_port: u16) -> Map<String, Value> {
    let mut config = network.clone();
    let mut set = |key: &str, value: Value| {
        config.insert(key.into(), value);
    };
    set("DataRootDirectory", data_root.to_string_lossy().into());
    set("LocalSocksProxyPort", socks_port.into());
    set("DisableLocalHTTPProxy", true.into());
    set("EgressRegion", region.into());
    // Only sing-box talks to it, on loopback.
    config.remove("ListenInterface");
    config.remove("DisableLocalSocksProxy");
    config.remove("UseNoticeFiles");
    config
}

/// Psiphon writes one JSON notice per line: `{"noticeType":"Tunnels","data":{"count":1},…}`.
fn notices(log: &str) -> impl DoubleEndedIterator<Item = Value> + '_ {
    log.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok())
}

/// Number of established tunnels, from the latest `Tunnels` notice.
fn tunnel_count(log: &str) -> u64 {
    notices(log)
        .rev()
        .find(|n| n["noticeType"] == "Tunnels")
        .and_then(|n| n["data"]["count"].as_u64())
        .unwrap_or(0)
}

/// Why Psiphon stopped, from the latest `Error` notice.
fn last_error(log: &str) -> Option<String> {
    notices(log)
        .rev()
        .find(|n| n["noticeType"] == "Error")
        .and_then(|n| n["data"]["message"].as_str().map(str::to_owned))
}

/// Runs Psiphon with sing-box in front; sing-box starts once Psiphon reports a tunnel.
#[derive(Default)]
pub struct PsiphonEngine {
    chain: Option<Chain>,
}

impl Engine for PsiphonEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let Profile::Psiphon { name } = profile else {
            return Err(EngineError::WrongEngine(profile.engine_kind()));
        };
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }
        let network = settings.psiphon.network.as_ref().ok_or(EngineError::PsiphonNetworkMissing)?;
        let binary = paths::find_binary(BINARY)?;

        let data_dir = paths::data_dir()?;
        let data_root = data_dir.join("psiphon");
        fs::create_dir_all(&data_root)?;
        let socks_port = chain::free_port()?;
        let config_path = data_dir.join("psiphon.json");
        let config = client_config(network, &settings.psiphon.region, &data_root, socks_port);
        paths::write_private(&config_path, &serde_json::to_string_pretty(&config)?)?;

        let log_path = data_dir.join("psiphon.log");
        let process = Process::spawn(
            "psiphon",
            &binary,
            [OsStr::new("-config"), config_path.as_os_str(), OsStr::new("-dataRootDirectory"), data_root.as_os_str()],
            &log_path,
        )?;
        // Psiphon's SOCKS proxy only forwards TCP: UDP fails fast instead of timing out.
        self.chain = Some(Chain::new(process, log_path, &binary, name, socks_port, Some(Network::Tcp), settings));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.chain.take().map_or(Ok(()), |mut chain| chain.stop())
    }

    fn status(&mut self) -> Status {
        let Some(chain) = self.chain.as_mut() else { return Status::Stopped };
        chain.status(
            |chain| tunnel_count(&chain.log()) > 0,
            |log| last_error(log).map(|e| format!("psiphon exited: {e}")),
        )
    }

    fn ready(&mut self) -> bool {
        self.chain.as_mut().is_some_and(Chain::ready)
    }

    fn authorized(&mut self) -> bool {
        self.chain.as_mut().is_some_and(Chain::authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::singbox::{config::outbound::{Outbound, socks::SocksOutbound}, generate::build_config};

    const NETWORK: &str = r#"{
        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "0000000000000000",
        "RemoteServerListURLs": [{ "URL": "https://example.com/list", "OnlyAfterAttempts": 0 }],
        "LocalHttpProxyPort": 8080,
        "ListenInterface": "any",
        "EgressRegion": "US"
    }"#;

    #[test]
    fn network_config_is_validated() {
        assert!(looks_like_network(NETWORK));
        assert!(parse_network(NETWORK).is_ok());
        assert_eq!(parse_network(r#"{ "SponsorId": "x" }"#).unwrap_err(), "PropagationChannelId is missing");
        assert_eq!(parse_network(r#"{ "PropagationChannelId": "x", "SponsorId": " " }"#).unwrap_err(), "SponsorId is missing");
        assert!(parse_network("[1]").is_err());
    }

    #[test]
    fn client_config_keeps_network_and_sets_local_parts() {
        let network = parse_network(NETWORK).unwrap();
        let config = client_config(&network, "DE", Path::new("/data/psiphon"), 40123);

        assert_eq!(config["PropagationChannelId"], "FFFFFFFFFFFFFFFF");
        assert_eq!(config["RemoteServerListURLs"][0]["URL"], "https://example.com/list");
        assert_eq!(config["LocalSocksProxyPort"], 40123);
        assert_eq!(config["DisableLocalHTTPProxy"], true);
        assert_eq!(config["DataRootDirectory"], "/data/psiphon");
        assert_eq!(config["EgressRegion"], "DE");
        assert!(config.get("ListenInterface").is_none());
    }

    #[test]
    fn reads_notices() {
        let log = r#"{"data":{"count":0},"noticeType":"Tunnels","timestamp":"2026-10-26T00:00:00.000Z"}
not json
{"data":{"count":1},"noticeType":"Tunnels","timestamp":"2026-10-26T00:00:01.000Z"}
{"data":{"message":"error loading configuration file: bad"},"noticeType":"Error","timestamp":"2026-10-26T00:00:02.000Z"}"#;
        assert_eq!(tunnel_count(log), 1);
        assert_eq!(tunnel_count(""), 0);
        assert_eq!(last_error(log).unwrap(), "error loading configuration file: bad");
        assert_eq!(last_error("{}"), None);
    }

    #[test]
    fn needs_a_network_config() {
        let profile = Profile::Psiphon { name: "Psiphon Tunnel".into() };
        let result = PsiphonEngine::default().start(&profile, &Settings::default());
        assert!(matches!(result, Err(EngineError::PsiphonNetworkMissing)));
    }

    #[test]
    fn singbox_side_chains_to_psiphon_and_lets_it_out_directly() {
        let profile = Profile::Proxy {
            name: "Psiphon Tunnel".into(),
            outbound: Outbound::Socks(SocksOutbound {
                server: "127.0.0.1".into(),
                server_port: 40123,
                version: Some("5".into()),
                network: Some(Network::Tcp),
                ..Default::default()
            }),
        };
        let config = build_config(&profile, &Settings::default(), Path::new("/data"), &[BINARY.into()]).unwrap();
        let config = serde_json::to_value(config).unwrap();

        assert_eq!(config["outbounds"][0], serde_json::json!({
            "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 40123, "version": "5", "network": "tcp"
        }));
        // Right after sniff and hijack-dns, before LAN bypass and user rules.
        assert_eq!(config["route"]["rules"][2], serde_json::json!({
            "action": "route", "outbound": "direct", "process_name": [BINARY]
        }));
    }
}
