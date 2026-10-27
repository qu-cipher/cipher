//! Psiphon: the ConsoleClient (`psiphon-tunnel-core`) connects to the user's own Psiphon server
//! (a server entry from `psiphond generate`) or private network (a client config) and serves a
//! local SOCKS proxy, with sing-box in front (see `engine::chain`).

use crate::engine::{chain::{self, Chain}, paths, process::Process, traffic::Traffic, Assist, Engine, EngineError, Status};
use crate::engine::singbox::config::shared::Network;
use crate::profile::{Profile, PsiphonSource, Settings};
use serde_json::{Map, Value};
use std::{ffi::OsStr, fs, path::Path};

pub const BINARY: &str = "psiphon-tunnel-core";

/// A self-hosted psiphond accepts any ids; these are the ones from Psiphon's own example config.
const PROPAGATION_CHANNEL_ID: &str = "24BCA4EE20BEB92C";
const SPONSOR_ID: &str = "721AE60D76700F5A";

/// The full client config. A server entry is used exclusively (`TargetServerEntry`), without
/// server list downloads; a network config is kept as imported. The local parts are set by us.
fn client_config(source: &PsiphonSource, data_root: &Path, socks_port: u16) -> Map<String, Value> {
    let mut config = match source {
        PsiphonSource::ServerEntry(entry) => Map::from_iter([
            ("PropagationChannelId".into(), PROPAGATION_CHANNEL_ID.into()),
            ("SponsorId".into(), SPONSOR_ID.into()),
            ("TargetServerEntry".into(), entry.as_str().into()),
            ("DisableRemoteServerListFetcher".into(), true.into()),
        ]),
        PsiphonSource::Network(network) => network.clone(),
    };
    let mut set = |key: &str, value: Value| {
        config.insert(key.into(), value);
    };
    set("DataRootDirectory", data_root.to_string_lossy().into());
    set("LocalSocksProxyPort", socks_port.into());
    set("DisableLocalHTTPProxy", true.into());
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
    assist: Assist,
}

impl Engine for PsiphonEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let Profile::Psiphon { name, source } = profile else {
            return Err(EngineError::WrongEngine(profile.engine_kind()));
        };
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }
        let binary = paths::find_binary(BINARY)?;

        let data_dir = paths::data_dir()?;
        let data_root = data_dir.join("psiphon");
        fs::create_dir_all(&data_root)?;
        let socks_port = chain::free_port()?;
        let config_path = data_dir.join("psiphon.json");
        let config = client_config(source, &data_root, socks_port);
        paths::write_private(&config_path, &serde_json::to_string_pretty(&config)?)?;

        let log_path = data_dir.join("psiphon.log");
        let process = Process::spawn(
            "psiphon",
            &binary,
            [OsStr::new("-config"), config_path.as_os_str(), OsStr::new("-dataRootDirectory"), data_root.as_os_str()],
            &log_path,
        )?;
        // Psiphon's SOCKS proxy only forwards TCP: UDP fails fast instead of timing out.
        self.chain = Some(Chain::new(process, log_path, &binary, name, socks_port, Some(Network::Tcp), settings, self.assist.clone()));
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

    fn traffic(&mut self) -> Option<Traffic> {
        self.chain.as_mut()?.traffic()
    }

    fn assist(&mut self, assist: Assist) {
        self.assist = assist;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::singbox::{config::outbound::{Outbound, socks::SocksOutbound}, generate::build_config};

    #[test]
    fn server_entry_config_targets_the_server() {
        let source = PsiphonSource::ServerEntry("abcd".into());
        let config = client_config(&source, Path::new("/data/psiphon"), 40123);

        assert_eq!(config["TargetServerEntry"], "abcd");
        assert_eq!(config["DisableRemoteServerListFetcher"], true);
        assert_eq!(config["PropagationChannelId"], PROPAGATION_CHANNEL_ID);
        assert_eq!(config["LocalSocksProxyPort"], 40123);
        assert_eq!(config["DisableLocalHTTPProxy"], true);
        assert_eq!(config["DataRootDirectory"], "/data/psiphon");
    }

    #[test]
    fn network_config_keeps_its_fields_and_sets_local_parts() {
        let network = crate::import::psiphon::parse_network(crate::import::psiphon::tests::NETWORK).unwrap();
        let config = client_config(&PsiphonSource::Network(network), Path::new("/data/psiphon"), 40123);

        assert_eq!(config["PropagationChannelId"], "FFFFFFFFFFFFFFFF");
        assert_eq!(config["RemoteServerListURLs"][0]["URL"], "https://example.com/list");
        assert_eq!(config["EgressRegion"], "US");
        assert_eq!(config["LocalSocksProxyPort"], 40123);
        assert_eq!(config["DisableLocalHTTPProxy"], true);
        assert_eq!(config["DataRootDirectory"], "/data/psiphon");
        assert!(config.get("ListenInterface").is_none());
        assert!(config.get("TargetServerEntry").is_none());
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
    fn singbox_side_chains_to_psiphon_and_lets_it_out_directly() {
        let profile = Profile::Proxy {
            name: "Psiphon 203.0.113.7".into(),
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
