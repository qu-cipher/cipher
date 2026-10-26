//! Xray-core: runs the protocols and transports sing-box doesn't have (XHTTP, mKCP, VLESS
//! encryption), and every VLESS/VMess/Trojan/Shadowsocks config when Settings → Core is Xray.
//! Xray only runs the proxy (SOCKS inbound → one outbound); sing-box sits in front of it for
//! TUN, the local/system proxy and routing rules (see `engine::chain`).

use crate::engine::{chain::{self, Chain}, paths, process::{Process, hide_console}, Engine, EngineError, Status};
use crate::engine::singbox::generate::{DIRECT_TAG, PROXY_TAG, PROXY_LISTEN};
use crate::engine::singbox::config::log::LogLevel;
use crate::profile::{Profile, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{borrow::Cow, net::{SocketAddr, TcpStream}, path::Path, process::Command, time::Duration};

pub mod config;
pub mod convert;

use config::{DomainStrategy, Finalmask, FragmentMask, Mask, Network, NoiseMask, NoisePacket, Sockopt, XrayOutbound};

pub const BINARY: &str = "xray";
const SOCKS_TAG: &str = "socks-in";
/// Tag of Xray's built-in DNS traffic; routed direct.
const DNS_TAG: &str = "dns-direct";

/// Which engine runs VLESS/VMess/Trojan/Shadowsocks configs that both could run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Core {
    #[default]
    SingBox,
    Xray,
}

/// The profile to connect with: with the Xray core, sing-box proxy configs Xray can run
/// become Xray configs. Everything else is unchanged (and keeps its own engine).
pub fn effective<'a>(profile: &'a Profile, settings: &Settings) -> Cow<'a, Profile> {
    if settings.core == Core::Xray
        && let Profile::Proxy { name, outbound } = profile
        && let Some(outbound) = convert::from_singbox(outbound)
    {
        return Cow::Owned(Profile::Xray { name: name.clone(), outbound });
    }
    Cow::Borrowed(profile)
}

/// The whole Xray config: a SOCKS inbound for sing-box, the proxy outbound, and a direct one.
/// Server domains resolve through Xray's own DNS (the direct DNS server, sent directly): in Tunnel
/// mode the system resolver would go through the TUN and back into Xray before it's connected.
fn build_config(outbound: &XrayOutbound, settings: &Settings, socks_port: u16) -> Value {
    let mut outbound = outbound.clone();
    outbound.tag = PROXY_TAG.into();
    let kcp = outbound.network() == Network::Kcp;
    let stream = outbound.stream.get_or_insert_default();
    stream.sockopt = Some(Sockopt { domain_strategy: Some(DomainStrategy::UseIP) });
    stream.finalmask = finalmask(settings, kcp);

    json!({
        "log": { "loglevel": log_level(settings.log_level) },
        "dns": { "servers": [settings.dns_direct], "tag": DNS_TAG },
        "inbounds": [{
            "tag": SOCKS_TAG,
            "listen": PROXY_LISTEN,
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
        }],
        "outbounds": [outbound, { "tag": DIRECT_TAG, "protocol": "freedom" }],
        "routing": { "rules": [{ "inboundTag": [DNS_TAG], "outboundTag": DIRECT_TAG }] },
    })
}

/// Anti-DPI masks from Settings: TLS-hello fragments for TCP transports, noise for mKCP.
fn finalmask(settings: &Settings, kcp: bool) -> Option<Finalmask> {
    let mut mask = Finalmask::default();
    if settings.tls_fragment && !kcp {
        mask.tcp.push(Mask::Fragment(FragmentMask {
            packets: "tlshello".into(),
            lengths: vec!["100-200".into()],
            delays: vec!["10-20".into()],
        }));
    }
    if settings.udp_noise && kcp {
        mask.udp.push(Mask::Noise(NoiseMask {
            reset: "30-60".into(),
            noise: vec![NoisePacket { rand: "10-20".into(), delay: "10-16".into() }],
        }));
    }
    (mask != Finalmask::default()).then_some(mask)
}

fn log_level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace | LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warning",
        _ => "error",
    }
}

/// Validates a config file with `xray run -test`.
pub fn check(binary: &Path, config_path: &Path) -> Result<(), EngineError> {
    let mut command = Command::new(binary);
    command.args(["run", "-test", "-c"]).arg(config_path);
    hide_console(&mut command);
    let output = command.output()?;
    if output.status.success() {
        return Ok(());
    }
    // The reason is the "Failed to start: …" line; Xray prints a banner and warnings first.
    let text = String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr);
    let reason = text
        .lines()
        .rev()
        .find(|line| line.contains("Failed") || line.contains("panic"))
        .or_else(|| text.lines().rev().find(|line| !line.trim().is_empty()))
        .unwrap_or("xray rejected the config");
    Err(EngineError::InvalidConfig(reason.trim().into()))
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok()
}

/// Runs Xray with sing-box in front; sing-box starts once Xray's SOCKS port accepts connections.
#[derive(Default)]
pub struct XrayEngine {
    chain: Option<Chain>,
}

impl Engine for XrayEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let Profile::Xray { name, outbound } = profile else {
            return Err(EngineError::WrongEngine(profile.engine_kind()));
        };
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }
        let binary = paths::find_binary(BINARY)?;
        let data_dir = paths::data_dir()?;
        let socks_port = chain::free_port()?;
        let config_path = data_dir.join("xray.json");
        let config = build_config(outbound, settings, socks_port);
        paths::write_private(&config_path, &serde_json::to_string_pretty(&config)?)?;
        check(&binary, &config_path)?;

        let log_path = data_dir.join("xray.log");
        let process = Process::spawn("xray", &binary, ["run".as_ref(), "-c".as_ref(), config_path.as_os_str()], &log_path)?;
        self.chain = Some(Chain::new(process, log_path, &binary, name, socks_port, None, settings));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.chain.take().map_or(Ok(()), |mut chain| chain.stop())
    }

    fn status(&mut self) -> Status {
        let Some(chain) = self.chain.as_mut() else { return Status::Stopped };
        chain.status(|chain| listening(chain.socks_port()), |_| None)
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
    use crate::engine::singbox::config::{
        outbound::{Outbound, vless::VlessOutbound},
        shared::TlsOutbound,
    };

    pub(crate) fn xhttp_reality() -> XrayOutbound {
        crate::import::xray::tests::parse(
            "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?type=xhttp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab&path=%2Fx&mode=auto#X",
        )
    }

    #[test]
    fn config_has_socks_in_proxy_out_and_direct_dns() {
        let settings = Settings { dns_direct: "9.9.9.9".into(), ..Default::default() };
        let config = build_config(&xhttp_reality(), &settings, 40123);

        assert_eq!(config["inbounds"][0]["port"], 40123);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(config["outbounds"][0]["tag"], PROXY_TAG);
        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(config["outbounds"][0]["streamSettings"]["network"], "xhttp");
        assert_eq!(config["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"], "UseIP");
        assert_eq!(config["outbounds"][1], json!({ "tag": "direct", "protocol": "freedom" }));
        assert_eq!(config["dns"], json!({ "servers": ["9.9.9.9"], "tag": DNS_TAG }));
        assert_eq!(config["routing"]["rules"][0]["outboundTag"], DIRECT_TAG);
        assert_eq!(config["log"]["loglevel"], "info");
    }

    #[test]
    fn anti_dpi_masks_follow_the_transport() {
        let all = Settings { tls_fragment: true, udp_noise: true, ..Default::default() };
        let stream = |config: Value| config["outbounds"][0]["streamSettings"].clone();

        assert!(stream(build_config(&xhttp_reality(), &Settings::default(), 1)).get("finalmask").is_none());

        let xhttp = stream(build_config(&xhttp_reality(), &all, 1));
        assert_eq!(xhttp["finalmask"]["tcp"][0]["type"], "fragment");
        assert_eq!(xhttp["finalmask"]["tcp"][0]["settings"]["packets"], "tlshello");
        assert!(xhttp["finalmask"].get("udp").is_none());

        let kcp = crate::import::xray::tests::samples().into_iter().find(|(_, o)| o.network() == Network::Kcp).unwrap().1;
        let kcp = stream(build_config(&kcp, &all, 1));
        assert_eq!(kcp["finalmask"]["udp"][0]["type"], "noise");
        assert!(kcp["finalmask"].get("tcp").is_none());
    }

    #[test]
    fn core_setting_picks_the_engine() {
        let vless = Profile::Proxy {
            name: "V".into(),
            outbound: Outbound::Vless(VlessOutbound {
                server: "a.example.com".into(),
                server_port: 443,
                uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
                tls: Some(TlsOutbound { enabled: Some(true), server_name: Some("a.example.com".into()), ..Default::default() }),
                ..Default::default()
            }),
        };
        assert!(matches!(*effective(&vless, &Settings::default()), Profile::Proxy { .. }));

        let xray = Settings { core: Core::Xray, ..Default::default() };
        assert!(matches!(*effective(&vless, &xray), Profile::Xray { .. }));

        let wireguard = Profile::WireGuard { name: "W".into(), endpoint: Default::default() };
        assert!(matches!(*effective(&wireguard, &xray), Profile::WireGuard { .. }));
    }

    /// Runs the real `xray run -test` on generated configs. Needs xray in PATH, next to the
    /// app, in `<data>/bin`, or `XRAY_BINARY=/path/to/xray`.
    #[test]
    #[ignore = "needs xray"]
    fn generated_configs_pass_xray_test() {
        let binary = std::env::var_os("XRAY_BINARY")
            .map(Into::into)
            .or_else(|| paths::find_binary(BINARY).ok())
            .expect("xray not installed");
        let dir = std::env::temp_dir().join("cipher_client_xray_check");
        std::fs::create_dir_all(&dir).unwrap();

        for (name, outbound) in crate::import::xray::tests::samples() {
            let path = dir.join(format!("{name}.json"));
            let anti_dpi = Settings { tls_fragment: true, udp_noise: true, ..Default::default() };
            for (variant, settings) in [("plain", Settings::default()), ("anti-dpi", anti_dpi)] {
                let config = build_config(&outbound, &settings, 40123);
                std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
                if let Err(e) = check(&binary, &path) {
                    panic!("{name} ({variant}) rejected: {e}");
                }
            }
        }
    }
}
