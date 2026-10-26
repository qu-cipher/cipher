//! Running plugins (see `crate::plugin`):
//! - [`PluginEngine`] runs an engine plugin's config: the plugin serves SOCKS on a free loopback
//!   port, and sing-box starts in front of it once it's ready (`engine::chain`).
//! - [`Transported`] runs any proxy config through a transport plugin: the plugin starts first, and
//!   the config's engine then dials `127.0.0.1:<plugin port>` instead of the server.
//!
//! A plugin that needs root runs in the admin helper (`engine::elevated`), which sing-box's TUN
//! joins in Tunnel mode, so it's still one password prompt.

use crate::engine::{
    chain::{self, Chain},
    elevated::Elevated,
    paths,
    process::Process,
    Assist, Engine, EngineError, Status,
};
use crate::engine::singbox::config::shared::{Network as SingBoxNetwork, TransportOptions};
use crate::engine::xray::config::{Network as XrayNetwork, Security};
use crate::plugin::{self, Installed, Kind, Network, Ready, TransportUse, Values};
use crate::profile::{Profile, Settings};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

const LOOPBACK: &str = "127.0.0.1";

/// A started plugin process.
struct Launched {
    process: Process,
    port: u16,
    ready: Ready,
    /// The admin helper it runs in (root plugins).
    elevated: Option<Arc<Elevated>>,
    /// Its process name, routed direct by sing-box.
    process_name: String,
    log_path: PathBuf,
}

impl Launched {
    fn is_ready(&self) -> bool {
        ready_now(&self.ready, self.port, &self.log_path)
    }
}

/// Whether a plugin is ready: its port accepts connections, or its log has the text.
fn ready_now(ready: &Ready, port: u16, log_path: &std::path::Path) -> bool {
    match ready {
        Ready::Port(_) => TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok(),
        Ready::Log(text) => fs::read_to_string(log_path).is_ok_and(|log| log.contains(text.as_str())),
    }
}

fn plugin_error(message: impl Into<String>) -> EngineError {
    EngineError::Plugin(message.into())
}

/// Loads an installed plugin of the expected kind that may run now.
fn load(id: &str, kind: Kind) -> Result<Installed, EngineError> {
    let plugin = plugin::load(&paths::data_dir()?, id).map_err(plugin_error)?;
    if plugin.manifest.kind != kind {
        return Err(plugin_error(format!("{} isn't a {} plugin", plugin.manifest.name, crate::plugin::install::kind_label(kind).to_lowercase())));
    }
    if !plugin.usable() {
        return Err(plugin_error(format!("{} needs administrator rights: allow them in Plugins", plugin.manifest.name)));
    }
    Ok(plugin)
}

/// The admin helper for a root plugin: through pkexec on Linux; Windows runs the whole app elevated.
fn admin_helper() -> Result<Option<Arc<Elevated>>, EngineError> {
    if cfg!(windows) {
        return Ok(None);
    }
    #[cfg(test)]
    return Ok(Some(crate::engine::elevated::tests::in_process()));
    #[cfg(not(test))]
    Ok(Some(Elevated::start()?))
}

/// Writes the plugin's config file (if it has a template) and starts it on `port`.
fn launch(plugin: &Installed, fields: &BTreeMap<String, String>, port: u16, extra: Values) -> Result<Launched, EngineError> {
    let manifest = &plugin.manifest;
    let data_dir = paths::data_dir()?;
    let work = plugin::plugins_dir(&data_dir).join(&manifest.id).join("data");
    fs::create_dir_all(&work)?;

    let fields = manifest.fill_fields(fields).map_err(|e| plugin_error(format!("{}: {e}", manifest.name)))?;
    let mut values = plugin::field_values(&fields);
    values.insert("listen_port".into(), port.to_string());
    values.insert("data_dir".into(), work.display().to_string());
    values.extend(extra);
    if let Some(template) = &manifest.config_template {
        let path = work.join(&manifest.config_file_name);
        values.insert("config_file".into(), path.display().to_string());
        let text = plugin::render(template, &values).map_err(plugin_error)?;
        paths::write_private(&path, &text)?;
    }
    let args = manifest
        .args
        .iter()
        .map(|arg| plugin::render(arg, &values).map(OsString::from))
        .collect::<Result<Vec<_>, _>>()
        .map_err(plugin_error)?;

    let log_path = data_dir.join(format!("plugin-{}.log", manifest.id));
    let name = manifest.name.as_str();
    let (process, elevated) = match manifest.needs_root.then(admin_helper).transpose()?.flatten() {
        Some(helper) => (Process::spawn_in(&helper, name, &plugin.binary, &args, &log_path)?, Some(helper)),
        None => (Process::spawn(name, &plugin.binary, &args, &log_path)?, None),
    };
    let process_name = plugin.binary.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    Ok(Launched { process, port, ready: manifest.ready.clone(), elevated, process_name, log_path })
}

// ───────────────────────────── Engine plugins ─────────────────────────────

/// Runs a `Profile::Plugin` config: the plugin, then sing-box in front of its SOCKS port.
#[derive(Default)]
pub struct PluginEngine {
    chain: Option<Chain>,
    /// How to tell the plugin is ready: (check, port, log).
    ready: Option<(Ready, u16, PathBuf)>,
    assist: Assist,
}

impl Engine for PluginEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let Profile::Plugin { name, plugin: id, link, fields } = profile else {
            return Err(EngineError::WrongEngine(profile.engine_kind()));
        };
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }
        let plugin = load(id, Kind::Engine)?;
        let port = chain::free_port()?;
        let extra = Values::from([("link".into(), link.clone().unwrap_or_default())]);
        let launched = launch(&plugin, fields, port, extra)?;

        let network = match plugin.manifest.network {
            Network::Tcp => Some(SingBoxNetwork::Tcp),
            Network::Udp => Some(SingBoxNetwork::Udp),
            Network::Both => None,
        };
        // A root plugin's helper also runs sing-box's TUN: one password prompt.
        let assist = Assist { elevated: launched.elevated.clone().or(self.assist.elevated.clone()), ..self.assist.clone() };
        self.ready = Some((launched.ready.clone(), port, launched.log_path.clone()));
        self.chain = Some(Chain::new(launched.process, launched.log_path, &plugin.binary, name, port, network, settings, assist));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.chain.take().map_or(Ok(()), |mut chain| chain.stop())
    }

    fn status(&mut self) -> Status {
        let (Some(chain), Some((ready, port, log_path))) = (self.chain.as_mut(), self.ready.as_ref()) else { return Status::Stopped };
        chain.status(|_| ready_now(ready, *port, log_path), |_| None)
    }

    fn ready(&mut self) -> bool {
        self.chain.as_mut().is_some_and(Chain::ready)
    }

    fn authorized(&mut self) -> bool {
        self.chain.as_mut().is_some_and(Chain::authorized)
    }

    fn assist(&mut self, assist: Assist) {
        self.assist = assist;
    }
}

// ───────────────────────────── Transport plugins ─────────────────────────────

/// Runs a config through a transport plugin: the plugin first, then the config's own engine
/// (sing-box or Xray), pointed at the plugin.
pub struct Transported {
    transport: TransportUse,
    inner: Box<dyn Engine + Send>,
    plugin: Option<Launched>,
    /// The rewritten config, started once the plugin is ready.
    pending: Option<(Profile, Settings)>,
    started: bool,
}

impl Transported {
    pub fn new(inner: Box<dyn Engine + Send>, transport: TransportUse) -> Self {
        Self { transport, inner, plugin: None, pending: None, started: false }
    }

    fn start_inner(&mut self) -> Result<(), EngineError> {
        let (Some((profile, settings)), Some(plugin)) = (self.pending.take(), self.plugin.as_ref()) else { return Ok(()) };
        self.inner.assist(Assist { elevated: plugin.elevated.clone(), direct_processes: vec![plugin.process_name.clone()] });
        self.inner.start(&profile, &settings)?;
        self.started = true;
        Ok(())
    }
}

impl Engine for Transported {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let plugin = load(&self.transport.plugin, Kind::Transport)?;
        let port = chain::free_port()?;
        let (rewritten, server, server_port, udp) = rewrite(profile, port)?;
        let needed = if udp { Network::Udp } else { Network::Tcp };
        if plugin.manifest.network != Network::Both && plugin.manifest.network != needed {
            let (has, wants) = if udp { ("TCP", "UDP") } else { ("UDP", "TCP") };
            return Err(plugin_error(format!("{} only carries {has}, and this config uses {wants}", plugin.manifest.name)));
        }
        let extra = Values::from([("server".into(), server), ("server_port".into(), server_port.to_string())]);
        self.plugin = Some(launch(&plugin, &self.transport.fields, port, extra)?);
        self.pending = Some((rewritten, settings.clone()));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.pending = None;
        let inner = if std::mem::take(&mut self.started) { self.inner.stop() } else { Ok(()) };
        if let Some(mut plugin) = self.plugin.take() {
            plugin.process.stop()?;
        }
        inner
    }

    fn status(&mut self) -> Status {
        let Some(plugin) = self.plugin.as_mut() else { return Status::Stopped };
        if let Status::Failed(reason) = plugin.process.status() {
            return Status::Failed(reason);
        }
        if self.pending.is_some() && plugin.is_ready() && let Err(e) = self.start_inner() {
            return Status::Failed(e.to_string());
        }
        match self.started {
            true => self.inner.status(),
            false => Status::Running,
        }
    }

    fn ready(&mut self) -> bool {
        self.started && self.inner.ready()
    }

    /// False until the config's engine runs (the plugin still starting, or the password dialog open).
    fn authorized(&mut self) -> bool {
        self.started && self.inner.authorized()
    }
}

/// The config pointed at the transport on `port`: (config, original server, original port, uses UDP).
/// The TLS server name and the HTTP Host keep the original server, or they'd become 127.0.0.1.
fn rewrite(profile: &Profile, port: u16) -> Result<(Profile, String, u16, bool), EngineError> {
    match profile {
        Profile::Proxy { name, outbound } => {
            let mut outbound = outbound.clone();
            let udp = outbound.uses_udp();
            let (server, server_port) = outbound.server_mut().ok_or_else(|| plugin_error("this config has no server to carry"))?;
            let original = (std::mem::replace(server, LOOPBACK.into()), std::mem::replace(server_port, port));
            if let crate::engine::singbox::config::outbound::Outbound::Hysteria2(o) = &mut outbound {
                o.server_ports = None;
            }
            if let Some(tls) = outbound.tls_mut() && tls.enabled == Some(true) {
                tls.server_name.get_or_insert_with(|| original.0.clone());
            }
            match outbound.transport_mut() {
                Some(TransportOptions::Ws(ws)) => {
                    let headers = ws.headers.get_or_insert_default();
                    if !headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                        headers.insert("Host".into(), original.0.clone());
                    }
                }
                Some(TransportOptions::HttpUpgrade(upgrade)) => {
                    upgrade.host.get_or_insert_with(|| original.0.clone());
                }
                Some(TransportOptions::Http(http)) => {
                    http.host.get_or_insert_with(|| vec![original.0.clone()]);
                }
                _ => {}
            }
            Ok((Profile::Proxy { name: name.clone(), outbound }, original.0, original.1, udp))
        }
        Profile::Xray { name, outbound } => {
            let mut outbound = outbound.clone();
            let udp = outbound.network() == XrayNetwork::Kcp;
            let (server, server_port) = outbound.server_mut().ok_or_else(|| plugin_error("this config has no server to carry"))?;
            let original = (std::mem::replace(server, LOOPBACK.into()), std::mem::replace(server_port, port));
            if let Some(stream) = outbound.stream.as_mut() {
                let host = || original.0.clone();
                if stream.security == Some(Security::Tls) {
                    stream.tls_settings.get_or_insert_default().server_name.get_or_insert_with(host);
                }
                if let Some(reality) = stream.reality_settings.as_mut() {
                    reality.server_name.get_or_insert_with(host);
                }
                if let Some(ws) = stream.ws_settings.as_mut() {
                    ws.host.get_or_insert_with(host);
                }
                if let Some(upgrade) = stream.httpupgrade_settings.as_mut() {
                    upgrade.host.get_or_insert_with(host);
                }
                if let Some(xhttp) = stream.xhttp_settings.as_mut() {
                    xhttp.host.get_or_insert_with(host);
                }
            }
            Ok((Profile::Xray { name: name.clone(), outbound }, original.0, original.1, udp))
        }
        _ => Err(plugin_error("transport plugins work with proxy configs (VLESS, Trojan, Shadowsocks, …), not this kind")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse_link;
    use serde_json::Value;

    fn rewritten(link: &str) -> (Value, String, u16, bool) {
        let profile = crate::engine::xray::effective(&parse_link(link).unwrap(), &Settings::default()).into_owned();
        let (profile, server, port, udp) = rewrite(&profile, 40000).unwrap();
        (serde_json::to_value(&profile).unwrap(), server, port, udp)
    }

    #[test]
    fn rewrite_keeps_the_server_name_and_host() {
        let (json, server, port, udp) = rewritten("vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls&type=ws&path=%2Fws#WS");
        assert_eq!((server.as_str(), port, udp), ("a.example.com", 443, false));
        let outbound = &json["outbound"];
        assert_eq!(outbound["server"], "127.0.0.1");
        assert_eq!(outbound["server_port"], 40000);
        assert_eq!(outbound["tls"]["server_name"], "a.example.com");
        assert_eq!(outbound["transport"]["headers"]["Host"], "a.example.com");

        // An explicit SNI stays as it was.
        let (json, ..) = rewritten("trojan://pw@1.2.3.4:443?sni=cdn.example.com#T");
        assert_eq!(json["outbound"]["tls"]["server_name"], "cdn.example.com");

        // QUIC protocols need a UDP transport.
        let (json, _, _, udp) = rewritten("hy2://pw@h.example.com:443?mport=443,5000-6000#H");
        assert!(udp);
        assert!(json["outbound"].get("server_ports").is_none());

        // Xray configs: address, serverName and XHTTP host.
        let (json, server, _, udp) = rewritten("vless://bf000d23-0752-40b4-affe-68f7707a9661@x.example.com:443?type=xhttp&security=tls&path=%2Fx#X");
        assert_eq!((server.as_str(), udp), ("x.example.com", false));
        let outbound = &json["outbound"];
        assert_eq!(outbound["settings"]["vnext"][0]["address"], "127.0.0.1");
        assert_eq!(outbound["streamSettings"]["tlsSettings"]["serverName"], "x.example.com");
        assert_eq!(outbound["streamSettings"]["xhttpSettings"]["host"], "x.example.com");

        let wireguard = Profile::WireGuard { name: "W".into(), endpoint: Default::default() };
        assert!(rewrite(&wireguard, 1).is_err());
    }

    /// End to end, on localhost only: sing-box plays the plugins and the "server".
    #[cfg(unix)]
    mod e2e {
        use super::*;

        use crate::engine::singbox::config::outbound::{Outbound, socks::SocksOutbound};
        use crate::plugin::{InstallRecord, MANIFEST_FILE, Manifest, binary_name, plugins_dir};
        use crate::profile::ConnectionMode;
        use std::{
            io::{Read, Write},
            net::TcpListener,
            path::Path,
            process::{Child, Command},
            thread,
            time::Instant,
        };

        /// A test data dir for this thread, with sing-box found in PATH.
        fn test_data_dir(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("cipher_plugin_e2e_{name}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            paths::TEST_DATA_DIR.with(|d| *d.borrow_mut() = Some(dir.clone()));
            dir
        }

        /// Installs a manifest with sing-box as its program, the way `install` lays it out.
        fn install_fake(data: &Path, manifest: Manifest, root_allowed: bool) {
            let dir = plugins_dir(data).join(&manifest.id);
            fs::create_dir_all(&dir).unwrap();
            let singbox = paths::find_binary("sing-box").expect("sing-box not installed");
            std::os::unix::fs::symlink(singbox, dir.join(binary_name(&manifest))).unwrap();
            fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(&manifest).unwrap()).unwrap();
            let record = InstallRecord { source: "test".into(), sha256: String::new(), official: false, root_allowed, development: true };
            plugin::save_record(data, &manifest.id, &record).unwrap();
        }

        fn manifest(id: &str, kind: &str, template: &str, needs_root: bool) -> Manifest {
            let mut manifest = match kind {
                "engine" => crate::plugin::tests::engine(),
                _ => crate::plugin::tests::transport(),
            };
            manifest.id = id.into();
            manifest.args = vec!["run".into(), "-c".into(), "{config_file}".into()];
            manifest.config_template = Some(template.into());
            manifest.ready = Ready::Port(true);
            manifest.needs_root = needs_root;
            manifest.fields.clear();
            manifest.schemes.clear();
            manifest
        }

        /// A one-shot HTTP server: answers `hello` to every request.
        fn http_server() -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let mut buffer = [0; 1024];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
                }
            });
            port
        }

        /// GETs `http://127.0.0.1:<target>/` through the app's local HTTP proxy.
        fn get_through_proxy(proxy_port: u16, target: u16) -> String {
            let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            write!(stream, "GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            response
        }

        /// Starts an engine like the app does (status polling until ready), in Proxy only mode.
        fn run(engine: &mut dyn Engine, profile: &Profile, settings: &Settings) {
            engine.start(profile, settings).unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Status::Failed(reason) = engine.status() {
                    panic!("engine failed: {reason}");
                }
                if engine.authorized() && engine.ready() && TcpStream::connect(("127.0.0.1", settings.proxy_port)).is_ok() {
                    return;
                }
                assert!(Instant::now() < deadline, "engine didn't get ready");
                thread::sleep(Duration::from_millis(100));
            }
        }

        fn proxy_settings() -> Settings {
            // Loopback targets must go through the chain, not around it.
            Settings { mode: ConnectionMode::ProxyOnly, bypass_lan: false, proxy_port: chain::free_port().unwrap(), ..Default::default() }
        }

        /// A SOCKS/HTTP server (sing-box, mixed inbound) standing in for a remote proxy server.
        fn fake_server(dir: &Path) -> (Child, u16) {
            let port = chain::free_port().unwrap();
            let config = dir.join("server.json");
            let json = format!(r#"{{"log":{{"level":"error"}},"inbounds":[{{"type":"mixed","listen":"127.0.0.1","listen_port":{port}}}],"outbounds":[{{"type":"direct"}}]}}"#);
            fs::create_dir_all(dir).unwrap();
            fs::write(&config, json).unwrap();
            let child = Command::new(paths::find_binary("sing-box").unwrap()).args(["run", "-c"]).arg(&config).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while TcpStream::connect(("127.0.0.1", port)).is_err() {
                assert!(Instant::now() < deadline, "fake server didn't start");
                thread::sleep(Duration::from_millis(50));
            }
            (child, port)
        }

        /// An engine plugin serving SOCKS: app proxy → sing-box → plugin → the local web server.
        #[test]
        #[ignore = "needs sing-box"]
        fn engine_plugin_end_to_end() {
            let data = test_data_dir("engine");
            let template = r#"{"log":{"level":"error"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":{listen_port}}],"outbounds":[{"type":"direct"}]}"#;
            install_fake(&data, manifest("fake-engine", "engine", template, false), false);
            let web = http_server();
            let settings = proxy_settings();

            let profile = Profile::Plugin { name: "Fake".into(), plugin: "fake-engine".into(), link: None, fields: BTreeMap::new() };
            let mut engine = PluginEngine::default();
            run(&mut engine, &profile, &settings);
            assert!(get_through_proxy(settings.proxy_port, web).ends_with("hello"));
            engine.stop().unwrap();
            fs::remove_dir_all(&data).unwrap();
        }

        /// A transport plugin (a TCP forwarder) under a SOCKS config, plain and as a root plugin in
        /// the admin helper: app proxy → sing-box → transport → fake server → the local web server.
        #[test]
        #[ignore = "needs sing-box"]
        fn transport_plugin_end_to_end() {
            let data = test_data_dir("transport");
            let template = r#"{"log":{"level":"error"},"inbounds":[{"type":"direct","listen":"127.0.0.1","listen_port":{listen_port},"override_address":"{server}","override_port":{server_port}}],"outbounds":[{"type":"direct"}]}"#;
            install_fake(&data, manifest("forwarder", "transport", template, false), false);
            install_fake(&data, manifest("root-forwarder", "transport", template, true), true);
            install_fake(&data, manifest("not-allowed", "transport", template, true), false);
            let (mut server, server_port) = fake_server(&data.join("server"));
            let web = http_server();

            let profile = Profile::Proxy {
                name: "Server".into(),
                outbound: Outbound::Socks(SocksOutbound { server: "127.0.0.1".into(), server_port, ..Default::default() }),
            };
            for id in ["forwarder", "root-forwarder"] {
                let settings = proxy_settings();
                let transport = TransportUse { plugin: id.into(), fields: BTreeMap::new() };
                let mut engine = Transported::new(crate::engine::engine_for(profile.engine_kind()), transport);
                run(&mut engine, &profile, &settings);
                assert!(get_through_proxy(settings.proxy_port, web).ends_with("hello"), "{id}");
                engine.stop().unwrap();
            }

            let transport = TransportUse { plugin: "not-allowed".into(), fields: BTreeMap::new() };
            let mut engine = Transported::new(crate::engine::engine_for(profile.engine_kind()), transport);
            let error = engine.start(&profile, &proxy_settings()).err().unwrap().to_string();
            assert!(error.contains("administrator rights"), "{error}");

            let _ = server.kill();
            fs::remove_dir_all(&data).unwrap();
        }
    }
}
