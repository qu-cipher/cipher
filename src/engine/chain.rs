//! An engine that runs behind sing-box (Xray, Psiphon): it serves a local SOCKS proxy, and
//! sing-box runs in front of it with a `socks` outbound to that proxy. Tunnel mode, the local
//! proxy and routing rules then work the same as for any sing-box config.
//!
//! sing-box starts only once the upstream engine is up, so the upstream's own startup traffic
//! happens before a TUN exists. Its later connections are routed direct by process name,
//! or the TUN would send them back into it.

use crate::engine::{process::Process, singbox::SingBoxEngine, Assist, Engine, EngineError, Status};
use crate::engine::singbox::config::{
    outbound::{Outbound, socks::SocksOutbound},
    shared::Network,
};
use crate::profile::{Profile, Settings};
use std::{fs, net::TcpListener, path::{Path, PathBuf}};

/// A free loopback port for the upstream's SOCKS proxy (sing-box owns the user-facing port).
pub fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub struct Chain {
    upstream: Process,
    log_path: PathBuf,
    socks_port: u16,
    /// The upstream's process name, routed direct by sing-box.
    process_name: String,
    /// The sing-box side to start: a SOCKS profile pointing at the upstream, and the settings.
    pending: Option<(Profile, Settings)>,
    /// From a transport plugin under the upstream, or the upstream's own admin helper.
    assist: Assist,
    singbox: Option<SingBoxEngine>,
}

impl Chain {
    /// `network`: what the upstream's SOCKS proxy forwards (`None` = TCP and UDP).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: Process,
        log_path: PathBuf,
        binary: &Path,
        name: &str,
        socks_port: u16,
        network: Option<Network>,
        settings: &Settings,
        assist: Assist,
    ) -> Self {
        let outbound = Outbound::Socks(SocksOutbound {
            tag: name.into(),
            server: "127.0.0.1".into(),
            server_port: socks_port,
            version: Some("5".into()),
            network,
            ..Default::default()
        });
        Self {
            upstream,
            log_path,
            socks_port,
            process_name: binary.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            pending: Some((Profile::Proxy { name: name.into(), outbound }, settings.clone())),
            assist,
            singbox: None,
        }
    }

    pub fn log(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    /// The upstream's status, then sing-box's. Also moves the start along: sing-box starts as
    /// soon as `upstream_up` says so. `explain` turns the upstream's log into a failure reason.
    pub fn status(&mut self, upstream_up: impl FnOnce(&Self) -> bool, explain: impl FnOnce(&str) -> Option<String>) -> Status {
        if let Status::Failed(reason) = self.upstream.status() {
            return Status::Failed(explain(&self.log()).unwrap_or(reason));
        }
        if self.pending.is_some() && upstream_up(self) && let Err(e) = self.start_singbox() {
            return Status::Failed(e.to_string());
        }
        self.singbox.as_mut().map_or(Status::Running, Engine::status)
    }

    fn start_singbox(&mut self) -> Result<(), EngineError> {
        let Some((profile, settings)) = self.pending.take() else { return Ok(()) };
        let mut singbox = SingBoxEngine::default();
        singbox.direct_processes = vec![self.process_name.clone()];
        singbox.assist(self.assist.clone());
        singbox.start(&profile, &settings)?;
        self.singbox = Some(singbox);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), EngineError> {
        self.pending = None;
        if let Some(mut singbox) = self.singbox.take() {
            singbox.stop()?;
        }
        self.upstream.stop()?;
        Ok(())
    }

    pub fn ready(&mut self) -> bool {
        self.singbox.as_mut().is_some_and(Engine::ready)
    }

    /// False until sing-box runs (the upstream still starting, or the admin password dialog is open).
    pub fn authorized(&mut self) -> bool {
        self.singbox.as_mut().is_some_and(Engine::authorized)
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
