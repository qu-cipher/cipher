//! Android Tunnel mode for sing-box: sing-box serves its mixed inbound (no TUN of its own, see
//! `generate::EXTERNAL_TUN`), the app's VpnService builds the TUN, and tun2proxy feeds the TUN's
//! packets into sing-box as SOCKS5 (UDP too, so DNS reaches sing-box's hijack rule).
//! The app itself is excluded from the VPN, so sing-box's own connections go out directly.
//! In the proxy modes this is just sing-box.

use crate::android::{self, Consent};
use crate::engine::openvpn::management::TunSpec;
use crate::engine::{singbox::SingBoxEngine, traffic::Traffic, Engine, EngineError, Status};
use crate::profile::{Profile, Settings};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters, ProxyType};

/// Inside the TUN; the DNS address only needs to be routed into it.
const TUN_ADDRESS: (&str, u8) = ("172.19.0.1", 30);
const TUN_ADDRESS6: (&str, u8) = ("fdfe:dcba:9876::1", 126);
const TUN_DNS: &str = "172.19.0.2";
const TUN_MTU: u16 = 1500;

#[derive(Default)]
pub struct VpnEngine {
    singbox: SingBoxEngine,
    /// Tunnel mode only.
    tunnel: Option<Tunnel>,
}

struct Tunnel {
    proxy_port: u16,
    consent: Consent,
    tun2proxy: Option<(CancellationToken, JoinHandle<Result<(), String>>)>,
    failed: Option<String>,
}

impl Engine for VpnEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        self.singbox.start(profile, settings)?;
        if !settings.mode.uses_tunnel() {
            return Ok(());
        }
        let (consent, failed) = match android::prepare() {
            Ok(consent) => (consent, None),
            Err(e) => (Consent::Refused, Some(e)),
        };
        self.tunnel = Some(Tunnel { proxy_port: settings.proxy_port, consent, tun2proxy: None, failed });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        if let Some(mut tunnel) = self.tunnel.take() {
            if let Some((token, handle)) = tunnel.tun2proxy.take() {
                token.cancel();
                let _ = handle.join();
            }
            android::stop();
        }
        self.singbox.stop()
    }

    fn status(&mut self) -> Status {
        if let Some(tunnel) = &mut self.tunnel {
            if let Some(reason) = &tunnel.failed {
                return Status::Failed(reason.clone());
            }
            if tunnel.tun2proxy.as_ref().is_some_and(|(_, handle)| handle.is_finished()) {
                let (_, handle) = tunnel.tun2proxy.take().unwrap();
                let reason = match handle.join() {
                    Ok(Err(e)) => format!("The tunnel stopped: {e}"),
                    _ => "The tunnel stopped".into(),
                };
                tunnel.failed = Some(reason.clone());
                return Status::Failed(reason);
            }
            if tunnel.tun2proxy.is_some() && android::revoked() {
                let reason = "Android turned the VPN off (another VPN app, or system settings)".to_string();
                tunnel.failed = Some(reason.clone());
                return Status::Failed(reason);
            }
        }
        self.singbox.status()
    }

    fn traffic(&mut self) -> Option<Traffic> {
        self.singbox.traffic()
    }

    /// False until the user allowed the VPN in Android's dialog.
    fn authorized(&mut self) -> bool {
        let Some(tunnel) = &mut self.tunnel else { return self.singbox.authorized() };
        if tunnel.failed.is_none()
            && let Err(e) = android::check_consent(&mut tunnel.consent)
        {
            tunnel.failed = Some(e);
        }
        tunnel.consent == Consent::Granted || tunnel.failed.is_some()
    }

    /// Once sing-box listens: builds the TUN and starts feeding it in.
    fn ready(&mut self) -> bool {
        let Some(tunnel) = &mut self.tunnel else { return true };
        if tunnel.tun2proxy.is_some() {
            return true;
        }
        if tunnel.failed.is_some() || !listening(tunnel.proxy_port) {
            return false;
        }
        let spec = TunSpec {
            addresses: vec![own(TUN_ADDRESS), own(TUN_ADDRESS6)],
            routes: vec![("0.0.0.0".into(), 0), ("::".into(), 0)],
            dns: vec![TUN_DNS.into()],
            search_domains: Vec::new(),
            mtu: TUN_MTU,
        };
        match android::establish(&spec) {
            Ok(Some(fd)) => {
                tunnel.tun2proxy = Some(feed(fd, tunnel.proxy_port));
                true
            }
            Ok(None) => false,
            Err(e) => {
                tunnel.failed = Some(format!("Couldn't create the VPN: {e}"));
                false
            }
        }
    }
}

impl Drop for VpnEngine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn own((address, prefix): (&str, u8)) -> (String, u8) {
    (address.into(), prefix)
}

fn listening(port: u16) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok()
}

/// Runs tun2proxy on the TUN (owned by Java: it closes the fd) until the token is cancelled.
fn feed(fd: i32, proxy_port: u16) -> (CancellationToken, JoinHandle<Result<(), String>>) {
    let token = CancellationToken::new();
    let stop = token.clone();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let mut args = Args::default();
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port));
        args.proxy(ProxyParameters::new(ProxyType::Socks5, Some(proxy.into()), None))
            .tun_fd(Some(fd))
            .close_fd_on_drop(false)
            // DNS packets go to sing-box as UDP, where its hijack rule answers them.
            .dns(ArgDns::Direct)
            .ipv6_enabled(true);
        runtime
            .block_on(tun2proxy::general_run_async(args, TUN_MTU, false, stop))
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    (token, handle)
}
