//! Traffic counters for the connect panel. sing-box reports them over its Clash API (polled on
//! a background thread, so the UI never waits on HTTP); OpenVPN through its status file.

use crate::engine::{chain::free_port, singbox::config::experimental::ClashApi};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    fs, io,
    path::Path,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    thread,
    time::Duration,
};

/// Bytes moved since the engine started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
}

const POLL: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(2);

/// Polls `GET /connections` of a sing-box Clash API on loopback. The random secret keeps other
/// local programs out of it (the API can also close connections).
pub struct Meter {
    port: u16,
    secret: String,
    latest: Arc<Mutex<Option<Traffic>>>,
    stop: Arc<AtomicBool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Totals {
    upload_total: u64,
    download_total: u64,
}

impl Meter {
    pub fn new() -> io::Result<Self> {
        let mut bytes = [0u8; 16];
        SystemRandom::new().fill(&mut bytes).map_err(|_| io::Error::other("no random source"))?;
        Ok(Self {
            port: free_port()?,
            secret: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            latest: Arc::default(),
            stop: Arc::default(),
        })
    }

    /// The `experimental.clash_api` block sing-box needs to serve the counters.
    pub fn clash_api(&self) -> ClashApi {
        ClashApi {
            external_controller: Some(format!("127.0.0.1:{}", self.port)),
            secret: Some(self.secret.clone()),
            ..Default::default()
        }
    }

    /// Starts polling; it stops when the meter is dropped.
    pub fn start(&self) {
        let url = format!("http://127.0.0.1:{}/connections", self.port);
        let auth = format!("Bearer {}", self.secret);
        let (latest, stop) = (self.latest.clone(), self.stop.clone());
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            // Loopback: never through a proxy from the environment.
            .proxy(None)
            .build()
            .into();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Refused until sing-box is up; it keeps the last numbers meanwhile.
                let totals = agent
                    .get(&url)
                    .header("Authorization", &auth)
                    .call()
                    .ok()
                    .and_then(|mut response| response.body_mut().read_to_string().ok())
                    .and_then(|body| serde_json::from_str::<Totals>(&body).ok());
                if let Some(totals) = totals {
                    *latest.lock().unwrap() = Some(Traffic { up: totals.upload_total, down: totals.download_total });
                }
                thread::sleep(POLL);
            }
        });
    }

    pub fn get(&self) -> Option<Traffic> {
        *self.latest.lock().unwrap()
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Reads an OpenVPN `--status` file (version 1). The TUN side counts what apps sent and got,
/// without the tunnel's own overhead.
pub fn read_openvpn_status(path: &Path) -> Option<Traffic> {
    parse_openvpn_status(&fs::read_to_string(path).ok()?)
}

fn parse_openvpn_status(text: &str) -> Option<Traffic> {
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(',')?.trim().parse().ok())
    };
    Some(Traffic { up: value("TUN/TAP read bytes")?, down: value("TUN/TAP write bytes")? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openvpn_status() {
        let text = "OpenVPN STATISTICS\nUpdated,2026-10-27 12:00:00\nTUN/TAP read bytes,1200\n\
                    TUN/TAP write bytes,34000\nTCP/UDP read bytes,36000\nTCP/UDP write bytes,2500\n\
                    Auth read bytes,34100\nEND\n";
        assert_eq!(parse_openvpn_status(text), Some(Traffic { up: 1200, down: 34000 }));
        assert_eq!(parse_openvpn_status("OpenVPN STATISTICS\nEND\n"), None);
    }
}
