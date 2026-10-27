//! Android: answers OpenVPN's management socket (see `management`), building its TUN with the
//! app's VpnService once the user allowed the VPN.

use super::management::{send_with_fd, Request, TunSpec};
use crate::android::{self, Consent};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long OpenVPN gets to open its management socket.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Management {
    stop: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<String>>>,
    consent: Consent,
    handle: Option<JoinHandle<()>>,
}

impl Management {
    /// The openvpn arguments that hand the network setup to us.
    pub fn args(socket: &Path) -> Vec<std::ffi::OsString> {
        let mut args: Vec<std::ffi::OsString> = vec!["--management".into(), socket.into(), "unix".into()];
        // Waits for us before connecting, so no request goes unanswered.
        args.push("--management-hold".into());
        args
    }

    /// Asks for the VPN permission, then serves `socket` until stopped or OpenVPN exits.
    pub fn start(socket: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(Mutex::new(None));
        let consent = android::prepare().unwrap_or_else(|e| {
            *failed.lock().unwrap() = Some(e);
            Consent::Refused
        });
        let handle = {
            let (stop, failed) = (stop.clone(), failed.clone());
            thread::spawn(move || {
                if let Err(e) = serve(&socket, &stop)
                    && !stop.load(Ordering::Relaxed)
                {
                    *failed.lock().unwrap() = Some(e);
                }
            })
        };
        Management { stop, failed, consent, handle: Some(handle) }
    }

    pub fn failed(&self) -> Option<String> {
        self.failed.lock().unwrap().clone()
    }

    /// False until the user allowed the VPN in Android's dialog.
    pub fn authorized(&mut self) -> bool {
        if let Err(e) = android::check_consent(&mut self.consent) {
            self.failed.lock().unwrap().get_or_insert(e);
        }
        self.consent == Consent::Granted || self.failed().is_some()
    }

    /// Call after stopping openvpn (which closes the socket).
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        android::stop();
    }
}

fn serve(socket: &Path, stop: &AtomicBool) -> Result<(), String> {
    let started = Instant::now();
    let stream = loop {
        match UnixStream::connect(socket) {
            Ok(stream) => break stream,
            Err(_) if stop.load(Ordering::Relaxed) => return Ok(()),
            Err(e) if started.elapsed() >= SOCKET_TIMEOUT => return Err(format!("OpenVPN's management socket: {e}")),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    };
    // Lets the loop notice `stop` while OpenVPN is quiet.
    stream.set_read_timeout(Some(Duration::from_millis(500))).map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer.write_all(b"hold release\n").map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut spec = TunSpec::default();
    let mut line = String::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        // A timeout can leave half a line in `line`: keep it and read on.
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(()), // OpenVPN exited; its process status says why
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e.to_string()),
        }
        if !line.ends_with('\n') {
            continue;
        }
        if let Some(request) = Request::parse(&line) {
            if request.kind == "OPENTUN" {
                let fd = open_tun(&spec, stop)?;
                send_with_fd(reader.get_ref(), "needok 'OPENTUN' ok\n", fd).map_err(|e| e.to_string())?;
                // A reconnect that needs a new TUN sends its settings again.
                spec = TunSpec::default();
            } else {
                request.apply(&mut spec);
                writer.write_all(request.reply().as_bytes()).map_err(|e| e.to_string())?;
            }
        }
        line.clear();
    }
}

/// Waits for the user's consent and the service, then builds the TUN.
fn open_tun(spec: &TunSpec, stop: &AtomicBool) -> Result<i32, String> {
    let mut consent = Consent::Waiting;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("stopped".into());
        }
        android::check_consent(&mut consent)?;
        if consent == Consent::Granted
            && let Some(fd) = android::establish(spec).map_err(|e| format!("Couldn't create the VPN: {e}"))?
        {
            return Ok(fd);
        }
        thread::sleep(Duration::from_millis(100));
    }
}
