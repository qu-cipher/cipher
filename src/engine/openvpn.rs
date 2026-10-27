use crate::engine::{paths, process::Process, Engine, EngineError, EngineKind, Status};
use crate::import::openvpn::config_needs_credentials;
use crate::profile::{OpenVpnConfig, Profile, Settings};
use std::{ffi::OsStr, fs, path::PathBuf};

#[cfg(target_os = "android")]
mod android;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub mod management;

const BINARY: &str = "openvpn";

/// `Status::Failed` reason when the server rejected the username/password.
pub const AUTH_FAILED: &str = "Wrong username or password";

/// Runs .ovpn profiles with the openvpn binary.
#[derive(Default)]
pub struct OpenVpnEngine {
    process: Option<Process>,
    /// Credentials handed to openvpn for this run; deleted on stop.
    auth_file: Option<PathBuf>,
    /// An inline config written out for this run; deleted on stop.
    temp_config: Option<PathBuf>,
    /// Android: OpenVPN asks us for its TUN over the management socket.
    #[cfg(target_os = "android")]
    management: Option<android::Management>,
}

impl Engine for OpenVpnEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        let Profile::OpenVpn { config, credentials, .. } = profile else {
            return Err(EngineError::WrongEngine(EngineKind::SingBox));
        };
        if !settings.mode.uses_tunnel() {
            return Err(EngineError::TunnelOnly);
        }
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }
        if let OpenVpnConfig::File(path) = config
            && !path.is_file()
        {
            return Err(EngineError::InvalidConfig(format!("{} does not exist", path.display())));
        }

        let binary = paths::find_binary(BINARY)?;
        let data_dir = paths::data_dir()?;

        let config_path = match config {
            // --cd, so relative cert/key paths inside the .ovpn resolve next to it.
            OpenVpnConfig::File(path) => path.canonicalize()?,
            // Inline configs embed their keys; written private, deleted on stop.
            OpenVpnConfig::Inline(text) => {
                let path = data_dir.join("openvpn.ovpn");
                paths::write_private(&path, text)?;
                self.temp_config = Some(path.clone());
                path
            }
        };
        let mut args = Vec::new();
        if let Some(dir) = config_path.parent() {
            args.extend([OsStr::new("--cd").to_owned(), dir.as_os_str().to_owned()]);
        }
        args.extend([OsStr::new("--config").to_owned(), config_path.clone().into_os_string()]);

        // OpenVPN would ask for these on stdin, which we don't have. Given after --config,
        // this overrides the bare `auth-user-pass` line.
        if config_needs_credentials(&config.text()?) {
            let credentials = credentials.as_ref().ok_or(EngineError::CredentialsRequired)?;
            let auth_file = data_dir.join("openvpn-auth.txt");
            paths::write_private(&auth_file, &format!("{}\n{}\n", credentials.username, credentials.password))?;
            args.extend([
                OsStr::new("--auth-user-pass").to_owned(),
                auth_file.clone().into_os_string(),
                OsStr::new("--auth-retry").to_owned(),
                OsStr::new("none").to_owned(),
            ]);
            self.auth_file = Some(auth_file);
        }

        #[cfg(target_os = "android")]
        let socket = data_dir.join("openvpn-management");
        #[cfg(target_os = "android")]
        {
            let _ = fs::remove_file(&socket);
            args.extend(android::Management::args(&socket));
        }

        // OpenVPN is Tunnel-only, so it always runs as admin.
        self.process = Some(Process::spawn_elevated("openvpn", &binary, args, &data_dir.join("openvpn.log"))?);
        #[cfg(target_os = "android")]
        {
            self.management = Some(android::Management::start(socket));
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        let result = self.process.take().map_or(Ok(()), |mut process| process.stop());
        #[cfg(target_os = "android")]
        if let Some(mut management) = self.management.take() {
            management.stop();
        }
        for file in [self.auth_file.take(), self.temp_config.take()].into_iter().flatten() {
            let _ = fs::remove_file(file);
        }
        Ok(result?)
    }

    fn status(&mut self) -> Status {
        #[cfg(target_os = "android")]
        if let Some(management) = &self.management {
            if let Some(reason) = management.failed() {
                return Status::Failed(reason);
            }
            if crate::android::revoked() {
                return Status::Failed("Android turned the VPN off (another VPN app, or system settings)".into());
            }
        }
        let Some(process) = self.process.as_mut() else { return Status::Stopped };
        match process.status() {
            Status::Failed(_) if process.log_contains("AUTH_FAILED") => Status::Failed(AUTH_FAILED.into()),
            status => status,
        }
    }

    fn ready(&mut self) -> bool {
        self.process.as_ref().is_some_and(|p| p.log_contains("Initialization Sequence Completed"))
    }

    fn authorized(&mut self) -> bool {
        #[cfg(target_os = "android")]
        if let Some(management) = &mut self.management {
            return management.authorized();
        }
        self.process.as_ref().is_some_and(Process::authorized)
    }
}

impl Drop for OpenVpnEngine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ConnectionMode;

    /// A process that logs what openvpn logs on a rejected login and exits.
    #[cfg(unix)]
    #[test]
    fn rejected_login_is_reported_as_such() {
        let log = std::env::temp_dir().join("cipher_client_auth_failed.log");
        let script = "echo 'AUTH: Received control message: AUTH_FAILED'; echo 'SIGTERM[soft,auth-failure] received, process exiting'";
        let process = Process::spawn("openvpn", "/bin/sh".as_ref(), ["-c", script], &log).unwrap();
        let mut engine = OpenVpnEngine::default();
        engine.process = Some(process);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while engine.status() == Status::Running && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(engine.status(), Status::Failed(AUTH_FAILED.into()));
        let _ = fs::remove_file(log);
    }

    #[test]
    fn refuses_proxy_modes() {
        let profile = Profile::OpenVpn { name: "Work".into(), config: OpenVpnConfig::File("work.ovpn".into()), credentials: None };
        for mode in [ConnectionMode::SystemProxy, ConnectionMode::ProxyOnly] {
            let settings = Settings { mode, ..Default::default() };
            assert!(matches!(OpenVpnEngine::default().start(&profile, &settings), Err(EngineError::TunnelOnly)));
        }
    }
}
