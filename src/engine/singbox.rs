use crate::engine::{elevated::Elevated, paths, process::{Process, hide_console}, Assist, Engine, EngineError, Status};
use crate::profile::{ConnectionMode, Profile, Settings};
use std::{ffi::{OsStr, OsString}, path::Path, process::Command, sync::Arc};

pub mod config;
pub mod generate;

/// Oldest sing-box release that understands the generated config
/// (1.12 DNS server format, `domain_resolver`, endpoints, rule actions).
pub const MIN_VERSION: &str = "1.12.0";

const BINARY: &str = "sing-box";

/// Runs proxy and WireGuard profiles through `sing-box run`.
#[derive(Default)]
pub struct SingBoxEngine {
    process: Option<Process>,
    /// sing-box set the OS proxy for this run (System proxy mode).
    system_proxy: bool,
    /// Process names whose traffic always goes direct (a chained engine's own connections).
    pub direct_processes: Vec<String>,
    /// A root plugin's admin helper: in Tunnel mode sing-box runs in it too (one password prompt).
    pub elevated: Option<Arc<Elevated>>,
}

impl Engine for SingBoxEngine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError> {
        if self.status() == Status::Running {
            return Err(EngineError::AlreadyRunning);
        }

        let data_dir = paths::data_dir()?;
        let config = generate::build_config(profile, settings, &data_dir, &self.direct_processes)?;
        let config_path = data_dir.join("sing-box.json");
        paths::write_private(&config_path, &serde_json::to_string_pretty(&config)?)?;

        let binary = paths::find_binary(BINARY)?;
        check(&binary, &config_path)?;

        let args = [OsStr::new("run"), OsStr::new("-c"), config_path.as_os_str()];
        let log_path = data_dir.join("sing-box.log");
        self.process = Some(if settings.mode.uses_tunnel() {
            // Created as us first: a root sing-box would make it root-owned and break the proxy modes.
            let cache = data_dir.join("cache.db");
            if !cache.exists() {
                std::fs::File::create(&cache)?;
            }
            match &self.elevated {
                Some(helper) => {
                    let args: Vec<OsString> = args.iter().map(|a| a.to_os_string()).collect();
                    Process::spawn_in(helper, "sing-box", &binary, &args, &log_path)?
                }
                None => Process::spawn_elevated("sing-box", &binary, args, &log_path)?,
            }
        } else {
            Process::spawn("sing-box", &binary, args, &log_path)?
        });
        self.system_proxy = settings.mode == ConnectionMode::SystemProxy;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        if let Some(mut process) = self.process.take() {
            process.stop()?;
        }
        if std::mem::take(&mut self.system_proxy) {
            reset_system_proxy();
        }
        Ok(())
    }

    fn status(&mut self) -> Status {
        self.process.as_mut().map_or(Status::Stopped, Process::status)
    }

    fn authorized(&mut self) -> bool {
        self.process.as_ref().is_some_and(Process::authorized)
    }

    fn assist(&mut self, assist: Assist) {
        self.direct_processes.extend(assist.direct_processes);
        self.elevated = assist.elevated;
    }
}

impl Drop for SingBoxEngine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// sing-box restores the OS proxy when it exits cleanly (SIGTERM on Unix). On Windows the
/// process is killed, which skips that, and a stale proxy setting would cut the machine off.
#[cfg(windows)]
fn reset_system_proxy() {
    const INTERNET_SETTINGS: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let mut command = Command::new("reg");
    command.args(["add", INTERNET_SETTINGS, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"]);
    hide_console(&mut command);
    let _ = command.status();
}

#[cfg(not(windows))]
fn reset_system_proxy() {}

/// Validates a config file with `sing-box check`.
pub fn check(binary: &Path, config_path: &Path) -> Result<(), EngineError> {
    let mut command = Command::new(binary);
    command.arg("check").arg("-c").arg(config_path);
    hide_console(&mut command);
    let output = command.output()?;

    if output.status.success() {
        Ok(())
    } else {
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(EngineError::InvalidConfig(format!("{reason} (needs sing-box {MIN_VERSION} or newer)")))
    }
}
