use crate::engine::{Status, elevated::{Elevated, MemberStatus}};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
};

/// Written to the log by the root wrapper once the admin password was accepted.
const AUTHORIZED_MARKER: &str = "cipher_client: running as admin";

/// Runs `"$@"` as root and stops it with SIGTERM when our end of stdin closes: on stop, on quit,
/// or if the app crashes. The app can't signal a root process itself. Background jobs get
/// /dev/null as stdin in a non-interactive shell, so the watcher reads a saved copy (fd 3).
#[cfg(target_os = "linux")]
const ELEVATED_WRAPPER: &str = r#"
echo "$0"
exec 3<&0
"$@" </dev/null 3<&- &
pid=$!
( read -r _ <&3; kill -TERM "$pid" 2>/dev/null ) &
watcher=$!
exec 3<&-
wait "$pid"
code=$?
kill "$watcher" 2>/dev/null
exit "$code"
"#;

/// A child process whose stdout/stderr go to a log file.
/// The process is stopped when this is dropped, so closing the app never leaves a tunnel up.
pub struct Process {
    name: String,
    /// `None` when the process runs inside the shared admin helper (`helper`).
    child: Option<Child>,
    log_path: PathBuf,
    /// Started through pkexec: runs as root and is stopped by closing its stdin.
    elevated: bool,
    /// Run by the admin helper (one password prompt for several root processes), with its id there.
    helper: Option<(Arc<Elevated>, u32)>,
}

impl Process {
    pub fn spawn<I, S>(name: &str, program: &Path, args: I, log_path: &Path) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let log = File::create(log_path)?;

        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);

        hide_console(&mut command);

        Ok(Self { name: name.into(), child: Some(command.spawn()?), log_path: log_path.to_owned(), elevated: false, helper: None })
    }

    /// Runs as root inside the shared admin helper (see `engine::elevated`).
    pub fn spawn_in(helper: &Arc<Elevated>, name: &str, program: &Path, args: &[std::ffi::OsString], log_path: &Path) -> io::Result<Self> {
        let id = helper.spawn(program, args, log_path)?;
        Ok(Self { name: name.into(), child: None, log_path: log_path.to_owned(), elevated: true, helper: Some((helper.clone(), id)) })
    }

    /// Like [`spawn`](Self::spawn), but as root through pkexec, which asks for the admin password
    /// (Linux). Elsewhere, and in tests, it runs normally (Windows: the app itself runs elevated).
    pub fn spawn_elevated<I, S>(name: &str, program: &Path, args: I, log_path: &Path) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        #[cfg(target_os = "linux")]
        if !cfg!(test) {
            let pkexec = crate::engine::paths::find_binary("pkexec")
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
            return Self::spawn_wrapped(name, Command::new(pkexec), program, args, log_path);
        }
        Self::spawn(name, program, args, log_path)
    }

    /// Runs `program` inside [`ELEVATED_WRAPPER`], launched by `launcher` (pkexec).
    #[cfg(target_os = "linux")]
    fn spawn_wrapped<I, S>(name: &str, mut launcher: Command, program: &Path, args: I, log_path: &Path) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let log = File::create(log_path)?;
        launcher
            .args([OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(ELEVATED_WRAPPER), OsStr::new(AUTHORIZED_MARKER)])
            .arg(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(log.try_clone()?)
            .stderr(log);
        Ok(Self { name: name.into(), child: Some(launcher.spawn()?), log_path: log_path.to_owned(), elevated: true, helper: None })
    }

    /// False while an elevated process still waits for the admin password.
    pub fn authorized(&self) -> bool {
        if let Some((helper, _)) = &self.helper {
            return helper.authorized();
        }
        !self.elevated || self.log_contains(AUTHORIZED_MARKER)
    }

    /// `None` while running, the exit status once it has exited (own child processes only).
    pub fn exit_status(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.as_mut().map_or(Ok(None), Child::try_wait)
    }

    /// Running, or why it stopped (the last log line is usually the actual error).
    pub fn status(&mut self) -> Status {
        if let Some((helper, id)) = &self.helper {
            return match helper.status(*id) {
                MemberStatus::Running => Status::Running,
                // A root plugin's prompt, also in the proxy modes: not ADMIN_REFUSED, which is about Tunnel mode.
                MemberStatus::HelperGone { refused: true } => {
                    Status::Failed(format!("{} needs the admin password: enter it when asked, or turn the plugin off", self.name))
                }
                MemberStatus::HelperGone { refused: false } => Status::Failed(format!("{} stopped: the admin helper exited", self.name)),
                MemberStatus::Exited(code) => Status::Failed(match last_log_line(&self.log_path) {
                    Some(line) => format!("{} exited: {line}", self.name),
                    None => format!("{} exited (code {})", self.name, code.map_or("unknown".into(), |c| c.to_string())),
                }),
            };
        }
        match self.exit_status() {
            Ok(None) => Status::Running,
            // pkexec: 126 = the password dialog was dismissed, 127 = not authorized.
            Ok(Some(exit)) if self.elevated && !self.authorized() && matches!(exit.code(), Some(126 | 127)) => {
                Status::Failed(ADMIN_REFUSED.into())
            }
            Ok(Some(exit)) => Status::Failed(match last_log_line(&self.log_path) {
                Some(line) => format!("{} exited: {line}", self.name),
                None => format!("{} exited ({exit})", self.name),
            }),
            Err(e) => Status::Failed(e.to_string()),
        }
    }

    pub fn log_contains(&self, needle: &str) -> bool {
        fs::read_to_string(&self.log_path).is_ok_and(|log| log.contains(needle))
    }

    /// Asks the process to exit (SIGTERM on Unix, so routes get cleaned up),
    /// and kills it if it is still running after a timeout.
    pub fn stop(&mut self) -> io::Result<()> {
        if let Some((helper, id)) = &self.helper {
            return helper.stop(*id);
        }
        let Some(child) = self.child.as_mut() else { return Ok(()) };
        if child.try_wait()?.is_some() {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::{thread, time::{Duration, Instant}};
            const STOP_TIMEOUT: Duration = Duration::from_secs(5);
            // A root engine can't be killed from here, so give its cleanup more time.
            const ELEVATED_STOP_TIMEOUT: Duration = Duration::from_secs(15);

            // Elevated: closing stdin makes the root wrapper stop the engine. The SIGTERM still
            // reaches pkexec while it waits for the password (it runs as us until then).
            drop(child.stdin.take());
            // SAFETY: plain syscall on a pid we own; the child has not been reaped yet.
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };

            let timeout = if self.elevated { ELEVATED_STOP_TIMEOUT } else { STOP_TIMEOUT };
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.exit_status()?.is_some() {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(100));
            }
        }

        if self.elevated {
            return Err(io::Error::other(format!("{} (running as admin) didn't stop", self.name)));
        }
        let Some(child) = self.child.as_mut() else { return Ok(()) };
        child.kill()?;
        child.wait()?;
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Don't pop up a console window next to the GUI (Windows; no-op elsewhere).
pub fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}

/// `Status::Failed` reason when the admin password dialog was dismissed or refused.
pub const ADMIN_REFUSED: &str = "Tunnel mode needs the admin password";

/// Last non-empty line of a log, without ANSI colors and sing-box's `LEVEL[0000]` prefix.
fn last_log_line(path: &Path) -> Option<String> {
    let log = fs::read_to_string(path).ok()?;
    let line = strip_ansi(log.lines().rev().find(|l| !l.trim().is_empty())?);
    let line = match line.split_once("] ") {
        Some((prefix, rest)) if prefix.contains('[') && !prefix.contains(' ') => rest,
        _ => &line,
    };
    Some(line.trim().to_owned())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip `ESC [ … letter`.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_log_line_is_cleaned_up() {
        let path = std::env::temp_dir().join("cipher_client_log_test.log");
        fs::write(&path, "INFO[0000] started\n\x1b[31mFATAL\x1b[0m[0000] start service: open tun: operation not permitted\n\n").unwrap();
        assert_eq!(last_log_line(&path).unwrap(), "start service: open tun: operation not permitted");

        fs::write(&path, "Options error: plain openvpn line\n").unwrap();
        assert_eq!(last_log_line(&path).unwrap(), "Options error: plain openvpn line");
        fs::remove_file(&path).unwrap();
    }

    /// The root wrapper without pkexec (`env` as the launcher): it reports the engine's own exit,
    /// and stopping it (closing stdin) sends the engine SIGTERM, so its cleanup runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn elevated_wrapper_stops_engine_when_stdin_closes() {
        use std::time::{Duration, Instant};
        let dir = std::env::temp_dir().join(format!("cipher_client_wrapper_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("engine.log");
        let cleaned = dir.join("cleaned");
        let engine = format!("trap 'touch {}; exit 0' TERM; echo started; while :; do sleep 0.05; done", cleaned.display());

        let mut process =
            Process::spawn_wrapped("engine", Command::new("env"), "/bin/sh".as_ref(), ["-c", &engine], &log).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !process.log_contains("started") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(process.authorized());
        assert_eq!(process.status(), Status::Running);

        // Only close the pipe, as a crash would: a root wrapper can't be signalled by us.
        drop(process.child.as_mut().unwrap().stdin.take());
        let deadline = Instant::now() + Duration::from_secs(3);
        while process.exit_status().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(process.exit_status().unwrap().is_some(), "wrapper didn't exit");
        assert!(cleaned.exists(), "engine didn't get SIGTERM");

        // An engine that exits by itself ends the wrapper with its exit code.
        let mut process =
            Process::spawn_wrapped("engine", Command::new("env"), "/bin/sh".as_ref(), ["-c", "echo bad config; exit 3"], &log).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while process.status() == Status::Running && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(process.status(), Status::Failed("engine exited: bad config".into()));
        fs::remove_dir_all(&dir).unwrap();
    }
}
