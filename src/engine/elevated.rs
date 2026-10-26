//! One admin password prompt for several root processes: Cipher's own binary runs as root
//! (`cipher_client --elevated-helper`, through pkexec) and starts the processes it's asked to.
//! Used when a plugin needs root, so the plugin and sing-box's TUN share one prompt, and the app
//! still decides when each one starts (the plugin first, sing-box once it's ready).
//!
//! Protocol, one JSON object per line:
//! - app → helper (stdin): `{"spawn": {"id": 1, "program": "…", "args": […], "log": "…"}}`, `{"stop": 1}`
//! - helper → app (stdout): the [`AUTHORIZED`] line once running as root, then `{"exited": 1, "code": 0}`
//!
//! Closing stdin (stop, quit, or a crash) makes the helper stop every process and exit, like the
//! single-process wrapper in `process.rs`. Log files are created by the app (as the user) first.

use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

/// The command-line flag that turns the app into the helper.
pub const HELPER_ARG: &str = "--elevated-helper";
/// The helper's first line, once the admin password was accepted.
const AUTHORIZED: &str = "cipher_client: helper running as admin";
const STOP_TIMEOUT: Duration = Duration::from_secs(15);

/// A member process's state, as the app sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberStatus {
    Running,
    Exited(Option<i32>),
    /// The helper itself is gone; `refused` = the password dialog was dismissed or failed.
    HelperGone { refused: bool },
}

#[derive(Default)]
struct State {
    authorized: bool,
    gone: bool,
    exited: HashMap<u32, Option<i32>>,
}

/// The app's handle on the running helper. Shared by the processes it runs; dropping the last
/// handle stops them all.
pub struct Elevated {
    input: Mutex<Option<Box<dyn Write + Send>>>,
    child: Mutex<Option<Child>>,
    state: Arc<Mutex<State>>,
    next_id: Mutex<u32>,
}

#[cfg_attr(test, allow(dead_code))]
impl Elevated {
    /// Starts the helper through pkexec (one password prompt). Not used on Windows, where the
    /// whole app already runs as administrator.
    pub fn start() -> io::Result<Arc<Self>> {
        let pkexec = crate::engine::paths::find_binary("pkexec")
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
        let exe = std::env::current_exe()?;
        let mut command = Command::new(pkexec);
        command.arg(exe).arg(HELPER_ARG);
        Self::launch(command)
    }

    fn launch(mut command: Command) -> io::Result<Arc<Self>> {
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let input = child.stdin.take().map(|s| Box::new(s) as Box<dyn Write + Send>);
        let output = child.stdout.take().ok_or_else(|| io::Error::other("no helper output"))?;
        Ok(Self::connect(input, Box::new(output), Some(child)))
    }

    /// Wires up the pipes; also used by tests with an in-process helper.
    fn connect(input: Option<Box<dyn Write + Send>>, output: Box<dyn Read + Send>, child: Option<Child>) -> Arc<Self> {
        let state = Arc::new(Mutex::new(State::default()));
        let reader_state = state.clone();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                let mut state = reader_state.lock().unwrap();
                if line.trim() == AUTHORIZED {
                    state.authorized = true;
                } else if let Ok(event) = serde_json::from_str::<Value>(&line)
                    && let Some(id) = event["exited"].as_u64()
                {
                    state.exited.insert(id as u32, event["code"].as_i64().map(|c| c as i32));
                }
            }
            reader_state.lock().unwrap().gone = true;
        });
        Arc::new(Self { input: Mutex::new(input), child: Mutex::new(child), state, next_id: Mutex::new(0) })
    }

    pub fn authorized(&self) -> bool {
        self.state.lock().unwrap().authorized
    }

    fn send(&self, message: &Value) -> io::Result<()> {
        let mut input = self.input.lock().unwrap();
        let input = input.as_mut().ok_or_else(|| io::Error::other("the admin helper was stopped"))?;
        writeln!(input, "{message}")?;
        input.flush()
    }

    /// Asks the helper to start a program as root; returns its id. The log file is created here,
    /// as the user, so it doesn't end up owned by root.
    pub fn spawn(&self, program: &Path, args: &[std::ffi::OsString], log: &Path) -> io::Result<u32> {
        std::fs::File::create(log)?;
        let id = {
            let mut next = self.next_id.lock().unwrap();
            *next += 1;
            *next
        };
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        self.send(&json!({ "spawn": { "id": id, "program": program, "args": args, "log": log } }))?;
        Ok(id)
    }

    pub fn status(&self, id: u32) -> MemberStatus {
        let state = self.state.lock().unwrap();
        if let Some(code) = state.exited.get(&id) {
            return MemberStatus::Exited(*code);
        }
        if state.gone {
            let refused = !state.authorized && self.exit_code().is_some_and(|c| matches!(c, 126 | 127));
            return MemberStatus::HelperGone { refused };
        }
        MemberStatus::Running
    }

    fn exit_code(&self) -> Option<i32> {
        let mut child = self.child.lock().unwrap();
        let child = child.as_mut()?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => return None,
            }
        }
    }

    /// Stops one process and waits until the helper reports it gone.
    pub fn stop(&self, id: u32) -> io::Result<()> {
        if self.status(id) != MemberStatus::Running {
            return Ok(());
        }
        // Before the password was entered there's nothing running as root yet: stop pkexec.
        if !self.authorized() {
            self.shutdown();
            return Ok(());
        }
        self.send(&json!({ "stop": id }))?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        while self.status(id) == MemberStatus::Running {
            if Instant::now() >= deadline {
                return Err(io::Error::other("a process running as admin didn't stop"));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Closes the pipe: the helper stops everything and exits.
    fn shutdown(&self) {
        drop(self.input.lock().unwrap().take());
        if let Some(child) = self.child.lock().unwrap().as_mut() {
            // Reaches pkexec while it still waits for the password (it runs as us until then).
            #[cfg(unix)]
            // SAFETY: plain syscall on a pid we own; the child has not been reaped yet.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM)
            };
            let deadline = Instant::now() + STOP_TIMEOUT;
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

impl Drop for Elevated {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ───────────────────────────── The helper side (runs as root) ─────────────────────────────

/// `cipher_client --elevated-helper`: serves stdin/stdout until stdin closes.
pub fn run_helper() {
    serve(BufReader::new(io::stdin()), io::stdout());
}

struct Member {
    id: u32,
    child: Child,
}

fn serve<R: BufRead + Send + 'static, W: Write>(input: R, mut output: W) {
    let _ = writeln!(output, "{AUTHORIZED}");
    let _ = output.flush();

    // Commands arrive on a thread, so exits can be reported while waiting for input.
    let (sender, commands) = mpsc::channel::<Value>();
    thread::spawn(move || {
        for line in input.lines() {
            let Ok(line) = line else { break };
            if let Ok(command) = serde_json::from_str(&line) && sender.send(command).is_err() {
                break;
            }
        }
    });

    let mut members: Vec<Member> = Vec::new();
    let report = |output: &mut W, id: u32, code: Option<i32>| {
        let _ = writeln!(output, "{}", json!({ "exited": id, "code": code }));
        let _ = output.flush();
    };
    loop {
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(command) => {
                if let Some(spawn) = command.get("spawn") {
                    let id = spawn["id"].as_u64().unwrap_or(0) as u32;
                    match start_member(spawn) {
                        Ok(child) => members.push(Member { id, child }),
                        Err(e) => {
                            append_log(spawn, &format!("couldn't start: {e}"));
                            report(&mut output, id, None);
                        }
                    }
                } else if let Some(id) = command["stop"].as_u64()
                    && let Some(index) = members.iter().position(|m| m.id == id as u32)
                {
                    let mut member = members.remove(index);
                    let code = stop_member(&mut member.child);
                    report(&mut output, member.id, code);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // stdin closed: stop everything, newest first (sing-box before the plugin under it).
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                while let Some(mut member) = members.pop() {
                    let code = stop_member(&mut member.child);
                    report(&mut output, member.id, code);
                }
                return;
            }
        }
        members.retain_mut(|member| match member.child.try_wait() {
            Ok(Some(status)) => {
                report(&mut output, member.id, status.code());
                false
            }
            _ => true,
        });
    }
}

fn start_member(spawn: &Value) -> io::Result<Child> {
    let program = spawn["program"].as_str().ok_or_else(|| io::Error::other("no program"))?;
    let log = PathBuf::from(spawn["log"].as_str().ok_or_else(|| io::Error::other("no log"))?);
    let args: Vec<&str> = spawn["args"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    // Truncating keeps the owner: the app created the file as the user.
    let file = std::fs::OpenOptions::new().write(true).truncate(true).create(true).open(&log)?;
    Command::new(program).args(args).stdin(Stdio::null()).stdout(file.try_clone()?).stderr(file).spawn()
}

fn append_log(spawn: &Value, text: &str) {
    if let Some(log) = spawn["log"].as_str()
        && let Ok(mut file) = std::fs::OpenOptions::new().append(true).create(true).open(log)
    {
        let _ = writeln!(file, "{text}");
    }
}

/// SIGTERM (so routes get cleaned up), then kill after a timeout.
fn stop_member(child: &mut Child) -> Option<i32> {
    if let Ok(Some(status)) = child.try_wait() {
        return status.code();
    }
    #[cfg(unix)]
    // SAFETY: plain syscall on a pid we own; the child has not been reaped yet.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM)
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.wait().ok().and_then(|s| s.code())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A helper served on a thread instead of through pkexec.
    pub(crate) fn in_process() -> Arc<Elevated> {
        let (app_reads, helper_writes) = io::pipe().unwrap();
        let (helper_reads, app_writes) = io::pipe().unwrap();
        thread::spawn(move || serve(BufReader::new(helper_reads), helper_writes));
        Elevated::connect(Some(Box::new(app_writes)), Box::new(app_reads), None)
    }

    #[cfg(unix)]
    fn wait_for(what: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !what() {
            assert!(Instant::now() < deadline, "timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    fn helper_runs_stops_and_reports_processes() {
        let dir = std::env::temp_dir().join(format!("cipher_elevated_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (log_a, log_b, cleaned) = (dir.join("a.log"), dir.join("b.log"), dir.join("cleaned"));

        let helper = in_process();
        wait_for(|| helper.authorized());

        let long = format!("trap 'touch {}; exit 0' TERM; echo started; while :; do sleep 0.05; done", cleaned.display());
        let a = helper.spawn("/bin/sh".as_ref(), &["-c".into(), long.into()], &log_a).unwrap();
        let b = helper.spawn("/bin/sh".as_ref(), &["-c".into(), "echo bye; exit 3".into()], &log_b).unwrap();
        wait_for(|| std::fs::read_to_string(&log_a).unwrap_or_default().contains("started"));
        wait_for(|| helper.status(b) == MemberStatus::Exited(Some(3)));
        assert_eq!(std::fs::read_to_string(&log_b).unwrap(), "bye\n");
        assert_eq!(helper.status(a), MemberStatus::Running);

        helper.stop(a).unwrap();
        assert_eq!(helper.status(a), MemberStatus::Exited(Some(0)));
        assert!(cleaned.exists(), "the process didn't get SIGTERM");

        // A missing program is reported as exited, with the reason in its log.
        let c = helper.spawn("/nonexistent/program".as_ref(), &[], &log_a).unwrap();
        wait_for(|| helper.status(c) == MemberStatus::Exited(None));
        assert!(std::fs::read_to_string(&log_a).unwrap().contains("couldn't start"));

        // Dropping the handle closes the pipe: running processes are stopped.
        std::fs::remove_file(&cleaned).unwrap();
        let long = format!("trap 'touch {}; exit 0' TERM; while :; do sleep 0.05; done", cleaned.display());
        helper.spawn("/bin/sh".as_ref(), &["-c".into(), long.into()], &log_a).unwrap();
        thread::sleep(Duration::from_millis(200));
        drop(helper);
        wait_for(|| cleaned.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
