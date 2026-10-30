//! Drives the real UI headlessly (Slint software renderer) and saves a screenshot after each step.
//!
//! ```sh
//! CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture
//! ```
//! Frames are written as raw RGBA (`*.rgba`, 820×520); convert them with
//! `magick -size 820x520 -depth 8 rgba:file.rgba file.png`.
//!
//! The phone layout (`CIPHER_UI=phone`, 400×820) has its own test:
//! `CIPHER_UI=phone CIPHER_SCREENSHOTS=/tmp/shots cargo test phone_screenshots -- --ignored`.

// The phone layout's test uses fewer helpers than the desktop ones.
#![cfg_attr(phone_ui, allow(dead_code))]

use super::*;
use slint::platform::{
    EventLoopProxy, Platform, PlatformError, PointerEventButton, WindowAdapter, WindowEvent,
    software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType},
};
use slint::{EventLoopError, LogicalPosition, PhysicalSize};
use std::{cell::{Cell, RefCell}, path::PathBuf, rc::Rc};

#[cfg(not(phone_ui))]
const WIDTH: u32 = 820;
#[cfg(not(phone_ui))]
const HEIGHT: u32 = 520;
#[cfg(phone_ui)]
const WIDTH: u32 = 400;
#[cfg(phone_ui)]
const HEIGHT: u32 = 820;

type Queue = Arc<Mutex<Vec<Box<dyn FnOnce() + Send>>>>;

struct Headless {
    window: Rc<MinimalSoftwareWindow>,
    queue: Queue,
}

struct Proxy(Queue);

impl EventLoopProxy for Proxy {
    fn quit_event_loop(&self) -> Result<(), EventLoopError> {
        Ok(())
    }

    fn invoke_from_event_loop(&self, event: Box<dyn FnOnce() + Send>) -> Result<(), EventLoopError> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }

    fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
        Some(Box::new(Proxy(self.queue.clone())))
    }
}

struct Driver {
    window: Rc<MinimalSoftwareWindow>,
    queue: Queue,
    out: PathBuf,
    frame: RefCell<Vec<PremultipliedRgbaColor>>,
    width: Cell<u32>,
}

impl Driver {
    /// Runs posted closures, timers and animations for `ms` of wall time.
    fn pump(&self, ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(ms);
        loop {
            let events: Vec<_> = std::mem::take(&mut *self.queue.lock().unwrap());
            for event in events {
                event();
            }
            slint::platform::update_timers_and_animations();
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn shot(&self, name: &str) {
        self.pump(30);
        self.window.request_redraw();
        let mut frame = self.frame.borrow_mut();
        self.window.draw_if_needed(|renderer| {
            renderer.render(&mut frame, self.width.get() as usize);
        });
        let bytes: Vec<u8> = frame.iter().flat_map(|p| [p.red, p.green, p.blue, p.alpha]).collect();
        std::fs::write(self.out.join(format!("{name}.rgba")), bytes).unwrap();
        println!("saved {name}");
    }

    /// Resizes the window, as dragging its edges or maximizing would.
    fn resize(&self, width: u32, height: u32) {
        self.window.set_size(PhysicalSize::new(width, height));
        self.width.set(width);
        *self.frame.borrow_mut() = vec![PremultipliedRgbaColor::default(); (width * height) as usize];
        self.pump(30);
    }

    fn click(&self, x: f32, y: f32) {
        let position = LogicalPosition::new(x, y);
        self.window.dispatch_event(WindowEvent::PointerMoved { position });
        self.window.dispatch_event(WindowEvent::PointerPressed { position, button: PointerEventButton::Left });
        self.window.dispatch_event(WindowEvent::PointerReleased { position, button: PointerEventButton::Left });
        self.pump(60);
    }

    /// Presses at (x, y) and moves down by each of `steps` in turn, without releasing.
    fn drag(&self, x: f32, y: f32, steps: &[f32]) {
        let position = LogicalPosition::new(x, y);
        self.window.dispatch_event(WindowEvent::PointerMoved { position });
        self.window.dispatch_event(WindowEvent::PointerPressed { position, button: PointerEventButton::Left });
        for dy in steps {
            self.window.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(x, y + dy) });
            self.pump(20);
        }
        self.pump(200);
    }

    fn release(&self, x: f32, y: f32) {
        self.window.dispatch_event(WindowEvent::PointerReleased { position: LogicalPosition::new(x, y), button: PointerEventButton::Left });
        self.pump(60);
    }

    fn hover(&self, x: f32, y: f32) {
        self.window.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(x, y) });
        self.pump(150);
    }

    fn type_text(&self, text: &str) {
        for c in text.chars() {
            let text = SharedString::from(c.to_string());
            self.window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
            self.window.dispatch_event(WindowEvent::KeyReleased { text });
        }
        self.pump(30);
    }
}

/// A local TCP server: serves one subscription over HTTP, and accepts the latency probes.
fn serve_subscription(body_links: String) -> u16 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::io::{BufRead, BufReader, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            if reader.read_line(&mut first).is_err() || !first.starts_with("GET") {
                continue; // a latency probe: just accept and drop
            }
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let body = STANDARD.encode(&body_links);
            let title = STANDARD.encode("Cipher Premium");
            let gb = 1024u64.pow(3);
            let expire = store::now() + 23 * 86_400;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nprofile-title: base64:{title}\r\n\
                 subscription-userinfo: upload={}; download={}; total={}; expire={expire}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
                3 * gb,
                (31 * gb) / 2,
                50 * gb,
            );
            let _ = (&stream).write_all(response.as_bytes());
        }
    });
    port
}

/// Minimal HTTP server that answers every request with `body`.
fn serve_http(body: &'static str) -> u16 {
    use std::io::{BufRead, BufReader, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = (&stream).write_all(response.as_bytes());
        }
    });
    port
}

/// `GET http://127.0.0.1:<target>/` sent to the app's HTTP proxy port.
fn http_via_proxy(proxy_port: u16, target_port: u16) -> String {
    use std::io::{Read, Write};

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("proxy port not listening");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(stream, "GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// Installs the headless platform (once per process) and starts the real app in it,
/// with its data dir inside the output dir.
fn start() -> (AppWindow, Ctx, Timer, Driver) {
    let out = PathBuf::from(std::env::var("CIPHER_SCREENSHOTS").expect("set CIPHER_SCREENSHOTS to an output dir"));
    std::fs::create_dir_all(&out).unwrap();
    // Keep the real data dir untouched.
    // SAFETY: single-threaded at this point; nothing else reads the environment yet.
    unsafe { std::env::set_var("XDG_DATA_HOME", out.join("data")) };
    let _ = std::fs::remove_dir_all(out.join("data"));

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(PhysicalSize::new(WIDTH, HEIGHT));
    let queue: Queue = Arc::default();
    slint::platform::set_platform(Box::new(Headless { window: window.clone(), queue: queue.clone() })).unwrap();

    let ui = AppWindow::new().unwrap();
    ui.show().unwrap();
    let (ctx, monitor) = init(&ui, crate::store::Store::load());
    let d = Driver {
        window,
        queue,
        out,
        frame: RefCell::new(vec![PremultipliedRgbaColor::default(); (WIDTH * HEIGHT) as usize]),
        width: Cell::new(WIDTH),
    };
    (ui, ctx, monitor, d)
}

/// The routing editor in Settings. Never connects, so it's safe to run anywhere:
/// `CIPHER_SCREENSHOTS=<dir> cargo test routing_screenshots -- --ignored`
#[cfg(not(phone_ui))]
#[test]
#[ignore = "visual check: CIPHER_SCREENSHOTS=<dir> cargo test routing_screenshots -- --ignored"]
fn routing_screenshots() {
    let (ui, _ctx, _monitor, d) = start();
    let state = ui.global::<AppState>();
    d.shot("r00-traffic-idle");
    // The traffic box as it looks connected (UI state only).
    state.set_connection(ConnectionState::Connected);
    state.set_uptime("00:12:34".into());
    state.set_traffic_known(true);
    state.set_download_speed("2.4 MB/s".into());
    state.set_upload_speed("312.5 KB/s".into());
    state.set_download_total("1.3 GB".into());
    state.set_upload_total("86.2 MB".into());
    d.shot("r00b-traffic-connected");
    state.set_connection(ConnectionState::Disconnected);
    state.set_current_tab(3);
    d.shot("r01-settings");
    state.set_core(1);
    state.invoke_settings_changed();
    d.shot("r01b-core-xray");

    // Add a rule through the editor.
    state.invoke_edit_rule(-1);
    d.shot("r02-rule-dialog-empty");
    state.set_rule_dialog_kind(4); // App
    state.set_rule_dialog_target(0); // Proxy
    state.set_rule_dialog_values("firefox\n/usr/bin/telegram-desktop\nchrome.exe".into());
    d.shot("r03-rule-dialog-app");
    state.invoke_save_rule();
    d.shot("r04-rule-added");

    // An invalid value keeps the dialog open with an error.
    state.invoke_edit_rule(-1);
    state.set_rule_dialog_kind(2); // IP
    state.set_rule_dialog_values("10.0.0.0/8, not-an-ip".into());
    state.invoke_save_rule();
    d.pump(300); // sheet slide-in
    d.shot("r05-rule-dialog-error");
    assert!(state.get_rule_dialog_open());
    state.set_rule_dialog_values("10.0.0.0/8, 192.168.1.10".into());
    state.set_rule_dialog_target(1); // Direct
    state.invoke_save_rule();

    state.invoke_edit_rule(-1);
    state.set_rule_dialog_kind(0);
    state.set_rule_dialog_target(2); // Block
    state.set_rule_dialog_values("doubleclick.net".into());
    state.invoke_save_rule();
    state.invoke_toggle_preset(0);
    state.invoke_toggle_preset(3);
    state.invoke_toggle_rule(2);
    state.invoke_move_rule(1, -1);
    d.pump(300); // sheet slide-out
    d.shot("r06-rules-and-presets");
    assert_eq!(state.get_rules().row_count(), 3);
    assert_eq!(state.get_rules().row_data(0).unwrap().kind, "IP");

    // The anti-DPI toggles, below the routing rules.
    state.set_tls_fragment(true);
    state.invoke_settings_changed();
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: -450.0 });
    d.shot("r07-anti-dpi");
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: 450.0 });

    state.set_current_tab(1);

    // Grouped by protocol (with a Psiphon server entry), then one group folded, then ungrouped.
    let psiphon = crate::import::psiphon::tests::sample_entry();
    state.invoke_add_links(
        format!(
            "trojan://pw@a.example.com:443#Trojan A\n\
             vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443?security=tls#VLESS B\n\
             trojan://pw@c.example.com:443#Trojan C\n\
             hy2://pw@d.example.com:443#Hysteria D\n\
             vless://bf000d23-0752-40b4-affe-68f7707a9661@e.example.com:443?type=xhttp&security=tls&path=%2Fx#XHTTP E\n\
             psiphon://{psiphon}"
        )
        .into(),
    );
    d.shot("r12-configs-grouped");
    assert!(state.get_configs().iter().any(|c| c.name == "XHTTP E"), "XHTTP link wasn't imported");
    let server = state.get_configs().iter().find(|c| c.name == "Psiphon 203.0.113.7 (DE)").expect("Psiphon entry wasn't imported");
    state.invoke_select_config(server.id);
    d.shot("r10-psiphon-selected");
    state.invoke_toggle_group("Trojan".into());
    d.shot("r13-group-collapsed");
    state.set_group_configs(false);
    state.invoke_grouping_changed();
    d.shot("r14-ungrouped");
    state.set_current_tab(3);

    // Scrolled down to the rule list.
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: -300.0 });
    d.shot("r07-rules-scrolled");
    d.hover(600.0, 330.0);
    d.shot("r08-rule-hover");
    // The bottom: appearance, logs, about.
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: -5000.0 });
    d.shot("r09-settings-bottom");
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: 1000.0 });

    plugin_frames(&ui, &_ctx, &d);
}

/// Editing a manual config, sorting by ping and moving a group. Never connects:
/// `CIPHER_SCREENSHOTS=<dir> cargo test config_list_screenshots -- --ignored`
#[cfg(not(phone_ui))]
#[test]
#[ignore = "visual check: CIPHER_SCREENSHOTS=<dir> cargo test config_list_screenshots -- --ignored"]
fn config_list_screenshots() {
    let (ui, ctx, _monitor, d) = start();
    let state = ui.global::<AppState>();
    // A reachable "server" (answers TCP) and a closed port (fails at once).
    let open = serve_http("ok");
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661";
    state.invoke_add_links(
        format!(
            "trojan://pw@127.0.0.1:{closed}#Trojan down\n\
             trojan://pw@127.0.0.1:{open}#Trojan up\n\
             vless://{uuid}@127.0.0.1:{open}?security=tls#VLESS up\n\
             hy2://pw@h.example.com:443#Hysteria"
        )
        .into(),
    );
    d.pump(300);
    d.shot("c01-list");
    let id_of = |name: &str| state.get_configs().iter().find(|c| c.name == name).map(|c| c.id).unwrap();

    // Edit: the dialog shows the link it was added from.
    state.invoke_edit_config(id_of("Trojan down"));
    d.pump(300);
    assert!(state.get_edit_dialog_open());
    assert_eq!(state.get_edit_dialog_link(), format!("trojan://pw@127.0.0.1:{closed}#Trojan down"));
    d.shot("c02-edit-dialog");

    // A bad link keeps the dialog open with the reason.
    state.set_edit_dialog_link("vless://broken".into());
    state.invoke_save_config();
    d.pump(100);
    assert!(state.get_edit_dialog_open());
    assert_ne!(state.get_edit_dialog_error(), "");
    d.shot("c03-edit-error");

    // A new link and a new name.
    let edited = id_of("Trojan down");
    state.set_edit_dialog_name("My server".into());
    state.set_edit_dialog_link(format!("trojan://secret@127.0.0.1:{closed}?sni=example.com#Whatever").into());
    state.invoke_save_config();
    d.pump(300);
    assert!(!state.get_edit_dialog_open());
    {
        let store = ctx.store.lock().unwrap();
        let entry = store.entry(edited as u64).unwrap();
        assert_eq!(entry.profile.name(), "My server");
        assert!(entry.link.as_deref().unwrap().contains("secret@"));
    }
    d.shot("c04-edited");

    // Sort by ping: within a group the reachable one comes first.
    state.set_sort_by_latency(true);
    state.invoke_grouping_changed();
    state.invoke_test_latency();
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.get_testing() && Instant::now() < deadline {
        d.pump(50);
    }
    d.pump(100);
    let names: Vec<String> = state.get_configs().iter().map(|c| c.name.to_string()).collect();
    let at = |name: &str| names.iter().position(|n| n == name).unwrap();
    assert!(at("Trojan up") < at("My server"), "{names:?}");
    d.shot("c05-sorted-by-ping");

    // Move the Trojan group to the top.
    state.invoke_move_group("Trojan".into(), -1);
    d.pump(100);
    let headers: Vec<String> = state.get_configs().iter().filter(|c| c.header).map(|c| c.name.to_string()).collect();
    assert_eq!(headers.first().map(String::as_str), Some("Trojan"), "{headers:?}");
    d.hover(600.0, 150.0);
    d.shot("c06-group-moved");

    // Both are saved.
    let saved = crate::store::Store::load().settings;
    assert!(saved.sort_by_latency);
    assert_eq!(saved.group_order.first().map(String::as_str), Some("Trojan"));

    // Drag the Trojan heading (y 142) to the bottom: the headings fold while it moves.
    let headers = || state.get_groups().iter().map(|c| c.name.to_string()).collect::<Vec<_>>();
    d.drag(500.0, 142.0, &[12.0, 40.0, 60.0]);
    d.shot("c07-group-dragging");
    d.drag(500.0, 142.0, &[]);
    d.window.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(500.0, 225.0) });
    d.pump(200);
    d.shot("c08-group-drag-bottom");
    d.release(500.0, 225.0);
    assert_eq!(headers(), ["VLESS", "Hysteria2", "Trojan"]);
    d.shot("c09-group-dropped");
    let saved = crate::store::Store::load().settings;
    let shown: Vec<&String> = saved.group_order.iter().filter(|g| ["VLESS", "Hysteria2", "Trojan"].contains(&g.as_str())).collect();
    assert_eq!(shown, ["VLESS", "Hysteria2", "Trojan"]);

    // Held still, a heading lifts (how a finger starts a drag); letting go there neither moves nor folds it.
    let collapsed = |name: &str| state.get_groups().iter().any(|c| c.name == name && c.collapsed);
    d.drag(500.0, 142.0, &[]);
    d.pump(400);
    d.shot("c10-group-held");
    d.release(500.0, 142.0);
    assert_eq!(headers(), ["VLESS", "Hysteria2", "Trojan"]);
    assert!(!collapsed("VLESS"));
    // A plain click still folds it.
    d.click(500.0, 142.0);
    assert!(collapsed("VLESS"));
}

/// The window resized and maximized. Never connects: `CIPHER_SCREENSHOTS=<dir> cargo test resize_screenshots -- --ignored`
/// (frames are named by size, e.g. `s1-configs-1600x900.rgba`).
#[cfg(not(phone_ui))]
#[test]
#[ignore = "visual check: CIPHER_SCREENSHOTS=<dir> cargo test resize_screenshots -- --ignored"]
fn resize_screenshots() {
    let (ui, ctx, _monitor, d) = start();
    let state = ui.global::<AppState>();
    state.invoke_add_links(
        "trojan://pw@a.example.com:443#Trojan A\n\
         vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443?security=tls#VLESS B with a rather long name\n\
         hy2://pw@d.example.com:443#Hysteria D"
            .into(),
    );
    let first = state.get_configs().iter().find(|c| !c.header).unwrap();
    state.invoke_select_config(first.id);
    for (width, height) in [(820, 520), (1100, 700), (1600, 900)] {
        d.resize(width, height);
        state.set_current_tab(1);
        d.shot(&format!("s1-configs-{width}x{height}"));
        state.set_current_tab(3);
        d.shot(&format!("s2-settings-{width}x{height}"));
        state.set_links_dialog_open(true);
        d.pump(300);
        d.shot(&format!("s3-dialog-{width}x{height}"));
        state.set_links_dialog_open(false);
        d.pump(300);
    }

    // Narrow: the compact layout, with what the phone hides (System proxy, Plugins).
    for (width, height) in [(819, 520), (400, 520), (400, 800)] {
        d.resize(width, height);
        state.set_current_tab(2);
        d.shot(&format!("s4-plugins-{width}x{height}"));
        state.set_current_tab(3);
        d.shot(&format!("s5-settings-{width}x{height}"));
        d.click(100.0, (height - 34) as f32); // bottom bar: Connect
        d.shot(&format!("s6-connect-{width}x{height}"));
        // Taller than a short window: the connect screen scrolls.
        state.set_error("sing-box exited: start service: initialize inbound/tun[tun-in]: configure tun interface: operation not permitted".into());
        d.shot(&format!("s6b-connect-error-{width}x{height}"));
        state.set_error("".into());
        state.set_links_dialog_open(true);
        d.pump(300);
        d.shot(&format!("s7-dialog-{width}x{height}"));
        state.set_links_dialog_open(false);
        d.pump(300);
    }
    d.resize(820, 520);
    d.shot("s8-back-820x520");

    // The size is saved on exit, and saved in state.json for the next start.
    d.resize(1000, 640);
    super::window::save(&ui, &ctx);
    let saved = crate::store::WindowSize { width: 1000, height: 640, maximized: false };
    assert_eq!(ctx.store.lock().unwrap().window, Some(saved));
    assert_eq!(crate::store::Store::load().window, Some(saved));
}

/// The Plugins tab with installed (fake) plugins, the add review, a settings form and the
/// transport picker. Nothing runs: the plugin programs are empty files.
#[cfg(not(phone_ui))]
fn plugin_frames(ui: &AppWindow, ctx: &Ctx, d: &Driver) {
    use crate::plugin::{InstallRecord, MANIFEST_FILE, binary_name, plugins_dir, save_record};
    let state = ui.global::<AppState>();
    let data = paths::data_dir().unwrap();
    let mut transport = crate::plugin::tests::transport();
    transport.description = "Carries TCP configs through DNS queries to your own server.".into();
    let engine = crate::plugin::tests::engine();
    for (manifest, official, root_allowed) in [(&transport, true, false), (&engine, false, false)] {
        let dir = plugins_dir(&data).join(&manifest.id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(binary_name(manifest)), "").unwrap();
        std::fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(manifest).unwrap()).unwrap();
        let record = InstallRecord { source: "test".into(), sha256: String::new(), official, root_allowed, development: false };
        save_record(&data, &manifest.id, &record).unwrap();
    }
    plugins::refresh_plugins(ui, ctx);
    state.set_current_tab(2);
    d.shot("p01-plugins");
    // The two installed ones, then the official plugins not added yet.
    let rows: Vec<_> = state.get_plugins().iter().collect();
    assert_eq!(rows.len(), 2 + crate::plugin::OFFICIAL.len());
    assert!(rows.iter().any(|p| p.id == "masterdnsvpn" && p.available && p.official));

    // The review step of the add dialog, as `review_plugin` fills it in.
    state.set_plugin_review(plugins::plugin_data_for_tests(&engine));
    let warnings = ModelRc::new(VecModel::from(vec![SharedString::from("The repository is archived: the plugin is no longer maintained.")]));
    state.set_plugin_review_warnings(warnings);
    state.set_plugin_review_ready(true);
    state.set_plugin_dialog_open(true);
    d.pump(300);
    d.shot("p02-add-review");
    state.set_plugin_dialog_open(false);
    state.set_plugin_review_ready(false);

    // Allowing admin rights later asks first.
    state.invoke_allow_plugin_root("myproto".into());
    d.pump(300);
    d.shot("p03-allow-admin");
    state.invoke_allow_plugin_root("myproto".into());
    assert!(state.get_plugins().iter().any(|p| p.id == "myproto" && p.root_allowed));

    // A transport's settings for a config, then the picker under the selected config.
    state.set_current_tab(1);
    let trojan = state.get_configs().iter().find(|c| c.name == "Trojan A").unwrap();
    state.invoke_select_config(trojan.id);
    assert!(state.get_transport_available());
    state.set_selected_transport(1);
    state.invoke_transport_changed();
    d.pump(300);
    d.shot("p04-transport-fields");
    let fields = state.get_fields_dialog_fields();
    let domain = fields.iter().position(|f| f.key == "domain").unwrap();
    state.invoke_edit_field(domain as i32, "t.example.com".into());
    state.invoke_save_fields();
    d.pump(300);
    d.shot("p05-transport-picked");
    let transport = ctx.store.lock().unwrap().entry(trojan.id as u64).and_then(|e| e.transport.clone());
    assert_eq!(transport.unwrap().fields["domain"], "t.example.com");

    // A new config for the engine plugin.
    state.set_current_tab(2);
    state.invoke_new_plugin_config("myproto".into());
    state.set_fields_dialog_name("Home server".into());
    state.invoke_save_fields();
    assert!(state.get_configs().iter().any(|c| c.name == "Home server"));
    d.shot("p06-engine-config");

    // MasterDnsVPN (official) installed: its form, with the multi-line resolver list.
    let masterdns = crate::plugin::official().into_iter().find(|m| m.id == "masterdnsvpn").unwrap();
    let dir = plugins_dir(&data).join(&masterdns.id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(binary_name(&masterdns)), "").unwrap();
    std::fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(&masterdns).unwrap()).unwrap();
    let record = InstallRecord { source: "test".into(), sha256: String::new(), official: true, root_allowed: false, development: false };
    save_record(&data, &masterdns.id, &record).unwrap();
    plugins::refresh_plugins(ui, ctx);
    assert!(state.get_plugins().iter().any(|p| p.id == "masterdnsvpn" && !p.available && !p.update));
    d.shot("p07-official-installed");
    state.invoke_new_plugin_config("masterdnsvpn".into());
    let fields = state.get_fields_dialog_fields();
    let resolvers = fields.iter().position(|f| f.key == "resolvers").unwrap();
    assert_eq!(fields.row_data(resolvers).unwrap().kind, "lines");
    state.invoke_edit_field(resolvers as i32, "8.8.8.8\n1.1.1.1:5353\n192.168.1.0/30".into());
    d.pump(300);
    d.shot("p08-masterdns-fields");
    let domains = fields.iter().position(|f| f.key == "domains").unwrap();
    state.invoke_edit_field(domains as i32, "v.example.com".into());
    state.set_fields_dialog_name("Home DNS".into());
    state.invoke_save_fields();
    assert!(!state.get_fields_dialog_open());

    // The new config is selected; its settings can be edited from the connect panel.
    assert!(state.get_plugin_config_editable());
    d.pump(300);
    d.shot("p09-plugin-config-selected");
    state.invoke_edit_plugin_config();
    assert_eq!(state.get_fields_dialog_name(), "Home DNS");
    let fields = state.get_fields_dialog_fields();
    assert_eq!(fields.row_data(resolvers).unwrap().value, "8.8.8.8\n1.1.1.1:5353\n192.168.1.0/30");
    state.invoke_edit_field(resolvers as i32, "9.9.9.9".into());
    state.invoke_save_fields();
    let id = state.get_selected_id() as u64;
    let profile = ctx.store.lock().unwrap().entry(id).unwrap().profile.clone();
    let Profile::Plugin { name, fields, .. } = profile else { panic!("not a plugin config") };
    assert_eq!((name.as_str(), fields["resolvers"].as_str()), ("Home DNS", "9.9.9.9"));

    // A core plugin: a "core" badge, a row under Settings → Engines, and a choice under Core.
    let fork = crate::plugin::tests::core();
    let dir = plugins_dir(&data).join(&fork.id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(binary_name(&fork)), "").unwrap();
    std::fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(&fork).unwrap()).unwrap();
    save_record(&data, &fork.id, &record).unwrap();
    plugins::refresh_plugins(ui, ctx);
    state.set_current_tab(2);
    d.pump(300);
    d.shot("p10-core-plugin");
    assert!(state.get_plugins().iter().any(|p| p.id == "fork" && p.kind == "Core"));
    assert_eq!(state.get_core_plugins().row_count(), 1);
    assert_eq!(state.get_cores().iter().map(|c| c.to_string()).collect::<Vec<_>>(), ["sing-box", "Xray", "Fork"]);
    state.set_core(2);
    state.invoke_settings_changed();
    assert_eq!(ctx.store.lock().unwrap().settings.core, crate::engine::xray::Core::Plugin("fork".into()));
    state.set_current_tab(3);
    d.pump(300);
    d.shot("p11-core-settings");
}

#[cfg(not(phone_ui))]
#[test]
#[ignore = "visual check: CIPHER_SCREENSHOTS=<dir> cargo test screenshots -- --ignored"]
fn screenshots() {
    let (ui, _ctx, _monitor, d) = start();

    // The local server doubles as a reachable "proxy server" for the latency test.
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661";
    let local = format!("127.0.0.1:{}", serve_subscription(String::new()));
    let sub_links = [
        format!("vless://{uuid}@{local}?security=reality&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0#🇩🇪 Germany Reality"),
        format!("vmess://{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD,
            format!(r#"{{"ps":"🇺🇸 US WebSocket","add":"127.0.0.1","port":"{}","id":"{uuid}","net":"ws","tls":"tls"}}"#, local.split(':').nth(1).unwrap()))),
        format!("trojan://pw@{local}?type=grpc&serviceName=x#🇳🇱 Netherlands gRPC"),
        "hy2://pw@hy.example.com:443#🇫🇮 Finland Hysteria2".to_owned(),
        "ssr://d2hhdGV2ZXI".to_owned(),
    ]
    .join("\n");
    let sub_port = serve_subscription(sub_links);

    // 1. First start: Configs tab, empty.
    d.shot("01-empty");

    // 2. Paste share links.
    d.click(612.0, 102.0); // "Add"
    d.type_text(&format!(
        "vless://{uuid}@{local}?security=tls&sni=de.example.com&type=ws#Home server\n\
         ss://{}@10.255.255.1:8388#Blackholed SS\n\
         wireguard://eCtXsJZ27%2B4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU%3D@203.0.113.1:51820?publickey=Cr8hWlKvtDt7nrvf%2Bf0brNQQzabAqrjfBvas9pmowjo%3D&address=10.0.0.2#Office WireGuard",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, "aes-256-gcm:pw")
    ));
    d.shot("02-add-links-dialog");
    d.click(770.0, 466.0); // dialog "Add"
    d.shot("03-configs-added");

    // 3. Select a config, then run the latency test.
    d.click(500.0, 182.0);
    d.shot("04-selected");
    d.click(780.0, 102.0); // "Test"
    d.shot("05-latency-testing");
    d.pump(3500);
    d.shot("06-latency-done");

    // 4. Add a subscription served from localhost.
    d.click(394.0, 60.0); // Subscriptions tab
    d.shot("07-subscriptions-empty");
    d.click(370.0, 102.0); // "Add subscription"
    d.type_text(&format!("http://127.0.0.1:{sub_port}/sub/token"));
    d.shot("08-subscription-dialog");
    d.click(770.0, 466.0); // dialog "Add"
    d.pump(800);
    d.shot("09-subscription-added");
    d.hover(560.0, 160.0);
    d.shot("10-subscription-hover");

    // 5. Open the subscription's configs.
    d.click(560.0, 160.0);
    d.shot("11-subscription-configs");

    // 6. Settings.
    d.click(720.0, 60.0);
    d.shot("12-settings");

    // 6b. Engines: without sing-box, install it from Settings (real download, checksum-verified).
    //     The rest of the run then uses that binary. (Test builds never ask for the admin password.)
    d.pump(1500); // engine detection runs in the background
    d.shot("12a-engines");
    if !ui.global::<AppState>().get_singbox_installed() {
        d.click(758.0, 130.0); // Download
        d.shot("12b-engines-downloading");
        let deadline = Instant::now() + Duration::from_secs(120);
        while ui.global::<AppState>().get_engine_busy() && Instant::now() < deadline {
            d.pump(200);
        }
        d.pump(1500);
        d.shot("12c-engines-installed");
        assert!(ui.global::<AppState>().get_singbox_installed(), "sing-box didn't install");
    }

    // 7. Connect: shows the animation, then the engine's real error (no sing-box / no rights here).
    d.click(557.0, 60.0);
    d.click(150.0, 200.0);
    d.pump(250);
    d.shot("13-connecting");
    d.pump(450);
    d.shot("14-connecting-later");
    d.pump(3000);
    d.shot("15-connect-result");

    // 8. A connection that hangs (OpenVPN to a silent UDP address): animation, then cancel.
    let ovpn = d.out.join("data/hang.ovpn");
    std::fs::write(d.out.join("data/creds.txt"), "user\npass\n").unwrap();
    std::fs::write(
        &ovpn,
        "client\ndev tun\nproto udp\nremote 192.0.2.1 1194\nca /etc/ssl/certs/ca-certificates.crt\nauth-user-pass creds.txt\n",
    )
    .unwrap();
    {
        let mut store = _ctx.store.lock().unwrap();
        let ids = store.add_profiles(vec![(crate::import::import_openvpn(&ovpn).unwrap(), None)]);
        store.selected = Some(ids[0]);
    }
    refresh_all(&ui, &_ctx);
    d.click(150.0, 200.0);
    d.pump(300);
    d.shot("17-ovpn-connecting-a");
    d.pump(350);
    d.shot("18-ovpn-connecting-b");
    d.click(150.0, 200.0); // cancel
    d.shot("19-ovpn-cancelling");
    d.pump(1500);
    d.shot("20-ovpn-cancelled");

    // 8b. OpenVPN config with a bare `auth-user-pass`: connect asks for a login first, and the
    //     login reaches openvpn through a private file that's removed on stop.
    let login_ovpn = d.out.join("data/login.ovpn");
    std::fs::write(
        &login_ovpn,
        "client\ndev tun\nproto udp\nremote 192.0.2.1 1194\nca /etc/ssl/certs/ca-certificates.crt\nauth-user-pass\n",
    )
    .unwrap();
    {
        let mut store = _ctx.store.lock().unwrap();
        let ids = store.add_profiles(vec![(crate::import::import_openvpn(&login_ovpn).unwrap(), None)]);
        store.selected = Some(ids[0]);
    }
    refresh_all(&ui, &_ctx);
    d.click(150.0, 200.0); // connect → sign-in dialog
    d.pump(300);
    d.shot("20b-ovpn-sign-in");
    assert!(ui.global::<AppState>().get_creds_dialog_open(), "sign-in dialog didn't open");
    d.type_text("alice");
    d.click(410.0, 434.0); // password field
    d.type_text("s3cret");
    d.shot("20c-ovpn-sign-in-filled");
    d.click(768.0, 474.0); // Connect
    d.pump(1200);
    d.shot("20d-ovpn-signed-in-connecting");
    let auth_file = d.out.join("data/cipher_client/openvpn-auth.txt");
    assert_eq!(std::fs::read_to_string(&auth_file).unwrap(), "alice\ns3cret\n");
    assert_eq!(ui.global::<AppState>().get_connection(), ConnectionState::Connecting, "openvpn didn't accept the login file");
    d.click(150.0, 200.0); // cancel
    d.pump(1500);
    assert!(!auth_file.exists(), "credentials file left behind");

    // 9. Proxy only, for real: app → sing-box (mixed :client) → shadowsocks → our own
    //    sing-box server → HTTP target. Needs no admin rights. (System proxy is never connected
    //    here: it would change the desktop's proxy settings.)
    let free_port = || std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (ss_port, proxy_port) = (free_port(), free_port());
    let target_port = serve_http("hello through the tunnel");

    let server_config = d.out.join("data/ss-server.json");
    std::fs::write(&server_config, format!(
        r#"{{"log":{{"level":"info"}},"inbounds":[{{"type":"shadowsocks","listen":"127.0.0.1","listen_port":{ss_port},"method":"aes-256-gcm","password":"cipher-test"}}],"outbounds":[{{"type":"direct"}}]}}"#
    )).unwrap();
    let sing_box = crate::engine::paths::find_binary("sing-box").expect("sing-box must be in PATH for this step");
    let server_log = d.out.join("data/ss-server.log");
    let mut server = crate::engine::process::Process::spawn("ss-server", &sing_box, ["run".as_ref(), "-c".as_ref(), server_config.as_os_str()], &server_log).unwrap();

    let ss = format!("ss://{}@127.0.0.1:{ss_port}#Local Shadowsocks",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, "aes-256-gcm:cipher-test"));
    {
        let mut store = _ctx.store.lock().unwrap();
        let ids = store.add_profiles(vec![(crate::import::parse_link(&ss).unwrap(), None)]);
        store.selected = Some(ids[0]);
        // Localhost counts as LAN: without this the request would skip the tunnel.
        store.settings.bypass_lan = false;
        store.settings.proxy_port = proxy_port;
    }
    load_settings(&ui, &_ctx);
    refresh_all(&ui, &_ctx);

    d.click(233.0, 368.0); // mode: Proxy only
    d.shot("21-mode-proxy-only");
    d.click(150.0, 187.0); // connect
    d.pump(2500);
    d.shot("22-proxy-connected");

    let response = http_via_proxy(proxy_port, target_port);
    println!("response through the app's proxy: {:?}", response.lines().last());
    assert!(response.ends_with("hello through the tunnel"), "unexpected response: {response}");
    let server_side = std::fs::read_to_string(&server_log).unwrap();
    assert!(server_side.contains(&format!("127.0.0.1:{target_port}")), "the request didn't go through the server:\n{server_side}");

    d.click(150.0, 187.0); // disconnect
    d.pump(1500);
    d.shot("23-proxy-disconnected");
    assert!(std::net::TcpStream::connect(("127.0.0.1", proxy_port)).is_err(), "proxy port still open after disconnect");
    server.stop().unwrap();

    d.click(141.0, 368.0); // mode: System proxy (not connected)
    d.shot("24-mode-system-proxy");
    d.click(720.0, 60.0); // Settings, now with the Proxy section
    d.shot("25-settings-proxy");

    // 10. Subscription list after the layout changes.
    d.click(394.0, 60.0);
    d.pump(7000); // let the toast fade
    d.shot("16-subscriptions");
}

/// The phone layout: connect screen, library tabs, a dialog. Never connects.
#[cfg(phone_ui)]
#[test]
#[ignore = "visual check: CIPHER_UI=phone CIPHER_SCREENSHOTS=<dir> cargo test phone_screenshots -- --ignored"]
fn phone_screenshots() {
    let (ui, _ctx, _monitor, d) = start();
    let state = ui.global::<AppState>();
    d.shot("p01-connect-empty");
    d.click(200.0, 572.0); // the selected-config card: opens the Configs tab

    state.invoke_add_links(
        "trojan://pw@a.example.com:443#Trojan A\n\
         vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443?security=tls#VLESS B with a rather long name\n\
         hy2://pw@d.example.com:443#Hysteria D"
            .into(),
    );
    d.pump(300);
    d.shot("p02-library-configs");
    let first = state.get_configs().iter().find(|c| !c.header).unwrap();
    state.invoke_select_config(first.id);
    d.click(100.0, (HEIGHT - 34) as f32); // bottom bar: Connect
    d.shot("p03-connect-selected");
    assert_eq!(state.get_mode(), 0);
    d.click(300.0, 484.0); // mode: Proxy only (2nd of 2 tabs)
    d.shot("p04-proxy-only");
    assert_eq!(state.get_mode(), 2);

    // Pull to connect, with toggling counted instead of connecting.
    let toggles = Rc::new(Cell::new(0));
    state.on_toggle_connection({
        let toggles = toggles.clone();
        move || toggles.set(toggles.get() + 1)
    });
    d.drag(200.0, 120.0, &[10.0, 30.0, 60.0, 80.0]); // on empty space above the button
    d.shot("p04a-pull-half");
    d.release(200.0, 200.0);
    d.shot("p04b-pull-let-go");
    assert_eq!(toggles.get(), 0, "an unfinished pull doesn't toggle");
    d.drag(200.0, 250.0, &[10.0, 60.0, 120.0]); // starting on the button
    d.shot("p04c-pull-most");
    for dy in [150.0, 180.0, 220.0] {
        d.window.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(200.0, 250.0 + dy) });
        d.pump(20);
    }
    d.shot("p04d-pull-done");
    d.release(200.0, 470.0);
    assert_eq!(toggles.get(), 1, "a full pull toggles once");
    d.drag(200.0, 250.0, &[4.0, 20.0]);
    d.release(200.0, 270.0); // a short drag on the button: neither a pull nor a tap
    assert_eq!(toggles.get(), 1);
    d.click(200.0, 250.0);
    assert_eq!(toggles.get(), 2, "a tap still toggles");

    d.click(300.0, (HEIGHT - 34) as f32); // bottom bar: Library
    state.set_current_tab(0);
    d.shot("p05-subscriptions");
    state.set_bundled_engines(true); // as on Android
    state.set_current_tab(3);
    d.shot("p06-settings");
    state.set_current_tab(1);
    state.set_links_dialog_open(true);
    d.pump(300);
    d.shot("p07-add-dialog");
}
