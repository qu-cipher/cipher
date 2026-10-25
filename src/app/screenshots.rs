//! Drives the real UI headlessly (Slint software renderer) and saves a screenshot after each step.
//!
//! ```sh
//! CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture
//! ```
//! Frames are written as raw RGBA (`*.rgba`, 820×520); convert them with
//! `magick -size 820x520 -depth 8 rgba:file.rgba file.png`.

use super::*;
use slint::platform::{
    EventLoopProxy, Platform, PlatformError, PointerEventButton, WindowAdapter, WindowEvent,
    software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType},
};
use slint::{EventLoopError, LogicalPosition, PhysicalSize};
use std::{cell::RefCell, path::PathBuf, rc::Rc};

const WIDTH: u32 = 820;
const HEIGHT: u32 = 520;

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
            renderer.render(&mut frame, WIDTH as usize);
        });
        let bytes: Vec<u8> = frame.iter().flat_map(|p| [p.red, p.green, p.blue, p.alpha]).collect();
        std::fs::write(self.out.join(format!("{name}.rgba")), bytes).unwrap();
        println!("saved {name}");
    }

    fn click(&self, x: f32, y: f32) {
        let position = LogicalPosition::new(x, y);
        self.window.dispatch_event(WindowEvent::PointerMoved { position });
        self.window.dispatch_event(WindowEvent::PointerPressed { position, button: PointerEventButton::Left });
        self.window.dispatch_event(WindowEvent::PointerReleased { position, button: PointerEventButton::Left });
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
    let (ctx, monitor) = init(&ui);
    let d = Driver {
        window,
        queue,
        out,
        frame: RefCell::new(vec![PremultipliedRgbaColor::default(); (WIDTH * HEIGHT) as usize]),
    };
    (ui, ctx, monitor, d)
}

/// The routing editor in Settings. Never connects, so it's safe to run anywhere:
/// `CIPHER_SCREENSHOTS=<dir> cargo test routing_screenshots -- --ignored`
#[test]
#[ignore = "visual check: CIPHER_SCREENSHOTS=<dir> cargo test routing_screenshots -- --ignored"]
fn routing_screenshots() {
    let (ui, _ctx, _monitor, d) = start();
    let state = ui.global::<AppState>();
    state.set_current_tab(2);
    d.shot("r01-settings");

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

    // The Psiphon settings and the built-in entry in the Configs tab.
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: -700.0 });
    d.shot("r09-psiphon-settings");
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: 1000.0 });
    state.set_current_tab(1);
    d.shot("r10-configs-psiphon");
    state.invoke_select_config(0);
    d.shot("r11-psiphon-selected");

    // Grouped by protocol, then one group folded, then ungrouped.
    state.invoke_add_links(
        "trojan://pw@a.example.com:443#Trojan A\n\
         vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443?security=tls#VLESS B\n\
         trojan://pw@c.example.com:443#Trojan C\n\
         hy2://pw@d.example.com:443#Hysteria D".into(),
    );
    d.shot("r12-configs-grouped");
    state.invoke_toggle_group("Trojan".into());
    d.shot("r13-group-collapsed");
    state.set_group_configs(false);
    state.invoke_grouping_changed();
    d.shot("r14-ungrouped");
    state.set_current_tab(2);

    // Scrolled down to the rule list.
    d.window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(600.0, 300.0), delta_x: 0.0, delta_y: -300.0 });
    d.shot("r07-rules-scrolled");
    d.hover(600.0, 330.0);
    d.shot("r08-rule-hover");
}

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
        let ids = store.add_profiles(vec![crate::import::import_openvpn(&ovpn).unwrap()]);
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
        let ids = store.add_profiles(vec![crate::import::import_openvpn(&login_ovpn).unwrap()]);
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
        let ids = store.add_profiles(vec![crate::import::parse_link(&ss).unwrap()]);
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
