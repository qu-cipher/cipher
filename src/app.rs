//! Connects the Slint UI to the store, the importers and the engines.
//!
//! The store, engine and caches live in [`Shared`] behind mutexes. Slow work (downloads,
//! connecting, latency tests, file dialogs) runs on background threads, which post their
//! results back to the UI thread with `upgrade_in_event_loop`.

use crate::engine::{self, Engine, EngineError, Status, install, openvpn, paths, process, psiphon, singbox, traffic::Traffic, xray};
use crate::engine::singbox::config::log::LogLevel;
use crate::import::{self, ImportError};
use crate::engine::singbox::generate::PROXY_LISTEN;
use crate::plugin::TransportUse;
use crate::profile::{ConnectionMode, Credentials, Profile, Settings};
use crate::routing::{Preset, Rule, RuleKind, Routing, Target};
use crate::store::{self, Store};
use crate::{AppState, AppWindow, ConfigData, ConnectionState, PresetData, RuleData, SubscriptionData};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const LOG_LEVELS: [LogLevel; 4] = [LogLevel::Debug, LogLevel::Info, LogLevel::Warn, LogLevel::Error];
/// Same order as the mode switch in the UI.
const MODES: [ConnectionMode; 3] = [ConnectionMode::Tunnel, ConnectionMode::SystemProxy, ConnectionMode::ProxyOnly];
/// Same order as `route-defaults` / `rule-targets` in the UI.
/// Settings → APPEARANCE → UI scale, in the order of `AppState.ui-scales`.
const UI_SCALES: [Option<u16>; 6] = [None, Some(100), Some(125), Some(150), Some(175), Some(200)];
const ROUTE_DEFAULTS: [Target; 2] = [Target::Proxy, Target::Direct];
const TARGETS: [Target; 3] = [Target::Proxy, Target::Direct, Target::Block];
/// Same order as `cores` in the UI.
/// Order of the groups in the grouped Configs list (`Profile::group`).
const GROUP_ORDER: [&str; 16] = [
    "VLESS", "VMess", "Trojan", "Shadowsocks", "Hysteria2", "TUIC", "AnyTLS", "WireGuard", "OpenVPN", "Psiphon",
    "Plugins", "SOCKS", "HTTP", "Direct", "Selector", "URLTest",
];
/// Index of the Settings tab (`tabs` in library-panel.slint).
const SETTINGS_TAB: i32 = 3;
const STARTUP_GRACE: Duration = Duration::from_millis(1500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// How long the admin password dialog may stay open (for Psiphon: also its first connection).
const PASSWORD_TIMEOUT: Duration = Duration::from_secs(120);
const LATENCY_TIMEOUT: Duration = Duration::from_secs(3);
const LATENCY_WORKERS: usize = 16;
/// Connect "error" when the user cancelled; not shown as an error.
const CANCELLED: &str = "Cancelled";

/// Which configs the list shows.
#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Manual,
    Subscription(u64),
}

#[derive(Clone, Copy)]
enum Latency {
    Testing,
    Ms(u128),
    Failed,
}

struct Shared {
    store: Mutex<Store>,
    engine: Mutex<Option<Box<dyn Engine + Send>>>,
    state: Mutex<ConnectionState>,
    connected_since: Mutex<Option<Instant>>,
    /// The engine's last few traffic readings (speeds average over them).
    traffic: Mutex<VecDeque<(Instant, Traffic)>>,
    cancel: AtomicBool,
    filter: Mutex<Filter>,
    latency: Mutex<HashMap<u64, Latency>>,
    /// Collapsed groups in the Configs list (this session only).
    collapsed: Mutex<HashSet<&'static str>>,
    updating: Mutex<HashSet<u64>>,
    notice_seq: AtomicU64,
    /// The config the sign-in dialog is for, and whether to connect after it.
    credentials_for: Mutex<Option<(u64, bool)>>,
    /// The plugin the add dialog reviewed, waiting for "Install".
    plugin_review: Mutex<Option<crate::plugin::install::Review>>,
    /// What the plugin fields dialog edits.
    fields_target: Mutex<Option<plugins::FieldsTarget>>,
}

type Ctx = Arc<Shared>;

pub fn run() -> Result<(), Box<dyn Error>> {
    let store = Store::load();
    // The winit backend reads this once, when it creates the window. A value the user set wins.
    #[cfg(not(target_os = "android"))]
    if let Some(percent) = store.settings.ui_scale
        && std::env::var_os(SCALE_FACTOR_VAR).is_none()
    {
        // SAFETY: single-threaded at this point; nothing else reads the environment yet.
        unsafe { std::env::set_var(SCALE_FACTOR_VAR, (f32::from(percent) / 100.0).to_string()) };
    }
    let ui = AppWindow::new()?;
    // Matches cipher_client.desktop, so the shell shows the launcher icon for this window.
    #[cfg(not(target_os = "android"))]
    slint::set_xdg_app_id("cipher_client")?;
    let (ctx, _monitor) = init(&ui, store);

    ui.run()?;

    // Take the tunnel down before exiting; stopping can take a few seconds, so hide first.
    ui.hide()?;
    if let Some(mut engine) = ctx.engine.lock().unwrap().take() {
        let _ = engine.stop();
    }
    Ok(())
}

/// Loads the store, wires up the window and starts the monitor (keep the timer alive).
fn init(ui: &AppWindow, store: Store) -> (Ctx, Timer) {
    let ctx: Ctx = Arc::new(Shared {
        store: Mutex::new(store),
        engine: Mutex::new(None),
        state: Mutex::new(ConnectionState::Disconnected),
        connected_since: Mutex::new(None),
        traffic: Mutex::new(VecDeque::new()),
        cancel: AtomicBool::new(false),
        filter: Mutex::new(Filter::All),
        latency: Mutex::new(HashMap::new()),
        collapsed: Mutex::new(HashSet::new()),
        updating: Mutex::new(HashSet::new()),
        notice_seq: AtomicU64::new(0),
        credentials_for: Mutex::new(None),
        plugin_review: Mutex::new(None),
        fields_target: Mutex::new(None),
    });

    bind_window(ui);
    tray::init(ui, &ctx);
    bind_callbacks(ui, &ctx);
    load_settings(ui, &ctx);
    refresh_routing(ui, &ctx);
    refresh_all(ui, &ctx);
    plugins::refresh_plugins(ui, &ctx);
    refresh_engines(ui, &ctx);

    // Watches the running engine and ticks the uptime clock.
    let monitor = Timer::default();
    monitor.start(TimerMode::Repeated, Duration::from_secs(1), {
        let weak = ui.as_weak();
        let ctx = ctx.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                monitor_tick(&ui, &ctx);
            }
        }
    });
    (ctx, monitor)
}

fn bind_window(ui: &AppWindow) {
    ui.on_minimize_window({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.window().set_minimized(true);
            }
        }
    });
}

const SCALE_FACTOR_VAR: &str = "SLINT_SCALE_FACTOR";

/// Settings → UI scale changed: rescales the open window, keeping its logical size.
fn ui_scale_changed(ui: &AppWindow, ctx: &Ctx) {
    settings_changed(ui, ctx);
    let Some(percent) = ctx.store.lock().unwrap().settings.ui_scale else {
        // The system's own factor is only known when the window is created.
        notify(ui, ctx, "The system scale applies the next time Cipher starts.", false);
        return;
    };
    let window = ui.window();
    let size = window.size().to_logical(window.scale_factor());
    let scale_factor = f32::from(percent) / 100.0;
    let _ = window.dispatch_event_with_result(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor });
    window.set_size(size.to_physical(scale_factor));
}

/// Registers an `AppState` callback that gets the window and the shared state.
macro_rules! on {
    ($ui:expr, $ctx:expr, $setter:ident, |$app:ident, $c:ident $(, $arg:ident : $ty:ty)*| $body:expr) => {{
        let weak = $ui.as_weak();
        let ctx = $ctx.clone();
        $ui.global::<AppState>().$setter(move |$($arg: $ty),*| {
            if let Some($app) = weak.upgrade() {
                let $c = &ctx;
                $body
            }
        });
    }};
}

mod plugins;
mod tray;

fn bind_callbacks(ui: &AppWindow, ctx: &Ctx) {
    plugins::bind(ui, ctx);
    on!(ui, ctx, on_toggle_connection, |ui, ctx| toggle_connection(&ui, ctx));
    on!(ui, ctx, on_mode_changed, |ui, ctx| {
        settings_changed(&ui, ctx);
        // Like switching configs: a live connection moves over to the new mode.
        if *ctx.state.lock().unwrap() == ConnectionState::Connected {
            connect(&ui, ctx);
        }
    });
    on!(ui, ctx, on_select_config, |ui, ctx, id: i32| select_config(&ui, ctx, id as u64));
    on!(ui, ctx, on_remove_config, |ui, ctx, id: i32| remove_config(&ui, ctx, id as u64));
    on!(ui, ctx, on_filter_changed, |ui, ctx, index: i32| filter_changed(&ui, ctx, index));
    on!(ui, ctx, on_ui_scale_changed, |ui, ctx| ui_scale_changed(&ui, ctx));
    on!(ui, ctx, on_grouping_changed, |ui, ctx| {
        settings_changed(&ui, ctx);
        refresh_configs(&ui, ctx);
    });
    on!(ui, ctx, on_toggle_group, |ui, ctx, name: SharedString| {
        let Some(group) = GROUP_ORDER.iter().find(|g| **g == name.as_str()) else { return };
        {
            let mut collapsed = ctx.collapsed.lock().unwrap();
            if !collapsed.remove(group) {
                collapsed.insert(group);
            }
        }
        refresh_configs(&ui, ctx);
    });
    on!(ui, ctx, on_test_latency, |ui, ctx| test_latency(&ui, ctx));
    on!(ui, ctx, on_add_links, |ui, ctx, text: SharedString| add_links(&ui, ctx, &text));
    on!(ui, ctx, on_import_files, |ui, ctx| import_files(&ui, ctx));
    on!(ui, ctx, on_submit_credentials, |ui, ctx| submit_credentials(&ui, ctx));
    on!(ui, ctx, on_add_subscription, |ui, ctx, url: SharedString| add_subscription(&ui, ctx, &url));
    on!(ui, ctx, on_update_subscription, |ui, ctx, id: i32| update_subscription(&ui, ctx, id as u64));
    on!(ui, ctx, on_update_all_subscriptions, |ui, ctx| {
        let ids: Vec<u64> = ctx.store.lock().unwrap().subscriptions.iter().map(|s| s.id).collect();
        for id in ids {
            update_subscription(&ui, ctx, id);
        }
    });
    on!(ui, ctx, on_remove_subscription, |ui, ctx, id: i32| remove_subscription(&ui, ctx, id as u64));
    on!(ui, ctx, on_show_subscription, |ui, ctx, index: i32| {
        let id = ctx.store.lock().unwrap().subscriptions.get(index as usize).map(|s| s.id);
        if let Some(id) = id {
            *ctx.filter.lock().unwrap() = Filter::Subscription(id);
            refresh_configs(&ui, ctx);
        }
    });
    on!(ui, ctx, on_settings_changed, |ui, ctx| settings_changed(&ui, ctx));
    on!(ui, ctx, on_toggle_preset, |ui, ctx, index: i32| toggle_preset(&ui, ctx, index as usize));
    on!(ui, ctx, on_edit_rule, |ui, ctx, index: i32| edit_rule(&ui, ctx, index));
    on!(ui, ctx, on_save_rule, |ui, ctx| save_rule(&ui, ctx));
    on!(ui, ctx, on_remove_rule, |ui, ctx, index: i32| change_rules(&ui, ctx, |rules| {
        if (index as usize) < rules.len() {
            rules.remove(index as usize);
        }
    }));
    on!(ui, ctx, on_toggle_rule, |ui, ctx, index: i32| change_rules(&ui, ctx, |rules| {
        if let Some(rule) = rules.get_mut(index as usize) {
            rule.enabled = !rule.enabled;
        }
    }));
    on!(ui, ctx, on_move_rule, |ui, ctx, index: i32, delta: i32| change_rules(&ui, ctx, |rules| {
        let to = index + delta;
        if index >= 0 && to >= 0 && (to as usize) < rules.len() && (index as usize) < rules.len() {
            rules.swap(index as usize, to as usize);
        }
    }));
    on!(ui, ctx, on_install_singbox, |ui, ctx| {
        install_engine(&ui, ctx, "sing-box", |state: &AppState, busy| state.set_engine_busy(busy), install::install_singbox)
    });
    on!(ui, ctx, on_install_xray, |ui, ctx| install_engine(&ui, ctx, "Xray", |state: &AppState, busy| state.set_xray_busy(busy), install::install_xray));
    on!(ui, ctx, on_install_psiphon, |ui, ctx| {
        install_engine(&ui, ctx, "Psiphon", |state: &AppState, busy| state.set_psiphon_busy(busy), install::install_psiphon)
    });
    on!(ui, ctx, on_open_data_dir, |ui, ctx| {
        if let Err(e) = paths::data_dir().and_then(|dir| open_external(&dir).map_err(Into::into)) {
            notify(&ui, ctx, format!("Couldn't open the data folder: {e}"), true);
        }
    });
    on!(ui, ctx, on_open_url, |ui, ctx, url: SharedString| {
        if let Err(e) = open_external(url.as_str()) {
            notify(&ui, ctx, format!("Couldn't open {url}: {e}"), true);
        }
    });
}

/// Runs `f` on the UI thread (from any thread).
fn on_ui(weak: &Weak<AppWindow>, ctx: &Ctx, f: impl FnOnce(&AppWindow, &Ctx) + Send + 'static) {
    let ctx = ctx.clone();
    let _ = weak.upgrade_in_event_loop(move |ui| f(&ui, &ctx));
}

fn save(ui: &AppWindow, ctx: &Ctx, store: &Store) {
    if let Err(e) = store.save() {
        notify(ui, ctx, format!("Couldn't save your configs: {e}"), true);
    }
}

/// Shows a toast that hides itself after a few seconds.
fn notify(ui: &AppWindow, ctx: &Ctx, text: impl Into<SharedString>, is_error: bool) {
    let seq = ctx.notice_seq.fetch_add(1, Ordering::Relaxed) + 1;
    let state = ui.global::<AppState>();
    state.set_notice(text.into());
    state.set_notice_is_error(is_error);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    Timer::single_shot(Duration::from_secs(if is_error { 7 } else { 4 }), move || {
        // Only hide it if no newer toast replaced it.
        if ctx.notice_seq.load(Ordering::Relaxed) == seq && let Some(ui) = weak.upgrade() {
            ui.global::<AppState>().set_notice(SharedString::new());
        }
    });
}

// ───────────────────────────── Lists ─────────────────────────────

fn refresh_all(ui: &AppWindow, ctx: &Ctx) {
    refresh_subscriptions(ui, ctx);
    refresh_configs(ui, ctx);
}

fn refresh_subscriptions(ui: &AppWindow, ctx: &Ctx) {
    let store = ctx.store.lock().unwrap();
    let updating = ctx.updating.lock().unwrap();
    let now = store::now();

    let rows: Vec<SubscriptionData> = store
        .subscriptions
        .iter()
        .map(|s| {
            let (usage, progress) = match s.usage {
                Some(u) if u.total > 0 => (
                    format!("{} / {}", format_bytes(u.used()), format_bytes(u.total)),
                    u.used() as f32 / u.total as f32,
                ),
                Some(u) => (format!("{} used", format_bytes(u.used())), -1.0),
                None => ("No usage info".into(), -1.0),
            };
            let expire = match s.usage.and_then(|u| u.expire) {
                Some(at) if at <= now => "Expired".into(),
                Some(at) => match (at - now) / 86_400 {
                    0 => "Expires today".into(),
                    1 => "1 day left".into(),
                    days => format!("{days} days left"),
                },
                None => String::new(),
            };
            SubscriptionData {
                id: s.id as i32,
                name: s.name.as_str().into(),
                count: s.entries.len() as i32,
                usage: usage.into(),
                progress,
                expire: expire.into(),
                updated: s.updated_at.map_or("never".into(), |t| format_ago(now.saturating_sub(t))).into(),
                updating: updating.contains(&s.id),
            }
        })
        .collect();

    ui.global::<AppState>().set_subscriptions(ModelRc::new(VecModel::from(rows)));
}

fn refresh_configs(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let store = ctx.store.lock().unwrap();
    let latency = ctx.latency.lock().unwrap();
    let mut filter = ctx.filter.lock().unwrap();

    // Filter list: All, Manual, then one entry per subscription.
    if let Filter::Subscription(id) = *filter && !store.subscriptions.iter().any(|s| s.id == id) {
        *filter = Filter::All;
    }
    let mut filters: Vec<SharedString> = vec!["All configs".into(), "Added manually".into()];
    filters.extend(store.subscriptions.iter().map(|s| SharedString::from(s.name.as_str())));
    let filter_index = match *filter {
        Filter::All => 0,
        Filter::Manual => 1,
        Filter::Subscription(id) => 2 + store.subscriptions.iter().position(|s| s.id == id).unwrap_or(0),
    };

    let mut rows: Vec<(&Profile, ConfigData)> = store
        .all_entries()
        .filter(|(source, _)| match *filter {
            Filter::All => true,
            Filter::Manual => source.is_none(),
            Filter::Subscription(id) => source.is_some_and(|s| s.id == id),
        })
        .map(|(source, entry)| {
            let (latency, level) = latency_display(latency.get(&entry.id).copied());
            (&entry.profile, ConfigData {
                id: entry.id as i32,
                name: entry.profile.name().into(),
                protocol: entry.profile.protocol().into(),
                source: source_label(source).into(),
                latency: latency.into(),
                latency_level: level,
                removable: source.is_none(),
                ..Default::default()
            })
        })
        .collect();
    let rows = match store.settings.group_configs {
        true => grouped(&mut rows, &ctx.collapsed.lock().unwrap()),
        false => rows.into_iter().map(|(_, row)| row).collect(),
    };

    state.set_filters(ModelRc::new(VecModel::from(filters)));
    state.set_filter_index(filter_index as i32);
    state.set_config_total(store.all_entries().count() as i32);
    state.set_configs(ModelRc::new(VecModel::from(rows)));

    // The selected config card.
    let selected = store.selected.and_then(|id| store.all_entries().find(|(_, e)| e.id == id));
    match selected {
        Some((source, entry)) => {
            state.set_selected_id(entry.id as i32);
            state.set_selected_name(entry.profile.name().into());
            state.set_selected_protocol(entry.profile.protocol().into());
            state.set_selected_source(source_label(source).into());
        }
        None => state.set_selected_id(-1),
    }
    plugins::refresh_transport(&state, &store);
}

/// Sorts rows into protocol groups, each under a heading row; collapsed groups keep only the heading.
fn grouped(rows: &mut [(&Profile, ConfigData)], collapsed: &HashSet<&str>) -> Vec<ConfigData> {
    let rank = |group: &str| GROUP_ORDER.iter().position(|g| *g == group).unwrap_or(GROUP_ORDER.len());
    rows.sort_by_key(|(profile, _)| rank(profile.group()));

    let mut out = Vec::new();
    for chunk in rows.chunk_by(|(a, _), (b, _)| a.group() == b.group()) {
        let group = chunk[0].0.group();
        let is_collapsed = collapsed.contains(group);
        out.push(ConfigData {
            id: -1,
            name: group.into(),
            protocol: chunk[0].1.protocol.clone(),
            header: true,
            count: chunk.len() as i32,
            collapsed: is_collapsed,
            ..Default::default()
        });
        if !is_collapsed {
            out.extend(chunk.iter().map(|(_, row)| row.clone()));
        }
    }
    out
}

fn source_label(source: Option<&store::StoredSubscription>) -> &str {
    source.map_or("Added manually", |s| s.name.as_str())
}

fn latency_display(latency: Option<Latency>) -> (String, i32) {
    match latency {
        None => (String::new(), 0),
        Some(Latency::Testing) => ("…".into(), 4),
        Some(Latency::Failed) => ("timeout".into(), 5),
        Some(Latency::Ms(0)) => ("<1 ms".into(), 1),
        Some(Latency::Ms(ms)) => (format!("{ms} ms"), if ms < 300 { 1 } else if ms < 800 { 2 } else { 3 }),
    }
}

fn select_config(ui: &AppWindow, ctx: &Ctx, id: u64) {
    {
        let mut store = ctx.store.lock().unwrap();
        // Also ignores group headings (id -1).
        if store.selected == Some(id) || store.entry(id).is_none() {
            return;
        }
        store.selected = Some(id);
        save(ui, ctx, &store);
    }
    refresh_configs(ui, ctx);

    // Switching configs while connected reconnects with the new one.
    if *ctx.state.lock().unwrap() == ConnectionState::Connected {
        connect(ui, ctx);
    }
}

fn remove_config(ui: &AppWindow, ctx: &Ctx, id: u64) {
    {
        let mut store = ctx.store.lock().unwrap();
        store.remove_entry(id);
        save(ui, ctx, &store);
    }
    ctx.latency.lock().unwrap().remove(&id);
    refresh_configs(ui, ctx);
}

fn filter_changed(ui: &AppWindow, ctx: &Ctx, index: i32) {
    let filter = match index {
        0 => Filter::All,
        1 => Filter::Manual,
        i => match ctx.store.lock().unwrap().subscriptions.get(i as usize - 2) {
            Some(s) => Filter::Subscription(s.id),
            None => Filter::All,
        },
    };
    *ctx.filter.lock().unwrap() = filter;
    refresh_configs(ui, ctx);
}

/// Adds imported profiles as manual configs and selects the first one if nothing is selected.
fn add_manual(ui: &AppWindow, ctx: &Ctx, profiles: Vec<Profile>) -> Vec<u64> {
    let ids = {
        let mut store = ctx.store.lock().unwrap();
        let ids = store.add_profiles(profiles);
        if store.selected.is_none() {
            store.selected = ids.first().copied();
        }
        save(ui, ctx, &store);
        ids
    };
    // Make sure the new configs are visible.
    let mut filter = ctx.filter.lock().unwrap();
    if matches!(*filter, Filter::Subscription(_)) {
        *filter = Filter::All;
    }
    drop(filter);
    refresh_configs(ui, ctx);
    ids
}

fn add_links(ui: &AppWindow, ctx: &Ctx, text: &str) {
    let state = ui.global::<AppState>();
    let parsed = import::parse_links(text);

    if parsed.profiles.is_empty() {
        let reason = parsed.skipped.first().cloned().unwrap_or_else(|| "No links found".into());
        state.set_links_dialog_error(reason.into());
        return;
    }

    let added = add_manual(ui, ctx, parsed.profiles).len();
    state.set_links_dialog_open(false);
    state.set_links_dialog_text(SharedString::new());
    state.set_links_dialog_error(SharedString::new());
    notify(ui, ctx, summary("Added", added, &parsed.skipped), !parsed.skipped.is_empty());
}

// TODO(android): the system file picker, through the Java side.
#[cfg(target_os = "android")]
fn import_files(ui: &AppWindow, ctx: &Ctx) {
    notify(ui, ctx, "Importing files isn't available on Android yet. Use Add to paste links.", true);
}

#[cfg(not(target_os = "android"))]
fn import_files(ui: &AppWindow, ctx: &Ctx) {
    let weak = ui.as_weak();
    let ctx = ctx.clone();
    // The native dialog blocks, so keep it off the UI thread.
    thread::spawn(move || {
        let Some(files) = rfd::FileDialog::new()
            .set_title("Import WireGuard or OpenVPN configs")
            .add_filter("WireGuard / OpenVPN", &["conf", "ovpn"])
            .add_filter("Share links / sing-box or Psiphon config / Psiphon server entry", &["txt", "json", "config", "dat"])
            .pick_files()
        else {
            return;
        };

        let mut profiles = Vec::new();
        let mut errors = Vec::new();
        for file in &files {
            match import_file(file) {
                Ok(found) => profiles.extend(found),
                Err(e) => errors.push(format!("{}: {e}", file.file_name().unwrap_or_default().to_string_lossy())),
            }
        }

        on_ui(&weak, &ctx, move |ui, ctx| {
            if profiles.is_empty() {
                let reason = errors.first().cloned().unwrap_or_else(|| "No configs found".into());
                notify(ui, ctx, format!("Nothing imported. {reason}"), true);
                return;
            }
            let ids = add_manual(ui, ctx, profiles);
            notify(ui, ctx, summary("Imported", ids.len(), &errors), !errors.is_empty());

            // Ask for an OpenVPN login now rather than at the first connect.
            let store = ctx.store.lock().unwrap();
            let needs_login = ids.into_iter().find(|id| store.entry(*id).is_some_and(|e| import::needs_credentials(&e.profile)));
            drop(store);
            if let Some(id) = needs_login {
                ask_credentials(ui, ctx, id, false, "");
            }
        });
    });
}

// Unused on Android until it gets a file picker.
#[cfg_attr(target_os = "android", allow(dead_code))]
fn import_file(path: &Path) -> Result<Vec<Profile>, ImportError> {
    let extension = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("ovpn") => Ok(vec![import::import_openvpn(path)?]),
        Some("conf") => {
            let name = path.file_stem().map_or("WireGuard".into(), |s| s.to_string_lossy().into_owned());
            Ok(vec![import::parse_wireguard_conf(&std::fs::read_to_string(path)?, &name)?])
        }
        _ => {
            let text = std::fs::read_to_string(path)?;
            if import::psiphon::looks_like_network(&text) {
                let name = path.file_stem().map_or("Psiphon network".into(), |s| s.to_string_lossy().into_owned());
                return Ok(vec![import::psiphon::parse_network_profile(&text, &name)?]);
            }
            let parsed = import::parse_links(&text);
            match parsed.profiles.is_empty() {
                true => Err(ImportError::Empty),
                false => Ok(parsed.profiles),
            }
        }
    }
}

/// "Added 12 configs" / "Added 12 configs, skipped 2 (ss: unsupported cipher `rc4-md5`)"
fn summary(verb: &str, count: usize, skipped: &[String]) -> String {
    let configs = if count == 1 { "config" } else { "configs" };
    match skipped {
        [] => format!("{verb} {count} {configs}"),
        [only] => format!("{verb} {count} {configs}, skipped 1 ({only})"),
        [first, rest @ ..] => format!("{verb} {count} {configs}, skipped {} ({first}, …)", rest.len() + 1),
    }
}

/// Opens the OpenVPN sign-in dialog for a config.
fn ask_credentials(ui: &AppWindow, ctx: &Ctx, id: u64, connect_after: bool, error: &str) {
    let store = ctx.store.lock().unwrap();
    let Some(Profile::OpenVpn { name, credentials, .. }) = store.entry(id).map(|e| &e.profile) else { return };

    let state = ui.global::<AppState>();
    state.set_creds_dialog_title(format!("Sign in to {name}").into());
    state.set_creds_username(credentials.as_ref().map_or("", |c| c.username.as_str()).into());
    state.set_creds_password(SharedString::new());
    state.set_creds_dialog_error(error.into());
    state.set_creds_dialog_action(if connect_after { "Connect" } else { "Save" }.into());
    state.set_creds_dialog_open(true);
    *ctx.credentials_for.lock().unwrap() = Some((id, connect_after));
}

fn submit_credentials(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let Some((id, connect_after)) = *ctx.credentials_for.lock().unwrap() else { return };
    let username = state.get_creds_username().trim().to_owned();
    if username.is_empty() {
        state.set_creds_dialog_error("Enter a username".into());
        return;
    }

    {
        let mut store = ctx.store.lock().unwrap();
        if let Some(Profile::OpenVpn { credentials, .. }) = store.entry_mut(id).map(|e| &mut e.profile) {
            *credentials = Some(Credentials { username, password: state.get_creds_password().to_string() });
        }
        save(ui, ctx, &store);
    }

    *ctx.credentials_for.lock().unwrap() = None;
    state.set_creds_dialog_open(false);
    state.set_creds_password(SharedString::new());
    if connect_after {
        connect(ui, ctx);
    }
}

// ───────────────────────────── Subscriptions ─────────────────────────────
fn add_subscription(ui: &AppWindow, ctx: &Ctx, url: &str) {
    let state = ui.global::<AppState>();
    let url = url.trim().to_owned();

    if !(url.starts_with("https://") || url.starts_with("http://")) {
        state.set_sub_dialog_error("Enter an http:// or https:// URL".into());
        return;
    }
    if ctx.store.lock().unwrap().subscriptions.iter().any(|s| s.url == url) {
        state.set_sub_dialog_error("This subscription is already added".into());
        return;
    }

    state.set_sub_dialog_busy(true);
    state.set_sub_dialog_error(SharedString::new());

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let result = import::fetch_subscription(&url);
        on_ui(&weak, &ctx, move |ui, ctx| {
            let state = ui.global::<AppState>();
            state.set_sub_dialog_busy(false);

            let content = match result {
                Ok(content) => content,
                Err(e) => {
                    state.set_sub_dialog_error(e.to_string().into());
                    return;
                }
            };

            let skipped = content.skipped.clone();
            let count = content.profiles.len();
            let name = {
                let mut store = ctx.store.lock().unwrap();
                let id = store.add_subscription(&url, content);
                let sub = store.subscriptions.iter().find(|s| s.id == id).expect("just added");
                let (name, first) = (sub.name.clone(), sub.entries.first().map(|e| e.id));
                if store.selected.is_none() {
                    store.selected = first;
                }
                save(ui, ctx, &store);
                name
            };

            state.set_sub_dialog_open(false);
            state.set_sub_dialog_url(SharedString::new());
            refresh_all(ui, ctx);
            notify(ui, ctx, summary(&format!("{name}:"), count, &skipped), !skipped.is_empty());
        });
    });
}

fn update_subscription(ui: &AppWindow, ctx: &Ctx, id: u64) {
    let Some(url) = ctx.store.lock().unwrap().subscriptions.iter().find(|s| s.id == id).map(|s| s.url.clone()) else {
        return;
    };
    if !ctx.updating.lock().unwrap().insert(id) {
        return; // already updating
    }
    refresh_subscriptions(ui, ctx);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let result = import::fetch_subscription(&url);
        on_ui(&weak, &ctx, move |ui, ctx| {
            ctx.updating.lock().unwrap().remove(&id);

            let message = {
                let mut store = ctx.store.lock().unwrap();
                let Some(name) = store.subscriptions.iter().find(|s| s.id == id).map(|s| s.name.clone()) else {
                    return; // removed while updating
                };
                match result {
                    Ok(content) => {
                        let (count, skipped) = (content.profiles.len(), content.skipped.clone());
                        store.update_subscription(id, content);
                        save(ui, ctx, &store);
                        Ok(summary(&format!("Updated {name}:"), count, &skipped))
                    }
                    Err(e) => Err(format!("Couldn't update {name}: {e}")),
                }
            };

            refresh_all(ui, ctx);
            match message {
                Ok(text) => notify(ui, ctx, text, false),
                Err(text) => notify(ui, ctx, text, true),
            }
        });
    });
}

fn remove_subscription(ui: &AppWindow, ctx: &Ctx, id: u64) {
    {
        let mut store = ctx.store.lock().unwrap();
        store.remove_subscription(id);
        save(ui, ctx, &store);
    }
    refresh_all(ui, ctx);
}

// ───────────────────────────── Latency ─────────────────────────────

/// TCP connect time to each visible server. UDP-based configs (Hysteria2, WireGuard) are skipped.
fn test_latency(ui: &AppWindow, ctx: &Ctx) {
    // With a TUN up, every TCP connect is answered locally by the tunnel: the numbers would be fake.
    // (The proxy modes don't capture our own sockets, so testing works while connected.)
    let tunnel_up = *ctx.state.lock().unwrap() != ConnectionState::Disconnected
        && ctx.store.lock().unwrap().settings.mode.uses_tunnel();
    if tunnel_up {
        notify(ui, ctx, "Disconnect first: latency can't be measured through the tunnel", false);
        return;
    }

    let targets: Vec<(u64, (String, u16))> = {
        let configs = ui.global::<AppState>().get_configs();
        let store = ctx.store.lock().unwrap();
        configs
            .iter()
            .filter_map(|row| {
                let id = row.id as u64;
                store.entry(id).and_then(|e| e.profile.tcp_endpoint()).map(|endpoint| (id, endpoint))
            })
            .collect()
    };

    if targets.is_empty() {
        notify(ui, ctx, "Nothing to test: UDP-based configs (Hysteria2, WireGuard) can't be TCP-pinged", false);
        return;
    }

    {
        let mut latency = ctx.latency.lock().unwrap();
        for (id, _) in &targets {
            latency.insert(*id, Latency::Testing);
        }
    }
    ui.global::<AppState>().set_testing(true);
    refresh_configs(ui, ctx);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let targets = Arc::new(targets);
        let next = Arc::new(AtomicUsize::new(0));

        let workers: Vec<_> = (0..LATENCY_WORKERS.min(targets.len()))
            .map(|_| {
                let (targets, next, weak, ctx) = (targets.clone(), next.clone(), weak.clone(), ctx.clone());
                thread::spawn(move || {
                    while let Some((id, (host, port))) = targets.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let result = measure(host, *port);
                        ctx.latency.lock().unwrap().insert(*id, result);
                        let id = *id;
                        on_ui(&weak, &ctx, move |ui, ctx| update_latency_row(ui, ctx, id));
                    }
                })
            })
            .collect();
        for worker in workers {
            let _ = worker.join();
        }

        on_ui(&weak, &ctx, |ui, _| ui.global::<AppState>().set_testing(false));
    });
}

fn measure(host: &str, port: u16) -> Latency {
    // Resolve first so DNS time isn't counted.
    let Some(address) = (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return Latency::Failed;
    };
    let start = Instant::now();
    match TcpStream::connect_timeout(&address, LATENCY_TIMEOUT) {
        Ok(_) => Latency::Ms(start.elapsed().as_millis()),
        Err(_) => Latency::Failed,
    }
}

/// Updates one row in place, so results stream in without rebuilding the list.
fn update_latency_row(ui: &AppWindow, ctx: &Ctx, id: u64) {
    let configs = ui.global::<AppState>().get_configs();
    let latency = ctx.latency.lock().unwrap().get(&id).copied();
    for i in 0..configs.row_count() {
        if let Some(mut row) = configs.row_data(i) && row.id as u64 == id {
            let (text, level) = latency_display(latency);
            row.latency = text.into();
            row.latency_level = level;
            configs.set_row_data(i, row);
            break;
        }
    }
}

// ───────────────────────────── Connection ─────────────────────────────

fn set_state(ui: &AppWindow, ctx: &Ctx, state: ConnectionState) {
    *ctx.state.lock().unwrap() = state;
    *ctx.connected_since.lock().unwrap() = (state == ConnectionState::Connected).then(Instant::now);
    let app = ui.global::<AppState>();
    app.set_connection(state);
    app.set_uptime("00:00:00".into());
    ctx.traffic.lock().unwrap().clear();
    app.set_traffic_known(false);
    if state != ConnectionState::Connected {
        app.set_proxy_address(SharedString::new());
    }
    if state != ConnectionState::Connecting {
        app.set_cancelling(false);
    }
    tray::update(state, app.get_cancelling());
}

fn toggle_connection(ui: &AppWindow, ctx: &Ctx) {
    let state = *ctx.state.lock().unwrap();
    match state {
        ConnectionState::Disconnected => connect(ui, ctx),
        ConnectionState::Connected => disconnect(ui, ctx),
        ConnectionState::Connecting => {
            ctx.cancel.store(true, Ordering::Relaxed);
            ui.global::<AppState>().set_cancelling(true);
            tray::update(state, true);
        }
        ConnectionState::Disconnecting => {}
    }
}

/// Starts the selected config, stopping whatever runs first (so it also reconnects).
fn connect(ui: &AppWindow, ctx: &Ctx) {
    let (id, profile, transport, settings) = {
        let store = ctx.store.lock().unwrap();
        match store.selected.and_then(|id| store.entry(id)) {
            Some(entry) => (entry.id, entry.profile.clone(), entry.transport.clone(), store.settings.clone()),
            None => {
                drop(store);
                notify(ui, ctx, "Select a config first", false);
                ui.global::<AppState>().set_current_tab(1);
                return;
            }
        }
    };

    if import::needs_credentials(&profile) {
        ask_credentials(ui, ctx, id, true, "");
        return;
    }
    // With the Xray core, configs Xray can run go to Xray; with a core plugin, the ones it can run go there.
    let profile = xray::effective(&profile, &settings).into_owned();
    let kind = engine::kind_for(&profile, &settings);

    // Android ships sing-box and OpenVPN only.
    #[cfg(target_os = "android")]
    if !matches!(kind, engine::EngineKind::SingBox | engine::EngineKind::OpenVpn) {
        ui.global::<AppState>().set_error("This config needs an engine the Android build doesn't have.".into());
        return;
    }

    ctx.cancel.store(false, Ordering::Relaxed);
    ui.global::<AppState>().set_error(SharedString::new());
    set_state(ui, ctx, ConnectionState::Connecting);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let previous = ctx.engine.lock().unwrap().take();
        if let Some(mut previous) = previous {
            let _ = previous.stop();
        }

        let result = start_engine(kind, &profile, transport, &settings, &ctx.cancel);
        let result = result.map(|engine| *ctx.engine.lock().unwrap() = Some(engine));
        let proxy_address = match settings.serves_proxy() && kind.runs_singbox() {
            true => format!("{PROXY_LISTEN}:{}", settings.proxy_port),
            false => String::new(),
        };

        on_ui(&weak, &ctx, move |ui, ctx| match result {
            Ok(()) => {
                set_state(ui, ctx, ConnectionState::Connected);
                ui.global::<AppState>().set_proxy_address(proxy_address.into());
            }
            Err(reason) if reason == openvpn::AUTH_FAILED => {
                set_state(ui, ctx, ConnectionState::Disconnected);
                ask_credentials(ui, ctx, id, true, openvpn::AUTH_FAILED);
            }
            Err(reason) => {
                set_state(ui, ctx, ConnectionState::Disconnected);
                if reason.contains("Settings → Engines") {
                    ui.global::<AppState>().set_current_tab(SETTINGS_TAB);
                }
                if reason != CANCELLED {
                    ui.global::<AppState>().set_error(reason.into());
                }
            }
        });
    });
}

/// Starts an engine and waits until it is up, has failed, or the user cancelled.
fn start_engine(
    kind: engine::EngineKind,
    profile: &Profile,
    transport: Option<TransportUse>,
    settings: &Settings,
    cancel: &AtomicBool,
) -> Result<Box<dyn Engine + Send>, String> {
    let mut engine = engine::engine_for(kind);
    if let Some(transport) = transport {
        engine = Box::new(engine::plugin::Transported::new(engine, transport));
    }
    engine.start(profile, settings).map_err(|e| explain(e.to_string()))?;

    // The grace period and timeout start once the admin password was accepted.
    let started = Instant::now();
    let mut authorized_at = None;
    loop {
        // A bad config or missing privileges make the engine exit within the first second.
        if let Status::Failed(reason) = engine.status() {
            return Err(explain(reason));
        }
        if cancel.load(Ordering::Relaxed) {
            let _ = engine.stop();
            return Err(CANCELLED.into());
        }
        if authorized_at.is_none() && engine.authorized() {
            authorized_at = Some(Instant::now());
        }
        let timed_out = match authorized_at {
            Some(at) if at.elapsed() >= STARTUP_GRACE && engine.ready() => return Ok(engine),
            Some(at) => at.elapsed() >= CONNECT_TIMEOUT,
            None => started.elapsed() >= PASSWORD_TIMEOUT,
        };
        if timed_out {
            let _ = engine.stop();
            return Err("Timed out while connecting".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Replaces errors people can fix themselves with what to do (the details stay in the engine log).
fn explain(reason: String) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("operation not permitted") || lower.contains("permission denied") || lower.contains("access is denied") {
        "No permission to create the tunnel: use a proxy mode (no rights needed), or check the engine log.".into()
    } else if reason == process::ADMIN_REFUSED {
        "Tunnel mode needs the admin password: enter it when asked, or use a proxy mode.".into()
    } else if lower.contains("`pkexec") && lower.contains("not found") {
        "Tunnel mode asks for the admin password through pkexec (polkit), which isn't installed.".into()
    } else if lower.contains("`sing-box") && lower.contains("not found") {
        "sing-box isn't installed yet: download it in Settings → Engines.".into()
    } else if lower.contains(&format!("`{}", xray::BINARY)) && lower.contains("not found") {
        "Xray isn't installed yet: download it in Settings → Engines.".into()
    } else if lower.contains(&format!("`{}", psiphon::BINARY)) && lower.contains("not found") {
        "Psiphon isn't installed yet: download it in Settings → Engines.".into()
    } else if lower.contains("`openvpn") && lower.contains("not found") {
        "OpenVPN isn't installed: see Settings → Engines.".into()
    } else if lower.contains("rule-set") {
        "Couldn't download the routing rule sets: check the server, or turn off geo rules in Settings → Routing.".into()
    } else if lower.contains("address already in use") || lower.contains("only one usage of each socket address") {
        "The proxy port is already in use: pick another one in Settings.".into()
    } else {
        reason
    }
}

fn disconnect(ui: &AppWindow, ctx: &Ctx) {
    set_state(ui, ctx, ConnectionState::Disconnecting);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let engine = ctx.engine.lock().unwrap().take();
        if let Some(mut engine) = engine {
            let _ = engine.stop();
        }
        on_ui(&weak, &ctx, |ui, ctx| set_state(ui, ctx, ConnectionState::Disconnected));
    });
}

/// Every second: notice an engine that died, and update the uptime.
fn monitor_tick(ui: &AppWindow, ctx: &Ctx) {
    if *ctx.state.lock().unwrap() != ConnectionState::Connected {
        return;
    }

    // try_lock: a disconnect thread may hold the engine while it stops; don't block the UI.
    let (failure, traffic) = match ctx.engine.try_lock() {
        Ok(mut engine) => match engine.as_mut().map(|e| (e.status(), e.traffic())) {
            Some((Status::Failed(reason), _)) => {
                engine.take();
                (Some(reason), None)
            }
            Some((_, traffic)) => (None, traffic),
            None => (None, None),
        },
        Err(_) => (None, None),
    };

    if let Some(reason) = failure {
        set_state(ui, ctx, ConnectionState::Disconnected);
        ui.global::<AppState>().set_error(explain(reason).into());
        return;
    }

    if let Some(since) = *ctx.connected_since.lock().unwrap() {
        let secs = since.elapsed().as_secs();
        let uptime = format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
        ui.global::<AppState>().set_uptime(uptime.into());
    }
    if let Some(traffic) = traffic {
        show_traffic(ui, ctx, traffic);
    }
}

/// Readings the speeds average over: engines refresh their counters about once a second, out of
/// step with this tick, so a single interval would jump between 0 and double.
const TRAFFIC_SAMPLES: usize = 3;

fn show_traffic(ui: &AppWindow, ctx: &Ctx, traffic: Traffic) {
    let mut samples = ctx.traffic.lock().unwrap();
    samples.push_back((Instant::now(), traffic));
    if samples.len() > TRAFFIC_SAMPLES {
        samples.pop_front();
    }
    let (first_at, first) = samples[0];
    let seconds = first_at.elapsed().as_secs_f64();
    let speed = |now: u64, then: u64| match seconds > 0.0 {
        true => format!("{}/s", format_bytes((now.saturating_sub(then) as f64 / seconds) as u64)),
        false => "0 B/s".into(),
    };

    let state = ui.global::<AppState>();
    state.set_upload_speed(speed(traffic.up, first.up).into());
    state.set_download_speed(speed(traffic.down, first.down).into());
    state.set_upload_total(format_bytes(traffic.up).into());
    state.set_download_total(format_bytes(traffic.down).into());
    state.set_traffic_known(true);
}

// ───────────────────────────── Settings ─────────────────────────────

fn load_settings(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let settings = ctx.store.lock().unwrap().settings.clone();
    state.set_bundled_engines(cfg!(target_os = "android"));

    let level = LOG_LEVELS.iter().position(|l| *l == settings.log_level).unwrap_or(1);
    state.set_log_level(level as i32);
    state.set_dns_remote(settings.dns_remote.into());
    state.set_dns_direct(settings.dns_direct.into());
    state.set_bypass_lan(settings.bypass_lan);
    state.set_mode(MODES.iter().position(|m| *m == settings.mode).unwrap_or(0) as i32);
    state.set_proxy_port(settings.proxy_port.to_string().into());
    state.set_tunnel_proxy(settings.tunnel_proxy);
    state.set_tls_fragment(settings.tls_fragment);
    state.set_udp_noise(settings.udp_noise);
    state.set_group_configs(settings.group_configs);
    state.set_close_to_tray(settings.close_to_tray);
    state.set_ui_scale(UI_SCALES.iter().position(|s| *s == settings.ui_scale).unwrap_or(0) as i32);
    plugins::refresh_cores(&state, &settings.core);
    state.set_route_default(ROUTE_DEFAULTS.iter().position(|t| *t == settings.routing.default).unwrap_or(0) as i32);
    if let Ok(dir) = paths::data_dir() {
        state.set_data_dir(dir.display().to_string().into());
    }
    state.set_app_version(env!("CARGO_PKG_VERSION").into());
}

fn settings_changed(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let defaults = Settings::default();
    let or_default = |value: SharedString, default: String| match value.trim() {
        "" => default,
        value => value.to_owned(),
    };

    let mut store = ctx.store.lock().unwrap();
    let settings = Settings {
        mode: MODES.get(state.get_mode() as usize).copied().unwrap_or_default(),
        log_level: LOG_LEVELS.get(state.get_log_level() as usize).copied().unwrap_or(LogLevel::Info),
        dns_remote: or_default(state.get_dns_remote(), defaults.dns_remote),
        dns_direct: or_default(state.get_dns_direct(), defaults.dns_direct),
        bypass_lan: state.get_bypass_lan(),
        // While a half-typed port is invalid, keep the last good one.
        proxy_port: state.get_proxy_port().trim().parse().ok().filter(|&p| p > 0).unwrap_or(store.settings.proxy_port),
        tunnel_proxy: state.get_tunnel_proxy(),
        tls_fragment: state.get_tls_fragment(),
        udp_noise: state.get_udp_noise(),
        group_configs: state.get_group_configs(),
        close_to_tray: state.get_close_to_tray(),
        ui_scale: UI_SCALES.get(state.get_ui_scale() as usize).copied().flatten(),
        core: plugins::core_choices(&store.settings.core).into_iter().nth(state.get_core() as usize).map(|(core, _)| core).unwrap_or_default(),
        // Rules and presets are edited through their own callbacks.
        routing: Routing {
            default: ROUTE_DEFAULTS.get(state.get_route_default() as usize).copied().unwrap_or_default(),
            ..store.settings.routing.clone()
        },
    };

    if store.settings != settings {
        store.settings = settings;
        save(ui, ctx, &store);
    }
}

// ───────────────────────────── Routing ─────────────────────────────

fn refresh_routing(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let store = ctx.store.lock().unwrap();
    let routing = &store.settings.routing;

    let presets: Vec<PresetData> = Preset::ALL
        .iter()
        .map(|p| PresetData { name: p.label().into(), hint: p.hint().into(), enabled: routing.presets.contains(p) })
        .collect();
    let rules: Vec<RuleData> = routing
        .rules
        .iter()
        .map(|r| RuleData {
            enabled: r.enabled,
            kind: r.kind.label().into(),
            summary: r.summary().into(),
            target: target_label(r.target).into(),
        })
        .collect();

    state.set_presets(ModelRc::new(VecModel::from(presets)));
    state.set_rules(ModelRc::new(VecModel::from(rules)));
}

fn target_label(target: Target) -> &'static str {
    match target {
        Target::Proxy => "Proxy",
        Target::Direct => "Direct",
        Target::Block => "Block",
    }
}

fn toggle_preset(ui: &AppWindow, ctx: &Ctx, index: usize) {
    let Some(&preset) = Preset::ALL.get(index) else { return };
    {
        let mut store = ctx.store.lock().unwrap();
        let presets = &mut store.settings.routing.presets;
        match presets.iter().position(|p| *p == preset) {
            Some(i) => { presets.remove(i); }
            None => presets.push(preset),
        }
        save(ui, ctx, &store);
    }
    refresh_routing(ui, ctx);
}

/// Changes the custom rules, saves and redraws the list.
fn change_rules(ui: &AppWindow, ctx: &Ctx, f: impl FnOnce(&mut Vec<Rule>)) {
    {
        let mut store = ctx.store.lock().unwrap();
        f(&mut store.settings.routing.rules);
        save(ui, ctx, &store);
    }
    refresh_routing(ui, ctx);
}

/// Opens the rule editor, filled in for an existing rule (`index` ≥ 0) or empty.
fn edit_rule(ui: &AppWindow, ctx: &Ctx, index: i32) {
    let state = ui.global::<AppState>();
    let store = ctx.store.lock().unwrap();
    let rule = usize::try_from(index).ok().and_then(|i| store.settings.routing.rules.get(i));

    let (index, kind, target, values) = match rule {
        Some(rule) => (index, rule.kind, rule.target, rule.values.join("\n")),
        None => (-1, RuleKind::Domain, Target::Direct, String::new()),
    };
    state.set_rule_dialog_index(index);
    state.set_rule_dialog_kind(RuleKind::ALL.iter().position(|k| *k == kind).unwrap_or(0) as i32);
    state.set_rule_dialog_target(TARGETS.iter().position(|t| *t == target).unwrap_or(0) as i32);
    state.set_rule_dialog_values(values.into());
    state.set_rule_dialog_error(SharedString::new());
    state.set_rule_dialog_open(true);
}

fn save_rule(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let kind = RuleKind::ALL.get(state.get_rule_dialog_kind() as usize).copied().unwrap_or(RuleKind::Domain);
    let target = TARGETS.get(state.get_rule_dialog_target() as usize).copied().unwrap_or_default();
    let values = match Rule::parse(kind, &state.get_rule_dialog_values()) {
        Ok(values) => values,
        Err(e) => return state.set_rule_dialog_error(e.into()),
    };

    let index = state.get_rule_dialog_index();
    change_rules(ui, ctx, |rules| match usize::try_from(index).ok().and_then(|i| rules.get_mut(i)) {
        Some(rule) => *rule = Rule { kind, values, target, ..rule.clone() },
        None => rules.push(Rule { enabled: true, kind, values, target }),
    });
    state.set_rule_dialog_open(false);
}

// ───────────────────────────── Engines ─────────────────────────────

/// Looks for sing-box / openvpn in the background (running them takes a moment) and shows the result.
fn refresh_engines(ui: &AppWindow, ctx: &Ctx) {
    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let singbox = install::installed("sing-box");
        let openvpn = install::installed("openvpn");
        let psiphon = install::installed(psiphon::BINARY);
        let xray = install::installed(xray::BINARY);

        let usable = singbox.as_ref().is_some_and(|info| version_at_least(&info.version, singbox::MIN_VERSION));
        let singbox_status = match &singbox {
            Some(info) if usable => format!("{} · {}", info.version, info.path.display()),
            Some(info) => format!("{} is too old (needs {} or newer): download {}", info.version, singbox::MIN_VERSION, install::SINGBOX_VERSION),
            None => "Not installed. Needed for everything except OpenVPN.".into(),
        };
        let openvpn_status = match &openvpn {
            Some(info) => format!("{} · {}", info.version, info.path.display()),
            None if cfg!(windows) => "Not installed. Get it from openvpn.net to use .ovpn configs.".into(),
            None => "Not installed. Install it with your package manager to use .ovpn configs.".into(),
        };
        let xray_installed = xray.is_some();
        let xray_status = match &xray {
            Some(info) => format!("{} · {}", info.version, info.path.display()),
            None => "Not installed. Needed for XHTTP, mKCP and VLESS encryption, and for the Xray core.".into(),
        };
        let psiphon_installed = psiphon.is_some();
        let psiphon_status = match &psiphon {
            Some(info) => format!("{} · {}", info.version, info.path.display()),
            None => "Not installed. Needed for Psiphon servers.".into(),
        };

        on_ui(&weak, &ctx, move |ui, _| {
            let state = ui.global::<AppState>();
            state.set_singbox_installed(usable);
            state.set_singbox_status(singbox_status.into());
            state.set_openvpn_status(openvpn_status.into());
            state.set_xray_installed(xray_installed);
            state.set_xray_status(xray_status.into());
            state.set_psiphon_installed(psiphon_installed);
            state.set_psiphon_status(psiphon_status.into());
        });
    });
}

/// Downloads an engine in the background, with its Download button showing progress.
fn install_engine(
    ui: &AppWindow,
    ctx: &Ctx,
    name: &'static str,
    set_busy: fn(&AppState, bool),
    install: fn(&Path) -> Result<install::EngineInfo, EngineError>,
) {
    let Ok(data_dir) = paths::data_dir() else { return };
    set_busy(&ui.global::<AppState>(), true);

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let result = install(&data_dir);
        on_ui(&weak, &ctx, move |ui, ctx| {
            set_busy(&ui.global::<AppState>(), false);
            match result {
                Ok(info) => notify(ui, ctx, format!("Installed {name} {}", info.version), false),
                Err(e) => notify(ui, ctx, e.to_string(), true),
            }
            refresh_engines(ui, ctx);
        });
    });
}

/// `"1.14.3" >= "1.12.0"`, comparing numerically part by part.
fn version_at_least(version: &str, minimum: &str) -> bool {
    let parts = |v: &str| -> Vec<u32> {
        v.split(['.', '-']).map_while(|part| part.parse().ok()).collect()
    };
    parts(version) >= parts(minimum)
}

// ───────────────────────────── Helpers ─────────────────────────────

/// Opens a folder or URL with the desktop's default handler.
fn open_external(target: impl AsRef<std::ffi::OsStr>) -> std::io::Result<()> {
    let opener = if cfg!(windows) { "explorer" } else { "xdg-open" };
    Command::new(opener).arg(target).spawn().map(|_| ())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ => format!("{value:.1} {}", UNITS[unit]),
    }
}

fn format_ago(secs: u64) -> String {
    match secs {
        0..60 => "updated just now".into(),
        60..3600 => format!("updated {} min ago", secs / 60),
        3600..86_400 => format!("updated {} h ago", secs / 3600),
        _ => format!("updated {} d ago", secs / 86_400),
    }
}

#[cfg(test)]
mod screenshots;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_configs_by_protocol() {
        let profiles: Vec<Profile> = [
            "trojan://pw@a.example.com:443#T1",
            "vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443#V1",
            "trojan://pw@c.example.com:443#T2",
        ]
        .iter()
        .map(|link| import::parse_link(link).unwrap())
        .chain([import::psiphon::parse_server_entry(&import::psiphon::tests::sample_entry()).unwrap()])
        .collect();
        let row = |p: &Profile| ConfigData { name: p.name().into(), protocol: p.protocol().into(), ..Default::default() };
        let mut rows: Vec<_> = profiles.iter().map(|p| (p, row(p))).collect();

        let names = |rows: &[ConfigData]| rows.iter().map(|r| (r.header, r.name.to_string(), r.count)).collect::<Vec<_>>();
        let out = grouped(&mut rows, &HashSet::new());
        assert_eq!(names(&out), [
            (true, "VLESS".into(), 1), (false, "V1".into(), 0),
            (true, "Trojan".into(), 2), (false, "T1".into(), 0), (false, "T2".into(), 0),
            (true, "Psiphon".into(), 1), (false, "Psiphon 203.0.113.7 (DE)".into(), 0),
        ]);
        assert_eq!(out[2].protocol, "trojan");

        let out = grouped(&mut rows, &HashSet::from(["Psiphon"]));
        assert_eq!(out.last().map(|r| (r.header, r.collapsed)), Some((true, true)));
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn formats_sizes_and_ages() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10 * 1024 * 1024 * 1024), "10.0 GB");
        assert_eq!(format_ago(30), "updated just now");
        assert_eq!(format_ago(7200), "updated 2 h ago");
    }

    #[test]
    fn summaries() {
        assert_eq!(summary("Added", 1, &[]), "Added 1 config");
        assert_eq!(summary("Added", 3, &["ssr: unsupported".into()]), "Added 3 configs, skipped 1 (ssr: unsupported)");
        assert_eq!(summary("Added", 3, &["a".into(), "b".into()]), "Added 3 configs, skipped 2 (a, …)");
    }

    #[test]
    fn version_comparison() {
        assert!(version_at_least("1.14.3", "1.12.0"));
        assert!(version_at_least("1.12.0", "1.12.0"));
        assert!(version_at_least("1.13.0-beta.2", "1.12.0"));
        assert!(!version_at_least("1.11.9", "1.12.0"));
        assert!(!version_at_least("1.9.10", "1.12.0"));
    }

    #[test]
    fn permission_errors_get_a_hint() {
        assert!(explain("open tun: TUNSETIFF: operation not permitted".into()).starts_with("No permission"));
        assert!(explain("`sing-box` was not found next to the app or in PATH".into()).contains("Settings → Engines"));
        assert!(explain("listen tcp 127.0.0.1:2080: bind: address already in use".into()).contains("port"));
        assert_eq!(explain("bad config".into()), "bad config");
    }
}
