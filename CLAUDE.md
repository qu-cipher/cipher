# Cipher VPN Client — project overview

Desktop VPN client (Linux + Windows) written in Rust with a **Slint** UI. It doesn't implement
protocols itself: it imports configs, then drives external engines as child processes:
- **sing-box** (≥ 1.12, pinned/tested 1.14.3) for proxy protocols and WireGuard
- **xray** (Xray-core ≥ 26, pinned 26.10.21) for XHTTP/mKCP/VLESS-encryption links and the optional Xray core, chained behind sing-box
- **openvpn** binary for `.ovpn` files (Tunnel mode only)
- **psiphon-tunnel-core** (Psiphon ConsoleClient) for the user's own Psiphon servers (self-hosted psiphond server
  entries, or a private network's client JSON), chained behind sing-box. Psiphon's public network is NOT supported

Crate name `cipher_client`, edition 2024 (let-chains are used). README.md is the public overview: keep its
feature list, "Not supported" list and layout table in sync when those change.
**Detailed sing-box config reference: `docs/singbox-config.md`** (modes, generated JSON, DNS, TUN,
privileges). Read that before touching config generation instead of re-deriving it.

## Commands
```sh
cargo build / cargo run
cargo test                    # unit tests, fixture round-trips, generator assertions
cargo test -- --ignored       # also real `sing-box check` + `xray run -test` (XRAY_BINARY=~/Apps/v2rayN/bin/xray/xray), release download, screenshots
CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture   # headless UI frames (*.rgba 820x520)
CIPHER_UI=phone cargo run     # preview the phone (Android) layout on the desktop
android/build.sh [--debug]    # Android APK (arm64) → target/android/cipher-<ver>-arm64.apk
CIPHER_UI=phone CIPHER_SCREENSHOTS=/tmp/shots cargo test phone_screenshots -- --ignored   # phone frames (400x820)
CIPHER_UI=phone CIPHER_SCREENSHOTS=/tmp/shots cargo test phone_touch -- --ignored   # finger input as Android sends it
                              # (InternalEvent::Touch via the i-slint-core dev-dep, pinned =slint's version: bump both together)
```
**Releases:** `.github/workflows/release.yml`, on a `v*` tag (must equal the Cargo.toml version) or manual run.
It runs `cargo test --locked` and then a release build on ubuntu-22.04 + windows-latest (MSVC), plus an `android` job
(ubuntu-latest: sdkmanager installs platform 36 / build-tools 36.0.0 / NDK 27.3.13750724 / CMake 4.1.2, caches
target/android/cache, runs android/build.sh), and publishes a Release with tar.gz/zip/apk + .sha256. APK signing: secrets
ANDROID_KEYSTORE_BASE64 / _PASSWORD / ANDROID_KEY_ALIAS / ANDROID_KEY_PASSWORD → build.sh env; tag builds fail without them. There's no per-push CI (the user tests locally). It's the only place Windows gets built.
**Screenshot test safety:** it connects a dummy server in Tunnel mode. The user's `/usr/bin/sing-box` has
setcap and their own VPN is often up on tun0, so first `cp /usr/bin/sing-box target/debug/deps/` (a copy
has no caps; found first because it's beside the test exe), and remove it afterwards. Convert frames with
`magick -size 820x520 -depth 8 rgba:f.rgba f.png`. Emoji flags render blank there (no emoji font); that's expected.

Sheets animate a 0..1 `shown` value, not `y`, so closed ones don't slide into view while the window resizes.
UI theme: all colors are tokens in `ui/theme.slint` (navy base, cyan accent matching Fluent's, per-protocol
badge colors). Avoid gradients on rounded shapes: the software renderer drops the corner radius.
Use `Toggle` (buttons.slint) instead of the Fluent `Switch`.
`build.rs` compiles `ui/main-window.slint` (or `ui/phone-window.slint` on Android / `CIPHER_UI=phone`, setting
`cfg(phone_ui)`; both export the same `AppWindow`, so app.rs is shared) with style `fluent-dark` and, on Windows, embeds
`windows/app.manifest` (requireAdministrator) via `windows/app.rc`.

## Layout
```
src/
  lib.rs             mod decls + slint::include_modules!(); main() (desktop, also --elevated-helper) and android_main
                     (Android NativeActivity: sets paths::set_android_data_dir, slint::android::init, app::run)
  main.rs            desktop binary: calls cipher_client::main()
  app.rs   (~1100 lines) UI glue: callbacks, threads, list refresh, connect/disconnect, settings, engines
  app/tray.rs        Tray (ui/tray.slint, a SystemTrayIcon-rooted component exported from both windows; thread_local, not on
                     Android or in tests), update() from set_state, close(): quit, or with close_to_tray hide (tray host checked
                     via dbus-send NameHasOwner org.kde.StatusNotifierWatcher on Linux; none → minimize). Handles both our ✕ and WM close
  app/window.rs      desktop window size + place: `window_resized` (Slint `changed width/height`) remembers the normal
                     (not max/minimized) logical size; saved on exit as Store.window {width, height, maximized} and
                     restored before the first show. Position: session only (hide to tray → show puts it back, also
                     maximized); a new start is placed by the system. No-op on Android.
                     Wayland: Slint DESTROYS the window on hide and recreates it at the preferred size (820x520) unless
                     set_size was called, still caching maximized=true (so set_maximized(true) no-ops): show() sets the
                     size and toggles maximized false→true before showing. Never toggle maximized on a hidden window
                     elsewhere (winit's ShowWindow shows it on Windows). Wayland can't restore positions (KWin places it).
                     apply_min_size() sets the 400x520 minimum on the winit window (slint `unstable-winit-030`, hence
                     `slint = "~1.18.1"` on desktop) at startup, after a recreating show and a UI scale change: the
                     recreated window had none (min 20x20, shrinkable until the layout broke), and with a UI scale
                     Slint scales its own limit twice. Retries on a 50 ms timer until the winit window exists.
                     Verified on KDE Wayland via KWin scripts (frameGeometry/closeWindow/setMaximize, filtered by pid)
                     + the tray's dbusmenu Event over busctl (ids: 2 Show, 5 Quit)
  app/screenshots.rs headless Slint platform driving the real UI in tests (`routing_screenshots`: routing, anti-DPI, grouped
                     Configs list with a Psiphon entry; `config_list_screenshots`: edit dialog, sort by ping (local
                     open/closed ports), moving a group; `resize_screenshots`: 820x520 / 1100x700 / 1600x900, then
                     compact at 819x520 / 400x520 / 400x800, via Driver::resize; never connect: safe)
  profile.rs         Profile enum {Proxy{outbound}, WireGuard{endpoint}, OpenVpn{config: OpenVpnConfig, credentials}, Psiphon{name, source: PsiphonSource}, Xray{name, outbound: XrayOutbound}},
                     OpenVpnConfig {File(path) → "config_path", Inline(text) → "config"} (serde-flattened, old state.json loads),
                     PsiphonSource {ServerEntry(hex) → "server_entry", Network(map) → "network"} (serde-flattened),
                     ConnectionMode {Tunnel(default), SystemProxy, ProxyOnly}, Settings (dns, bypass_lan, proxy_port=2080, tunnel_proxy, routing,
                     core: xray::Core {SingBox(default), Xray, Plugin(id)}, group_configs=true,
                     tls_fragment, udp_noise: anti-DPI toggles, default off; ui_scale: Option<u16> percent, None = system; close_to_tray=true);
                     Profile::group() = group label in the Configs list ("VLESS", …, "Psiphon");
                     Profile::Custom{name, outbound: Value} = a core plugin's new protocol (raw sing-box outbound), group = its type
  routing.rs         Routing {default: Target, presets, rules}, Rule {enabled, kind, values, target}, RuleKind (Domain/Keyword/Ip/Port/App/Geosite/Geoip),
                     Preset (Iran/China/Russia direct, BlockAds), Rule::parse (normalizes input), effective_rules() (custom, then presets)
  store.rs           Store persisted as state.json (atomic write, 0600; corrupt → .bak): settings, manual entries,
                     subscriptions (with entries, usage, updated_at), selected id, window (last size), next_id;
                     Store::migrated: an old settings.psiphon.network (≤0.3) becomes a manual Psiphon config on load
  engine.rs          Engine trait (start/stop/status/ready), EngineKind, Status, EngineError, engine_for()
  engine/process.rs  child process → log file; SIGTERM then kill after 5s; stops on Drop; last log line = error msg;
                     spawn_elevated: Linux Tunnel mode via `pkexec /bin/sh` wrapper, stopped by closing its stdin pipe
  engine/paths.rs    data_dir(), bin_dir(), find_binary() (beside exe → <data>/bin → PATH; Android: lib<name>.so in the APK's
                     native lib dir, found via /proc/self/maps), write_private()
  engine/singbox.rs  SingBoxEngine: generate → write sing-box.json → `sing-box check` → `run`; Windows proxy reset
  engine/singbox/generate.rs   build_config(profile, settings, data_dir, direct_processes) → SingBoxConfig (tags: proxy, direct, tun-in, mixed-in)
  engine/singbox/generate/routing.rs  routing rules → route rules + remote geo rule sets (SagerNet .srs via proxy) + DNS rules
  engine/singbox/config/       serde model of sing-box config (inbound/, outbound/, endpoint, dns, route, shared/{tls,transport,dial,multiplex,hysteria}, tests.rs)
  engine/traffic.rs  Traffic {up, down} totals; Meter (sing-box Clash API on a free port + random secret, polled on a thread);
                     read_openvpn_status (openvpn --status <data>/openvpn-status.txt 1, TUN/TAP bytes). Engine::traffic() (wrappers delegate)
  engine/chain.rs    Chain: upstream process with a local SOCKS port + inner SingBoxEngine (socks outbound, process_name→direct),
                     started once `upstream_up`; shared by Xray and Psiphon
  engine/xray.rs     XrayEngine (xray.json → `xray run -test` → `xray run`; up = SOCKS port open), Core, effective() (core setting)
  engine/xray/config.rs   serde model of an Xray outbound (vless/vmess/trojan/shadowsocks + streamSettings, finalmask)
  engine/xray/convert.rs  sing-box Outbound → XrayOutbound for the Xray core (None = stays on sing-box)
  engine/psiphon.rs  PsiphonEngine: psiphon-tunnel-core (as user, JSON notices → psiphon.log) then, once a `Tunnels` notice
                     count ≥ 1, an inner SingBoxEngine with a socks outbound to it + process_name→direct rule;
                     client_config: ServerEntry → TargetServerEntry + DisableRemoteServerListFetcher; Network → as imported
  engine/plugin.rs   PluginEngine (Profile::Plugin: plugin serves SOCKS on a free port → Chain to sing-box; also core plugins:
                     runs_on_core()/engine::kind_for() pick it for Custom configs and, with Core::Plugin, what its format carries;
                     {outbound} = generate::proxy_outbound / xray::proxy_outbound JSON) and
                     Transported (wraps any engine: plugin first, then the config rewritten to 127.0.0.1:<port>; rewrite() keeps
                     tls.server_name / ws Host / Xray serverName+host on the ORIGINAL server). e2e tests (ignored) use sing-box as fake plugins
  engine/elevated.rs Elevated: one pkexec for several root processes: `cipher_client --elevated-helper` (main.rs) runs as root,
                     JSON lines over stdin/stdout (spawn/stop → exited), stdin EOF stops all. Only used when a plugin needs_root;
                     SingBoxEngine.elevated / Assist{elevated, direct_processes} let sing-box's TUN join it. Plain Tunnel mode is unchanged
  engine/openvpn.rs  OpenVpnEngine: --cd/--config, Inline configs → temp <data>/openvpn.ovpn (0600, removed on stop), temp auth file for auth-user-pass, ready = "Initialization Sequence Completed", AUTH_FAILED detection
  engine/openvpn/management.rs  OpenVPN's Android management protocol (doc/android.txt): Request::parse/apply (>NEED-OK IFCONFIG/
                     IFCONFIG6/ROUTE/ROUTE6/DNSSERVER/DNSDOMAIN → TunSpec; ROUTE "dev x" ignored; PERSIST_TUN_ACTION →
                     OPEN_BEFORE_CLOSE), send_with_fd (SCM_RIGHTS). Compiled + unit-tested everywhere, used on Android
  engine/openvpn/android.rs  Management: --management <data>/openvpn-management unix --management-hold; thread: connect, "hold
                     release", answer requests, OPENTUN → android::establish → fd back with the reply
  engine/vpn.rs      (Android) VpnEngine = engine_for(SingBox): proxy modes = plain sing-box; Tunnel = sing-box mixed inbound
                     (generate::EXTERNAL_TUN) + VpnService TUN (172.19.0.1/30, fdfe:dcba:9876::1/126, DNS 172.19.0.2, MTU 1500)
                     fed by tun2proxy (SOCKS5, ArgDns::Direct → sing-box hijack-dns) on its own tokio runtime
  android.rs         (Android) JNI to MainActivity: prepare/consent/check_consent (VPN dialog), establish(TunSpec) → fd (Java owns it),
                     revoked, stop. jni 0.22 (= Slint's), JavaVM::singleton(), activity from AndroidApp
  engine/install.rs  engine detection/versions; downloads pinned sing-box + Xray (XRAY_VERSION zip, `zip` crate) releases and pinned Psiphon binary
                     (psiphon-tunnel-core-binaries @ PSIPHON_COMMIT; SHA-256 verified) into <data>/bin
  plugin.rs          Manifest (plugin.json, deny_unknown_fields, validate(): GitHub repo, asset URLs under <repo>/releases/download/,
                     sha256, placeholders `{name}`/`{name:json}`, other braces literal), `files` (extra templates in {data_dir}),
                     fields (text/number/bool/select/lines), Installed/InstallRecord
                     (<data>/plugins/<id>/{plugin.json,install.json,cipher-plugin-<id>}), TransportUse, scheme registry (global, for
                     link.rs), OFFICIAL = include_str! of plugins/<id>.json (official = exact text match; the list shows them
                     with "Add", "Update" when the built-in one differs). `core: {format: sing-box|xray, protocols}` = core plugin
                     (engine kind; no fields/schemes; `{outbound}` placeholder); PROTOCOLS registry → protocol_owner().
                     Public dev guide: docs/plugins.md
  plugin/install.rs  review() / review_official(id) (fetch manifest: URL, GitHub repo → raw HEAD/plugin.json, or local file; GitHub API: public + license
                     spdx match; archived = warning), install() (download, sha256, extract zip/tar, swap folder), remove();
                     CIPHER_PLUGIN_DEV=1 = local folder binary, no checks ("Development")
  import.rs          ImportError, decode_base64 (all variants), re-exports
  import/link.rs + link/*.rs   share links: vless, vmess, trojan, ss, hysteria2/hy2, tuic, anytls, wireguard/wg (tests in link/tests.rs);
                               ovpn/openvpn (base64 .ovpn + #name) is parsed in import/openvpn.rs
  import/uri.rs      ShareLink URI parsing helpers
  import/subscription.rs  fetch (ureq, 20s), base64 or plain body, or sing-box JSON; `subscription-userinfo` → Usage; profile-title
  import/singbox_json.rs  sing-box JSON → profiles (skips direct/block/dns/selector/urltest)
  import/wireguard.rs     .conf → WireGuard endpoint
  import/openvpn.rs       .ovpn file / ovpn:// link → Profile::OpenVpn, needs_credentials()
  import/psiphon.rs       server entries (hex / psiphon://<hex>, also subscription lines) + client JSON configs → Profile::Psiphon
  import/xray.rs          links needing Xray (xhttp/splithttp/kcp/mkcp, VLESS encryption) → Profile::Xray; hooked in vless/vmess/trojan
ui/
  state.slint        AppState global: ALL Rust↔UI properties & callbacks (structs ConfigData, SubscriptionData, enum ConnectionState)
  main-window.slint  AppWindow (frameless, resizable, min 400x520; Slint's resize-border-width does the edges, the builtin
                     `maximized` property drives the title bar's maximize/restore button + double-click): TitleBar, then
                     ≥ 820px wide: ConnectPanel (300→400px) | LibraryPanel (content capped at 1040px, centered);
                     narrower: CompactLayout{desktop: true}. `compact` is set in `changed width` (a binding would loop
                     through the window's size constraints). Dialogs
  compact-layout.slint  CompactLayout: header, Connect (in a ScrollView, centered when it fits) / Library screens + bottom
                     bar. `desktop` = System proxy mode + Plugins tab, 128px power button, no header on the connect screen;
                     without it (phone): no System proxy, no Plugins tab (TabBar `values` maps the shorter tab lists onto
                     the same indices). Desktop-only settings hang on AppState.bundled-engines (Android), not on the layout
  phone-window.slint AppWindow for phones: CompactLayout inside the safe-area insets
  dialogs.slint      Dialogs: all Sheets (subscription / links / OpenVPN creds / rule / plugin dialogs) + toast, shared by both windows
  theme.slint        Theme colors (always dark)
  panels/            connect, library (tabs: subscriptions, configs, settings), configs, subscriptions, settings
  components/        buttons, config-item, group-header, rule-item, sub-item, tab-bar, title-bar, sheet
plugins/             official manifests (masterdnsvpn.json: engine, TOML config + client_resolvers.txt via `files`, `-domains` flag)
assets/              Geist.ttf, Mdi*.svg icons, tray.png / tray-connected.png (64px, from icon.svg; green = #3ddc97)
tests/fixtures/      sing-box JSON fixtures (vless_reality, wireguard, hysteria2) — must round-trip unchanged
```

## How it works
- **app.rs architecture**: `Shared` (Arc'd as `Ctx`) holds `Mutex<Store>`, `Mutex<Option<Box<dyn Engine>>>`,
  connection state, cancel flag, filter, latency map, updating set. Slow work runs on `thread::spawn`, results
  posted back with `on_ui(weak, ctx, f)` (`upgrade_in_event_loop`). Callbacks registered in `bind_callbacks`.
  A 1s `monitor_tick` timer detects dead engines and updates uptime.
- **Connect**: selected entry → (OpenVPN creds dialog if needed) → background thread stops old engine →
  `start_engine` polls status every 100ms: fail fast, 1.5s grace then `ready()`, 45s timeout, cancellable.
  `explain()` maps permission/not-found/port-in-use errors to user hints (pointing at Settings → Engines).
- **Routing** (Settings → ROUTING): default route combo goes through `settings_changed`; presets/rules have
  their own callbacks (`toggle_preset`, `edit_rule`/`save_rule` with the rule Sheet, `change_rules`) + `refresh_routing`.
  Proxy modes get a `resolve` action before the first IP rule. Details in docs/singbox-config.md §6.1.
- **Imports**: `import_files` by extension: `.ovpn`, `.conf` (WireGuard), else text of links. Links dialog → `parse_links`.
  Subscriptions update in place; selection follows the same server name.
- **Configs grouping**: `refresh_configs` → `grouped()` sorts rows by `group_order(settings)` (Settings.group_order,
  the user's, then `GROUP_ORDER`; unknown groups after, by name) and inserts heading rows (`ConfigData.header`, id -1,
  `count`, `collapsed`, `index`, `first`/`last`); `AppState.groups` = just the headings. Folded groups live in
  `Shared.collapsed` (session only, by name). The header arrows → `move_group` → `moved_group()` (moves among the
  shown groups); dragging a heading → `place-group(name, index)` → `placed_group()`. Drag UI (configs-panel.slint):
  a layer over the ListView shows only the headings while one is dragged (the ListView itself is never changed
  mid-drag: rebuilding it would destroy the TouchArea holding the grab), auto-scrolls near its edges. Mouse drags
  start at once (Fluent ScrollView has mouse-drag-pan off); touch needs a ~0.5s hold (GroupHeader's Timer), because
  Slint's Flickable steals vertical swipes > 8px within 500ms of the press. `Settings.sort_by_latency` (toolbar) sorts
  rows by `latency_rank` before grouping (stable); a latency test re-sorts once at the end, not per result.
- **Editing configs**: manual only (`Store::manual_mut`). `Entry.link` = the share link it was added from
  (`Subscription.links`, by index; `into_imported()` pairs them; subscription entries don't keep links). Edit dialog
  (`edit_config` / `save_config`): a changed link is re-parsed (exactly one config) and replaces the profile, then
  the name applies; reconnects if it was the connected config.
- **Anti-DPI** (Settings → ANTI-DPI): `tls_fragment` → sing-box `tls.fragment` on TLS-enabled TCP outbounds
  (`Outbound::tcp_tls_mut`), Xray `finalmask.tcp` fragment (`tlshello`) on non-kcp; `udp_noise` → Xray `finalmask.udp`
  noise on kcp only. Both shapes pass `xray run -test` 26.10.21 / `sing-box check` (also with Reality). Old
  `kcpSettings.header` still accepted by 26.10.21 (no `mkcp-legacy` migration needed yet).
- **UI scale** (desktop, Settings → WINDOW, shown when `AppState.desktop`): `run()` loads the Store before creating the window and sets `SLINT_SCALE_FACTOR` from
  `ui_scale` (unless already set; winit reads it only at window creation). `ui_scale_changed` applies a percentage live
  (`ScaleFactorChanged` + `set_size` to the same logical size); "System" needs a restart (system factor unknown then).
- **Pull to connect** (phone, `ConnectPanel.pull`): a downward drag anywhere on the connect screen (or the button)
  draws an arc around the button and grows it; at `pull-distance` (180px) it calls `AppState.haptic()` (Android:
  MainActivity.haptic → performHapticFeedback CONFIRM) and `toggle-connection`. Only when the screen doesn't scroll
  (a scrolling ScrollView takes vertical drags). `phone_screenshots` checks it with a counting toggle handler.
- **Traffic box** (connect panel, under the power button): `monitor_tick` reads `Engine::traffic()` (try_lock), keeps 3 samples
  in `Shared.traffic` (speeds average over them; counters update out of step with the tick), cleared in `set_state`.
- **Latency test**: TCP connect (3s, 16 workers) to `Profile::tcp_endpoint()`; UDP protocols skipped.
- **UI contract**: Rust owns data; UI only calls `AppState` callbacks. Adding a UI feature = property/callback in
  `state.slint` + handler in `app.rs` `bind_callbacks` (plugin UI handlers: `app/plugins.rs`).
- **Plugins** (tab index 2; Settings is 3 = `SETTINGS_TAB`): Entry.transport (per config, kept across subscription updates by
  name) → `start_engine` wraps the engine in `Transported`. Engine plugins → Profile::Plugin (group "Plugins"; links in claimed
  schemes via `plugin::scheme_owner` in link.rs). Root plugins need `record.root_allowed` (asked at install or "Allow admin").
  Tests: `paths::TEST_DATA_DIR` (thread-local) keeps plugin tests out of the real data dir.
- **Runtime files** (`~/.local/share/cipher_client`, Windows `%APPDATA%\cipher_client`): state.json,
  sing-box.json, sing-box.log, cache.db, openvpn.log, openvpn.ovpn + openvpn-auth.txt (temporary),
  openvpn-status.txt (traffic, removed on stop), xray.json, xray.log, psiphon.json, psiphon.log, psiphon/ (its datastore), bin/, plugins/<id>/, plugin-<id>.log.

## Android (in progress, see docs/android-plan.md)
- Same crate; `target_os = "android"` gates. Slint features are per target in Cargo.toml (desktop = Slint defaults,
  Android = `backend-android-activity-06`); `rfd` is desktop-only (Android import = TODO system picker).
- APK: `android/build.sh` uses SDK build-tools directly (aapt2 link → add lib/arm64-v8a/*.so → zipalign -P 16 → apksigner
  with ~/.android/debug.keystore). No Gradle: Google Maven (AGP) returns 404 from the user's network; GitHub + Maven Central work.
  `android/AndroidManifest.xml`: package io.github.qu_cipher.cipher (`qu-cipher` isn't a valid Java identifier),
  `.MainActivity` (extends NativeActivity, lib_name cipher_client) + `.CipherVpnService` (BIND_VPN_SERVICE), extractNativeLibs=true.
  Java in android/java/ (javac --release 17 → d8 → classes.dex): MainActivity.vpn* methods (called from Rust), CipherVpnService
  (establish(spec lines), excludes our own package so engines bypass the VPN, onRevoke). Engines ship as lib/arm64-v8a/lib<name>.so (sing-box pinned + sha256 in build.sh, from SagerNet's
  android-arm64 release). Icons: android/res/mipmap-*/ic_launcher.png rendered from assets/icon.svg.
- Rust .so: NDK r27 clang as CC/linker for `aarch64-linux-android` (API 26), `cargo rustc --lib --crate-type cdylib`.
- OpenVPN: android/openvpn.sh cross-builds 2.7.8 + static OpenSSL 3.5.9 (sha256-pinned GitHub tarballs) via OpenVPN's CMake
  (only CMake sets TARGET_ANDROID), empty pkg-config path, GIT_CEILING_DIRECTORIES; cached in target/android/cache.
- connect() refuses engines other than sing-box / OpenVPN on Android.
- Android: SystemProxy mode becomes Tunnel on load (store.rs), `AppState.bundled-engines` hides downloads / Xray / Core / Psiphon.
  Plugin code still compiles there but is unreachable (no Plugins tab).

## Key decisions / gotchas
- TUN uses `stack: gvisor` (the default mixed stack broke TCP behind UFW). `strict_route`, `auto_route` on.
- DNS: `remote` DoH via proxy (final) + `local` UDP direct used only as `route.default_domain_resolver` (required since 1.14).
  Never `type: local` on Linux (systemd-resolved loops into the TUN).
- Profile outbound's tag is always overwritten to `proxy`; a `direct` outbound is always appended.
- Only emit sing-box 1.12+ formats; no legacy fields. New fixtures must round-trip exactly.
- Linux tunnel privileges: one pkexec password dialog per Tunnel connect; the engine runs as root (no setcap,
  no polkit rule; the old Grant button was removed 2026-10-18). Windows: whole app runs elevated.
- Never connect to real VPN servers when testing; the user verifies connections. Test locally (unit tests, `sing-box check`).
- Git repo since 2026-10-18 (branch `master`, remote `origin` = github.com/qu-cipher/cipher; latest release v0.4.2, tagged 2026-10-28). Older manual backup: `/home/ali/Dev/_rust/cipher_vpn_client.backup-20261018-0059`.
- Code style: LF line endings (normalized), all config struct fields `pub`, fixed-value strings modeled as enums.

## Status & history (as of 2026-10-30)
Releases: v0.3.0 = Xray core + anti-DPI toggles. 0.3.1 (Psiphon back for users' own servers) was never tagged. v0.4.0 = plugin system.
v0.4.1 (tag pushed 2026-10-27) = core plugins + official MasterDnsVPN plugin, Android build (phone UI, Tunnel mode, OpenVPN),
traffic box, tray icon + close to tray, UI scale, settings layout fixes. First release with a signed APK: release key
`~/.android/cipher-release.jks` (alias `cipher`, password in `~/.android/cipher-release-password.txt`; never regenerate,
Android only installs updates signed with it), stored in the repo's ANDROID_* Actions secrets.
v0.4.2 (tag pushed 2026-10-28) = first round of real users' feedback (Windows users): resizable window (maximize,
compact layout below 820px, size remembered, minimum size kept), editing manual configs (name + link), sort by ping,
user-ordered protocol groups. 0.4.3 (committed 2026-10-30) = pull to connect on the phone (+ haptic tick), dragging
group headings to reorder them (grip + arrows kept). Haptic tick and touch drags not yet tried on a real phone.
Releasing = bump Cargo.toml, commit, then push a `v*` tag; pushing commits alone builds nothing.
Next: official sni-spoofing-rust plugin (docs/plugins-plan.md, private); addons ideas in docs/addons-plan.md (private).
Maybe later: built-in public VPN servers for general use (user's idea, not planned yet).
Built across earlier sessions: config schema rewrite (client-only, 1.12+) → engine layer → importers →
full UI + store → connection modes → OpenVPN credentials, TUIC/AnyTLS, sing-box JSON subscriptions,
in-app sing-box download → ovpn:// links → pkexec per Tunnel connect (replaced Grant). 113 tests passing (+15 ignored) at last count (2026-10-30); clippy mostly clean.

User-confirmed working: proxy modes, Tunnel mode (after the gvisor fix), UI scale (live and at startup), tray icon +
close to tray (KDE), sing-box + OpenVPN on the user's Android phone.
Pending / unverified:
- Traffic box (2026-10-27): sing-box counting checked by e2e tests (plain + chained behind a plugin). Not yet watched on a real
  connection; OpenVPN's status file (written by root in Tunnel mode) is untested; if unreadable the box shows "—".
  Counts include direct-routed traffic and DNS (sing-box's Clash API totals).
- Tray on Windows and on desktops without a StatusNotifierItem host (closing should minimize there): untested.
- Plugin system (2026-10-26, uncommitted at first): unit + e2e tests (sing-box as fake engine/transport plugins, root path via an
  in-process helper) pass; real `--elevated-helper` mode checked over stdin without pkexec. NOT yet verified: a real pkexec prompt
  with a root plugin (one prompt for plugin + TUN), real GitHub install of a published plugin, Windows.
- Official MasterDnsVPN plugin (2026-10-26, pinned release v2026.10.26.100415-5f83ee9): the real client (offline, in
  `unshare -rn`, resolvers on 127.0.0.1) accepts the rendered config/resolvers and exits on SIGTERM
  (`MASTERDNSVPN_BINARY=… cargo test masterdnsvpn_accepts -- --ignored`). Its SOCKS port opens only once a session exists
  (so `ready: port` = tunnel up); with no working resolver it retries forever (Cipher's start timeout ends it). Engine-plugin
  configs are editable (connect panel → Settings). A real connection to the user's server is for the user to verify.
  Next official plugin: sni-spoofing-rust (see docs/plugins-plan.md, private).
- Core plugins (2026-10-26, user's design: forks or new engines = engines, chained behind official sing-box, picked in
  Settings → Core; new protocols via sing-box JSON only, no link converter yet): unit tests + e2e with sing-box as a fake
  fork pass. No real fork tested yet. Xray JSON import (for xray-format protocols) not built.
- Xray (2026-10-26): link parsing, converter and 10 config shapes pass the real `xray run -test` (v2rayN's 26.9.9);
  chained sing-box config passes `sing-box check`. Real connections (XHTTP etc.) are for the user to verify.
- Anti-DPI (2026-10-26): configs validated by both engines; whether fragmenting/noise actually helps on real networks is unverified.
- Psiphon own servers (2026-10-26): re-enabled for self-hosted server entries + private-network JSON configs. Public network
  dropped (needs a config from the Psiphon team; the user isn't pursuing it). The real binary (pinned build) accepts the
  generated config: with a 203.0.113.x entry it dials OSSH only to that address. Entries must have `handshake` +
  `ssh-api-requests` capabilities (real `psiphond generate` output does). A real psiphond connection is for the user to verify.
- Split tunneling / routing rules (2026-10-25): generator + `sing-box check` pass, UI rendered headlessly. User must verify
  real routing: app rules in Tunnel mode (process lookup as root), geo presets (rule-set download via proxy), whitelist default.
- pkexec-per-connect (2026-10-18): user must confirm exactly 1 prompt per Tunnel connect, clean disconnect, OpenVPN tun0 creation.
  First OpenVPN test (ovpn:// link) got through TLS + PUSH_REPLY, then failed creating tun0 unprivileged; that's what this fixes.
- OpenVPN pushed DNS: now root, so OpenVPN 2.7's own DNS handling may apply it; unverified.
- Windows: builds and passes `cargo test` in CI (v0.2.0 release, MSVC), but has never been run on a real Windows machine.
  Local `cargo check --tests --target x86_64-pc-windows-gnu` passes now (2026-10-26).

Known unsupported (rejected on import with a clear reason): AmneziaWG, ShadowTLS links, Clash YAML subscriptions.
Xray 26 limits (checked with `xray run -test`): no `allowInsecure`, no plain VLESS/Trojan to public addresses, no h2/QUIC.
Modeled but unused: `selector`/`urltest` outbounds. `clash_api` is emitted only for the traffic meter (could also serve latency tests / server switching).

Environment: CachyOS (Arch), fish shell, UFW enabled, system sing-box at `/usr/bin/sing-box`; v2rayN is also installed
and caused unrelated sudo prompts. Headless screenshot test can hide system sing-box from PATH to test the download flow.
