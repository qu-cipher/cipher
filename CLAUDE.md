# Cipher VPN Client — project overview

Desktop VPN client (Linux + Windows) written in Rust with a **Slint** UI. It doesn't implement
protocols itself: it imports configs, then drives external engines as child processes:
- **sing-box** (≥ 1.12, pinned/tested 1.14.3) for proxy protocols and WireGuard
- **openvpn** binary for `.ovpn` files (Tunnel mode only)
- **psiphon-tunnel-core** (Psiphon ConsoleClient) for the built-in "Psiphon Tunnel" entry, chained behind sing-box

Crate name `cipher_client`, edition 2024 (let-chains are used). README.md is the public overview: keep its
feature list, "Not supported" list and layout table in sync when those change.
**Detailed sing-box config reference: `docs/singbox-config.md`** (modes, generated JSON, DNS, TUN,
privileges). Read that before touching config generation instead of re-deriving it.

## Commands
```sh
cargo build / cargo run
cargo test                    # unit tests, fixture round-trips, generator assertions
cargo test -- --ignored       # also real `sing-box check`, real release download, screenshots
CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture   # headless UI frames (*.rgba 820x520)
```
**Screenshot test safety:** it connects a dummy server in Tunnel mode. The user's `/usr/bin/sing-box` has
setcap and their own VPN is often up on tun0, so first `cp /usr/bin/sing-box target/debug/deps/` (a copy
has no caps; found first because it's beside the test exe), and remove it afterwards. Convert frames with
`magick -size 820x520 -depth 8 rgba:f.rgba f.png`. Emoji flags render blank there (no emoji font); that's expected.

UI theme: all colors are tokens in `ui/theme.slint` (navy base, cyan accent matching Fluent's, per-protocol
badge colors). Avoid gradients on rounded shapes: the software renderer drops the corner radius.
Use `Toggle` (buttons.slint) instead of the Fluent `Switch`.
`build.rs` compiles `ui/main-window.slint` with style `fluent-dark` and, on Windows, embeds
`windows/app.manifest` (requireAdministrator) via `windows/app.rc`.

## Layout
```
src/
  main.rs            mod decls + slint::include_modules!(); calls app::run()
  app.rs   (~1100 lines) UI glue: callbacks, threads, list refresh, connect/disconnect, settings, engines
  app/screenshots.rs headless Slint platform driving the real UI in tests (`routing_screenshots` never connects: safe)
  profile.rs         Profile enum {Proxy{outbound}, WireGuard{endpoint}, OpenVpn{config: OpenVpnConfig, credentials}, Psiphon{name}},
                     OpenVpnConfig {File(path) → "config_path", Inline(text) → "config"} (serde-flattened, old state.json loads),
                     ConnectionMode {Tunnel(default), SystemProxy, ProxyOnly}, Settings (dns, bypass_lan, proxy_port=2080, tunnel_proxy, routing,
                     psiphon: PsiphonSettings {network: imported JSON map, region})
  routing.rs         Routing {default: Target, presets, rules}, Rule {enabled, kind, values, target}, RuleKind (Domain/Keyword/Ip/Port/App/Geosite/Geoip),
                     Preset (Iran/China/Russia direct, BlockAds), Rule::parse (normalizes input), effective_rules() (custom, then presets)
  store.rs           Store persisted as state.json (atomic write, 0600; corrupt → .bak): settings, manual entries,
                     subscriptions (with entries, usage, updated_at), selected id, next_id;
                     built-in entries (Psiphon, id PSIPHON_ID=0) come first in all_entries(), not saved, not removable
  engine.rs          Engine trait (start/stop/status/ready), EngineKind, Status, EngineError, engine_for()
  engine/process.rs  child process → log file; SIGTERM then kill after 5s; stops on Drop; last log line = error msg;
                     spawn_elevated: Linux Tunnel mode via `pkexec /bin/sh` wrapper, stopped by closing its stdin pipe
  engine/paths.rs    data_dir(), bin_dir(), find_binary() (beside exe → <data>/bin → PATH), write_private()
  engine/singbox.rs  SingBoxEngine: generate → write sing-box.json → `sing-box check` → `run`; Windows proxy reset
  engine/singbox/generate.rs   build_config(profile, settings, data_dir, direct_processes) → SingBoxConfig (tags: proxy, direct, tun-in, mixed-in)
  engine/singbox/generate/routing.rs  routing rules → route rules + remote geo rule sets (SagerNet .srs via proxy) + DNS rules
  engine/singbox/config/       serde model of sing-box config (inbound/, outbound/, endpoint, dns, route, shared/{tls,transport,dial,multiplex,hysteria}, tests.rs)
  engine/psiphon.rs  PsiphonEngine: psiphon-tunnel-core (as user, JSON notices → psiphon.log) then, once a `Tunnels` notice
                     count ≥ 1, an inner SingBoxEngine with a socks outbound to it + process_name→direct rule; REGIONS
  engine/openvpn.rs  OpenVpnEngine: --cd/--config, Inline configs → temp <data>/openvpn.ovpn (0600, removed on stop), temp auth file for auth-user-pass, ready = "Initialization Sequence Completed", AUTH_FAILED detection
  engine/install.rs  engine detection/versions; downloads pinned sing-box release and pinned Psiphon binary
                     (psiphon-tunnel-core-binaries @ PSIPHON_COMMIT; SHA-256 verified) into <data>/bin
  import.rs          ImportError, decode_base64 (all variants), re-exports
  import/link.rs + link/*.rs   share links: vless, vmess, trojan, ss, hysteria2/hy2, tuic, anytls, wireguard/wg (tests in link/tests.rs);
                               ovpn/openvpn (base64 .ovpn + #name) is parsed in import/openvpn.rs
  import/uri.rs      ShareLink URI parsing helpers
  import/subscription.rs  fetch (ureq, 20s), base64 or plain body, or sing-box JSON; `subscription-userinfo` → Usage; profile-title
  import/singbox_json.rs  sing-box JSON → profiles (skips direct/block/dns/selector/urltest)
  import/wireguard.rs     .conf → WireGuard endpoint
  import/openvpn.rs       .ovpn file / ovpn:// link → Profile::OpenVpn, needs_credentials()
ui/
  state.slint        AppState global: ALL Rust↔UI properties & callbacks (structs ConfigData, SubscriptionData, enum ConnectionState)
  main-window.slint  AppWindow (820x520, frameless): TitleBar, ConnectPanel | LibraryPanel, Sheets (subscription / links / OpenVPN creds dialogs)
  theme.slint        Theme colors (always dark)
  panels/            connect, library (tabs: subscriptions, configs, settings), configs, subscriptions, settings
  components/        buttons, config-item, sub-item, tab-bar, title-bar, sheet
assets/              Geist.ttf, Mdi*.svg icons
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
- **Latency test**: TCP connect (3s, 16 workers) to `Profile::tcp_endpoint()`; UDP protocols skipped.
- **UI contract**: Rust owns data; UI only calls `AppState` callbacks. Adding a UI feature = property/callback in
  `state.slint` + handler in `app.rs` `bind_callbacks`.
- **Runtime files** (`~/.local/share/cipher_client`, Windows `%APPDATA%\cipher_client`): state.json,
  sing-box.json, sing-box.log, cache.db, openvpn.log, openvpn.ovpn + openvpn-auth.txt (temporary),
  psiphon.json, psiphon.log, psiphon/ (its datastore), bin/.

## Key decisions / gotchas
- TUN uses `stack: gvisor` (the default mixed stack broke TCP behind UFW). `strict_route`, `auto_route` on.
- DNS: `remote` DoH via proxy (final) + `local` UDP direct used only as `route.default_domain_resolver` (required since 1.14).
  Never `type: local` on Linux (systemd-resolved loops into the TUN).
- Profile outbound's tag is always overwritten to `proxy`; a `direct` outbound is always appended.
- Only emit sing-box 1.12+ formats; no legacy fields. New fixtures must round-trip exactly.
- Linux tunnel privileges: one pkexec password dialog per Tunnel connect; the engine runs as root (no setcap,
  no polkit rule; the old Grant button was removed 2026-10-18). Windows: whole app runs elevated.
- Never connect to real VPN servers when testing; the user verifies connections. Test locally (unit tests, `sing-box check`).
- Git repo since 2026-10-18 (branch `master`, no remote). Older manual backup: `/home/ali/Dev/_rust/cipher_vpn_client.backup-20261018-0059`.
- Code style: LF line endings (normalized), all config struct fields `pub`, fixed-value strings modeled as enums.

## Status & history (as of 2026-10-26)
Built across earlier sessions: config schema rewrite (client-only, 1.12+) → engine layer → importers →
full UI + store → connection modes → OpenVPN credentials, TUIC/AnyTLS, sing-box JSON subscriptions,
in-app sing-box download → ovpn:// links → pkexec per Tunnel connect (replaced Grant). 67 tests passing at last count (Psiphon added 2026-10-26); clippy mostly clean.

User-confirmed working: proxy modes, Tunnel mode (after the gvisor fix).
Pending / unverified:
- Psiphon (2026-10-26): unit tests + `sing-box check` of the chained config pass; the downloaded binary was never run
  here (sandbox refused executing it), so `-version` parsing ("Revision:" line) and the whole connect are unverified.
  No network config ships: the user imports one (Settings → Psiphon, or Configs → Import of a .json/.config with
  PropagationChannelId). User plans to ask Psiphon Inc. for their own IDs.
- Split tunneling / routing rules (2026-10-25): generator + `sing-box check` pass, UI rendered headlessly. User must verify
  real routing: app rules in Tunnel mode (process lookup as root), geo presets (rule-set download via proxy), whitelist default.
- pkexec-per-connect (2026-10-18): user must confirm exactly 1 prompt per Tunnel connect, clean disconnect, OpenVPN tun0 creation.
  First OpenVPN test (ovpn:// link) got through TLS + PUSH_REPLY, then failed creating tun0 unprivileged; that's what this fixes.
- OpenVPN pushed DNS: now root, so OpenVPN 2.7's own DNS handling may apply it; unverified.
- Windows build never compiled: `cargo check --target x86_64-pc-windows-gnu` fails in `ring` without MinGW
  (`sudo pacman -S mingw-w64-gcc`, user's call). Target is already added via rustup.

Known unsupported (rejected on import with a clear reason): Xray-only XHTTP/SplitHTTP, mKCP, VLESS
`encryption` (XHTTP is common for the user, so this matters), AmneziaWG, ShadowTLS links, Clash YAML subscriptions.
Modeled but unused: `selector`/`urltest` outbounds, `clash_api` (planned for latency tests / server switching).

Environment: CachyOS (Arch), fish shell, UFW enabled, system sing-box at `/usr/bin/sing-box`; v2rayN is also installed
and caused unrelated sudo prompts. Headless screenshot test can hide system sing-box from PATH to test the download flow.
