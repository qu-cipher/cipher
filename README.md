# Cipher VPN Client

A small desktop VPN client for **Linux** and **Windows**, written in Rust with a [Slint](https://slint.dev) UI.

It doesn't implement any VPN protocol itself. It imports your configs, turns them into a config file
for an existing engine, and runs that engine as a child process:

- **[sing-box](https://sing-box.sagernet.org)** for proxy protocols (VLESS, VMess, Trojan, Shadowsocks,
  Hysteria2, TUIC, AnyTLS) and WireGuard
- **[Xray-core](https://github.com/XTLS/Xray-core)** for what sing-box can't run (XHTTP/SplitHTTP, mKCP,
  VLESS encryption), and optionally for all VLESS/VMess/Trojan/Shadowsocks configs; chained behind sing-box
- **OpenVPN** for `.ovpn` files and `ovpn://` links
- **[Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core)** (its ConsoleClient) for your own Psiphon
  servers, chained behind sing-box

> **Status:** a personal project, early but usable. Tested on Linux (CachyOS) with real servers in
> Tunnel and proxy modes. Windows builds and passes the tests in CI but hasn't been run on Windows yet.
> OpenVPN has only been tested locally. It hasn't had a security review.

## Features

- **Import** share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tuic://`,
  `anytls://`, `wireguard://`, `ovpn://` with the base64 `.ovpn` inline), WireGuard `.conf` files, OpenVPN `.ovpn` files, and lists of links in a text file.
- **Subscriptions:** base64 or plain link lists, or sing-box JSON. Shows traffic usage and expiry when the
  server sends them (`subscription-userinfo` header). Configs update in place, and your selection is kept.
- **Three connection modes:**

  | Mode | What it does | Admin rights |
  |---|---|---|
  | Tunnel | TUN device, captures all system traffic | Yes |
  | System proxy | Local SOCKS5/HTTP proxy, set as the OS proxy while connected | No |
  | Proxy only | Local SOCKS5/HTTP proxy on `127.0.0.1:2080`; apps opt in | No |

  OpenVPN works in Tunnel mode only.
- **Xray core:** links with XHTTP (or SplitHTTP), mKCP or VLESS encryption become Xray configs automatically.
  *Settings → Engines → Core* can also run every VLESS/VMess/Trojan/Shadowsocks config on Xray instead of
  sing-box, except the ones Xray can't run the same way (insecure TLS, h2/QUIC, multiplex, plain VLESS/Trojan).
  sing-box stays in front of Xray, so all three modes and the routing rules work the same.
- **Psiphon (your own servers):** add a self-hosted [psiphond](https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/psiphon/server)
  server by pasting the contents of the `server-entry.dat` that `psiphond generate` writes (bare hex, or a
  `psiphon://<hex>` link) into *Add*, or by importing the file. A Psiphon client JSON config for a private
  Psiphon network (`PropagationChannelId`, `SponsorId`, server lists) can be imported too. Each becomes a
  config in the *Psiphon* group. sing-box runs in front of Psiphon, so all three modes and the routing rules
  work. Psiphon's proxy only forwards TCP, so UDP apps fall back to TCP. Psiphon's public network isn't
  included: its config is only available from the Psiphon team.
- **Split tunneling and routing rules** (sing-box configs, all modes): send domains, keywords, IPs/CIDRs,
  ports, apps (process name or path), and geosite/geoip lists through the VPN, direct, or block them.
  Rules are checked top to bottom. One-click presets: Iran / China / Russia direct, Block ads. The default
  route can be Direct, so that only matching traffic uses the VPN. Domains routed direct also resolve
  through the direct DNS server.
- **Anti-DPI options** (*Settings → Anti-DPI*): **Fragment TLS hello** splits the TLS handshake into small,
  delayed pieces so filters can't read the server name (TCP configs on sing-box and Xray). **UDP noise**
  sends random packets before an mKCP connection (Xray).
- **Plugins** (*Plugins* tab): add **transports** that carry a config's traffic another way (DNS tunnels,
  SNI spoofing, …; picked per config under the selected config) and whole **VPN engines** with their own
  configs and link schemes. Plugins are separate open-source programs: Cipher only installs them from a public
  GitHub repository's releases, with a recognized license and SHA-256 checksums, and warns before adding one.
  Plugins that need admin rights must be allowed separately, and still share Tunnel mode's single password
  prompt. Writing one: [docs/plugins.md](docs/plugins.md).
  - **Core plugins**: a fork of sing-box or Xray, or a new engine that reads their outbound format, can run
    your ordinary configs (*Settings → Core*) and add protocols of its own (configs from sing-box JSON).
  - **Official plugins** are listed in the tab, ready to add:
    [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN), a DNS tunnel to your own MasterDnsVPN
    server (domain, encryption and your resolver list are set per config).
- **Configs grouped by protocol** (VLESS, Trojan, …, Psiphon, Plugins); groups fold, and the
  grouping toggles from the Configs toolbar.
- TCP latency test, a per-subscription filter, an OpenVPN username/password prompt, and DNS without leaks
  (DNS-over-HTTPS through the tunnel).
- **Engine management:** downloads pinned sing-box and Xray releases, and a pinned Psiphon ConsoleClient
  build (Linux x86_64, Windows), and checks their SHA-256.

### Not supported

Neither engine runs these, so the app rejects them on import and says why:
- AmneziaWG
- Xray-only links with `allowInsecure` lose that flag (Xray removed it), and plain VLESS/Trojan without TLS
  to a public address is refused by Xray

The app doesn't handle these yet:
- ShadowTLS links
- Clash YAML subscriptions

## Requirements

- Rust (edition 2024, so a recent stable toolchain)
- **sing-box 1.12 or newer** (tested on 1.14.3). Install it yourself, put it next to the executable, or use
  *Settings → Engines → Download*.
- **openvpn**, only for `.ovpn` configs (from your package manager)
- **Xray**, only for Xray configs or the Xray core (tested with 26.9.9 and 26.10.21; *Settings → Engines → Download*
  installs 26.10.21)
- **psiphon-tunnel-core**, only for Psiphon servers (*Settings → Engines → Download*)

The app looks for engines next to its own executable first, then in `<data dir>/bin`, then in `PATH`.

## Build and run

```sh
cargo run              # debug
cargo build --release  # optimized binary: target/release/cipher_client
```

### Tunnel mode permissions

- **Linux:** each Tunnel connect asks for the admin password once (polkit's `pkexec` dialog). The engine
  runs as root for that connection only, and the app stops it on disconnect, on quit, or if the app crashes.
  Nothing is installed or changed on the system.
- **Windows:** the executable asks for administrator rights at launch (UAC). For `cargo run`, use an
  elevated terminal.

The proxy modes need no special rights.

## Tests

```sh
cargo test                  # unit tests, config round-trips, generator checks
cargo test -- --ignored     # also: real `sing-box check` / `xray run -test` on generated configs, real release download
                            # (XRAY_BINARY=/path/to/xray if xray isn't in PATH or <data>/bin)
CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture
                            # drives the real UI headlessly and saves a frame per step (raw RGBA, 820×520)
CIPHER_SCREENSHOTS=/tmp/shots cargo test routing_screenshots -- --ignored
                            # Settings (engines, core, routing) and the Configs list; never connects
```

No test connects to a VPN server.

## Releases

GitHub Actions builds the binaries (`.github/workflows/release.yml`). To publish a release:

```sh
# bump `version` in Cargo.toml first, and commit it
git tag v0.2.0
git push origin v0.2.0
```

The workflow runs `cargo test` and a release build on Linux (Ubuntu 22.04, x86_64) and Windows (x86_64).
It then publishes a GitHub Release with `cipher_client-linux-x86_64.tar.gz`, `cipher_client-windows-x86_64.zip`
and their SHA-256 files. If one OS fails its tests, the release goes out without that OS's binary. It
refuses a tag that doesn't match the Cargo.toml version.

To try a build without releasing: *Actions → Release → Run workflow*. The archives are kept as workflow
artifacts. Engines (sing-box, Psiphon, OpenVPN) aren't bundled: the app downloads or finds them.

## How it works

```
 share link / .conf / .ovpn / subscription
            │  src/import/
            ▼
        Profile  ──────────────►  state.json        (src/profile.rs, src/store.rs)
            │
            │  Connect (src/app.rs, background thread)
            ▼
   ┌────────────────────┬────────────────────┐
   │ SingBoxEngine      │ OpenVpnEngine      │     both implement trait Engine (src/engine.rs)
   │ generate config    │ openvpn --config … │
   │ sing-box check     │ (+ temp auth file) │
   │ sing-box run       │                    │
   └────────────────────┴────────────────────┘
            │  child process, output → log file, stopped with SIGTERM (src/engine/process.rs)
            ▼
       TUN device or local proxy
```

### Project layout

| Path | What's there |
|---|---|
| `src/main.rs` | Entry point. Calls `app::run()` |
| `src/app.rs` | Glue between the UI and everything else: callbacks, background threads, connecting, latency tests |
| `src/app/screenshots.rs` | Headless Slint platform for the UI test |
| `src/profile.rs` | `Profile` (Proxy / WireGuard / OpenVPN / Psiphon / Xray / Plugin), `ConnectionMode`, `Settings` |
| `src/routing.rs` | Routing rules, presets and the default route; input parsing and normalization |
| `src/store.rs` | Saved state (`state.json`): configs, subscriptions, selection, settings |
| `src/import/` | Share-link parsers (one file per protocol in `link/`), WireGuard/OpenVPN files, Psiphon server entries and configs, subscriptions, sing-box JSON |
| `src/engine/` | `Engine` trait, child-process handling, binary lookup, engine downloads and permissions, OpenVPN engine, Xray (`xray.rs`, `xray/`) and Psiphon engines chained behind sing-box (`chain.rs`), plugin engines and transports (`plugin.rs`), the admin helper for root plugins (`elevated.rs`) |
| `src/plugin.rs`, `src/plugin/` | Plugin manifests (validation, placeholders), installed plugins, and installing them (GitHub checks, download, SHA-256) |
| `plugins/` | Official plugin manifests, built into the app and published here (e.g. `masterdnsvpn.json`) |
| `src/engine/singbox/config/` | Typed serde model of the sing-box config (client-side subset, 1.12+ format only) |
| `src/engine/singbox/generate.rs` | Builds the sing-box config from a profile and settings (routing rules in `generate/routing.rs`) |
| `ui/state.slint` | `AppState`: every property and callback shared between Rust and the UI |
| `ui/main-window.slint`, `ui/panels/`, `ui/components/` | The window, its panels and reusable widgets |
| `tests/fixtures/` | sing-box JSON that must survive deserialize → serialize unchanged |
| `docs/singbox-config.md` | **Detailed guide to the generated sing-box config** and why each part is there |
| `docs/plugins.md` | **Plugin developer guide**: the manifest, what a plugin must do, root plugins, testing and publishing |
| `windows/` | Manifest that asks for admin rights, embedded by `build.rs` |

### Things worth reading if you're here to learn

- **Wrapping an external engine safely:** `src/engine/process.rs`. It sends SIGTERM so the engine can
  clean up routes, kills it after a timeout, stops it on `Drop` so closing the app never leaves a tunnel up,
  and turns the last log line into an error message.
- **Modeling a big JSON format with serde:** `src/engine/singbox/config/`. It uses tagged enums
  (`#[serde(tag = "type")]`) and `#[serde(flatten)]` for shared dial fields, and the round-trip fixtures
  catch drift.
- **A minimal working sing-box client config,** and the pitfalls behind each choice: the gvisor TUN stack
  behind a firewall, a DNS resolver for the proxy's own domain, avoiding DNS loops through systemd-resolved.
  See `docs/singbox-config.md`.
- **Slint with background work:** `src/app.rs`. Shared state sits behind `Arc<Mutex<…>>`, worker threads post
  results back with `upgrade_in_event_loop`, and Rust owns all data while the `.slint` files only call callbacks.
- **Testing a GUI without a display:** `src/app/screenshots.rs`.
- **Parsing messy real-world share links:** `src/import/link/`. Covers base64 variants, three Shadowsocks
  formats and Hysteria2 port ranges.

## Runtime files

Linux `~/.local/share/cipher_client/`, Windows `%APPDATA%\cipher_client\`:

| File | Contents |
|---|---|
| `state.json` | Your configs, subscriptions and settings. Holds credentials, so it's readable only by you |
| `sing-box.json` / `sing-box.log` | The last generated config and engine log |
| `openvpn.log` | OpenVPN log |
| `openvpn.ovpn` | An `ovpn://` config, written while connected and deleted on disconnect |
| `cache.db` | sing-box cache, including downloaded geo rule sets |
| `psiphon.json` / `psiphon.log` / `psiphon/` | Generated Psiphon client config, its notices (JSON lines), and its data store |
| `xray.json` / `xray.log` | The last generated Xray config and its log |
| `bin/` | sing-box, Xray and Psiphon downloaded by the app |
| `plugins/<id>/` | An installed plugin: its `plugin.json`, `install.json` (source, checksum, admin rights allowed) and program; `data/` is the plugin's own folder |
| `plugin-<id>.log` | A plugin's output |

## License

MIT, see [LICENSE](LICENSE).
