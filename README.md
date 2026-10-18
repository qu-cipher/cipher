# Cipher VPN Client

A small desktop VPN client for **Linux** and **Windows**, written in Rust with a [Slint](https://slint.dev) UI.

It doesn't implement any VPN protocol itself. It imports your configs, turns them into a config file
for an existing engine, and runs that engine as a child process:

- **[sing-box](https://sing-box.sagernet.org)** for proxy protocols (VLESS, VMess, Trojan, Shadowsocks,
  Hysteria2, TUIC, AnyTLS) and WireGuard
- **OpenVPN** for `.ovpn` files and `ovpn://` links

> **Status:** a personal project, early but usable. Tested on Linux (CachyOS) with real servers in
> Tunnel and proxy modes. The Windows build has never been compiled or run. OpenVPN has only been
> tested locally. It hasn't had a security review.

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
- TCP latency test, a per-subscription filter, an OpenVPN username/password prompt, and DNS without leaks
  (DNS-over-HTTPS through the tunnel).
- **Engine management:** downloads a pinned sing-box release and checks its SHA-256.

### Not supported

sing-box can't run these, so the app rejects them on import and says why:
- Xray-only features: XHTTP/SplitHTTP and mKCP transports, VLESS `encryption`
- AmneziaWG

The app doesn't handle these yet:
- ShadowTLS links
- Clash YAML subscriptions

## Requirements

- Rust (edition 2024, so a recent stable toolchain)
- **sing-box 1.12 or newer** (tested on 1.14.3). Install it yourself, put it next to the executable, or use
  *Settings → Engines → Download*.
- **openvpn**, only for `.ovpn` configs (from your package manager)

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
cargo test -- --ignored     # also: real `sing-box check` on generated configs, real release download
CIPHER_SCREENSHOTS=/tmp/shots cargo test screenshots -- --ignored --nocapture
                            # drives the real UI headlessly and saves a frame per step (raw RGBA, 820×520)
```

No test connects to a VPN server.

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
| `src/profile.rs` | `Profile` (Proxy / WireGuard / OpenVPN), `ConnectionMode`, `Settings` |
| `src/store.rs` | Saved state (`state.json`): configs, subscriptions, selection, settings |
| `src/import/` | Share-link parsers (one file per protocol in `link/`), WireGuard/OpenVPN files, subscriptions, sing-box JSON |
| `src/engine/` | `Engine` trait, child-process handling, binary lookup, sing-box download and permissions, OpenVPN engine |
| `src/engine/singbox/config/` | Typed serde model of the sing-box config (client-side subset, 1.12+ format only) |
| `src/engine/singbox/generate.rs` | Builds the sing-box config from a profile and settings |
| `ui/state.slint` | `AppState`: every property and callback shared between Rust and the UI |
| `ui/main-window.slint`, `ui/panels/`, `ui/components/` | The window, its panels and reusable widgets |
| `tests/fixtures/` | sing-box JSON that must survive deserialize → serialize unchanged |
| `docs/singbox-config.md` | **Detailed guide to the generated sing-box config** and why each part is there |
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
| `cache.db` | sing-box cache |
| `bin/` | sing-box downloaded by the app |

## License

MIT, see [LICENSE](LICENSE).
