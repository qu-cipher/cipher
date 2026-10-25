# Sing-box Configuration — Developer Guide

Reference for the sing-box config generator in `cipher_client`.
Based on the official docs (https://sing-box.sagernet.org/configuration/).

**Supported versions:** sing-box **1.12.0+** (`engine::singbox::MIN_VERSION`). Verified with `sing-box check` on **1.14.3**.
We only emit the 1.12+ formats: typed DNS servers, `domain_resolver`, `endpoints`, rule actions. No legacy fields.

**Scope:** a *client* with one proxy outbound or one WireGuard endpoint, in one of three connection modes (`Settings.mode`):

| Mode | Inbounds | Admin rights | Notes |
|---|---|---|---|
| **Tunnel** (default) | `tun` (+ `mixed` if `tunnel_proxy`) | yes | Captures all system traffic |
| **System proxy** | `mixed` with `set_system_proxy: true` | no | sing-box sets the OS proxy and restores it on a clean exit. On Windows the engine is killed instead, so `SingBoxEngine::stop` resets `ProxyEnable` itself |
| **Proxy only** | `mixed` | no | SOCKS5/HTTP on `127.0.0.1:<proxy_port>`; apps opt in |

OpenVPN is not sing-box — it runs as its own process (`engine::openvpn`) and only supports Tunnel mode (`EngineError::TunnelOnly`).

## 0. Where things live

| Piece | Path |
|---|---|
| Profile the user picks (`Proxy` / `WireGuard` / `OpenVpn`) + `Settings` | `src/profile.rs` |
| `Engine` trait, `EngineError`, `Status` | `src/engine.rs` |
| Child process (log file, SIGTERM → kill, stop on drop) | `src/engine/process.rs` |
| Data dir + binary lookup (next to exe, then `<data>/bin`, then `PATH`) | `src/engine/paths.rs` |
| sing-box download (pinned, SHA-256 checked) | `src/engine/install.rs` |
| Running engines, elevated start through pkexec (Linux Tunnel mode) | `src/engine/process.rs` |
| sing-box engine (`check` then `run`) | `src/engine/singbox.rs` |
| Config generator | `src/engine/singbox/generate.rs` |
| Serde model of the config | `src/engine/singbox/config/` |
| Share links / files / subscriptions → `Profile` | `src/import/` |
| Round-trip fixtures | `tests/fixtures/*.json` |

Runtime files (Linux `~/.local/share/cipher_client`, Windows `%APPDATA%\cipher_client`):
`state.json` (saved configs, subscriptions, settings), `sing-box.json`, `sing-box.log`, `cache.db`, `openvpn.log`, `openvpn-auth.txt` (only while connected), `bin/` (downloaded sing-box).

## 1. Top-level structure

```json
{
  "$schema": "https://sing-box.sagernet.org/schema.json",
  "log": {},
  "dns": {},
  "inbounds": [],
  "outbounds": [],
  "endpoints": [],
  "route": {},
  "experimental": {}
}
```

A config is **functional** only when it has:

| Requirement | Why |
|---|---|
| A `tun` inbound with `auto_route: true` (Tunnel mode) or a `mixed` inbound (proxy modes) | How traffic gets in |
| A proxy outbound **or** endpoint tagged `proxy` | Somewhere for traffic to go |
| `route.final: "proxy"` | Default for unmatched traffic |
| `route.auto_detect_interface: true` (Tunnel mode) | Proxy connections use the real NIC, not the TUN (prevents loops) |
| `route.default_domain_resolver` | **Required since 1.14** — resolves the proxy server's own domain. Without it `sing-box check` fails |
| A `dns` section | TUN hijacks DNS; something has to answer |

**Provenance legend** used below:
- **Hardcoded** — fixed in the generator
- **Generated** — computed by the app (paths, ports, tags)
- **User/Server** — from user input, a link or a subscription

## 2. `log`

| Field | Provenance | Notes |
|---|---|---|
| `level` | User (`Settings.log_level`) | `LogLevel` enum: `trace` … `panic` |
| `timestamp` | Hardcoded `true` | |
| `output` | not set | sing-box logs to stderr, and `Process` writes stderr to `sing-box.log` |

## 3. `dns`

What the generator emits:

```json
"dns": {
  "servers": [
    { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
    { "type": "udp",   "tag": "local",  "server": "8.8.8.8" }
  ],
  "final": "remote"
}
```

- `remote` (DoH through the tunnel) answers all app queries: no DNS leaks.
- `local` (plain UDP, direct) is only used through `route.default_domain_resolver` to resolve proxy server domains. It can't go through the proxy, because the proxy isn't connected yet.
- Don't use `type: local` for this. On Linux it asks systemd-resolved, whose upstream query goes back into the TUN.
- Don't set `detour` to an empty `direct` outbound. That's an error in 1.12+, and leaving it unset already means direct.

### 3.1 Server types (`DnsServer` enum, tagged on `type`)

| `type` | Rust struct | Fields |
|---|---|---|
| `local` | `LocalDnsServer` | `tag`, `prefer_go`, dial fields |
| `hosts` | `HostsDnsServer` | `tag`, `path`, `predefined` |
| `udp`, `tcp` | `PlainDnsServer` | `tag`, `server`, `server_port`, dial fields |
| `tls`, `quic` | `TlsDnsServer` | + `tls` |
| `https`, `h3` | `HttpsDnsServer` | + `path` (default `/dns-query`), `headers`, `tls` |
| `fakeip` | `FakeIpDnsServer` | `tag`, `inet4_range`, `inet6_range` |

Dial fields (`detour`, `domain_resolver`, …) are flattened from `DialerOptions`.

The legacy `address: "tls://…"` format and the top-level `dns.fakeip` object were removed in favor of these types.

### 3.2 `dns.rules[]`

Only emitted for routing rules that match domains (Domain, Keyword, Geosite). Each one picks the DNS server
for the same domains, in the same order as the route rules (§6.1):

| Rule target | DNS rule |
|---|---|
| Direct | `{ …matcher, "action": "route", "server": "local" }`: domestic CDNs answer with nearby IPs |
| Proxy | `{ …matcher, "action": "route", "server": "remote" }`, so an earlier proxy rule beats a later direct one |
| Block | `{ …matcher, "action": "reject" }` |

IP, port and app rules get no DNS rule: DNS queries carry no such information (in Tunnel mode they come from systemd-resolved anyway).

`DnsRule` supports `action` (`route` / `route-options` / `reject` / `predefined`), `server`, and the common matchers `domain*`, `query_type`, `inbound`, `ip_is_private`, `clash_mode`, `rule_set`.
The old `{ "outbound": "any", "server": … }` rule is deprecated. Use `route.default_domain_resolver` instead.

## 4. `inbounds`

Only two inbound types are modeled (`Inbound` enum), because this is a client.

**TUN** (Tunnel mode):

```json
{ "type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"], "stack": "gvisor", "auto_route": true, "strict_route": true }
```

| Field | Provenance | Notes |
|---|---|---|
| `address` | Hardcoded | IPv4 + IPv6 CIDRs of the interface |
| `stack` | Hardcoded `gvisor` | The default (`mixed`) passes TCP through the kernel on the TUN interface, where host firewalls drop it (e.g. ufw's default-deny input). Only DNS kept working |
| `auto_route` | Hardcoded `true` | Without it nothing is captured |
| `strict_route` | Hardcoded `true` | Windows: stops multihomed DNS leaks. Linux: blocks traffic that bypasses the TUN |
| `mtu` | not set | sing-box picks a sane default |
| `dns_mode` | not set | `DnsMode` enum (`disabled` / `native` / `hijack`) |
| `route_exclude_address`, `include/exclude_interface`, `include/exclude_uid` | not set | Split tunneling is done with route rules instead (§6.1), which work in every mode |

**Mixed** (proxy modes, or Tunnel mode with `Settings.tunnel_proxy`): a local SOCKS5/HTTP proxy on `127.0.0.1:<proxy_port>` (default 2080). In System proxy mode it also has `set_system_proxy: true`.

## 5. `outbounds` and `endpoints`

The profile's proxy is cloned, and its tag is **always overwritten with `proxy`**, so the rest of the config can refer to it by a fixed name. A `direct` outbound is always added after it.

| Profile | Becomes |
|---|---|
| `Profile::Proxy { outbound }` | `outbounds[0]`: one of `vless`, `vmess`, `trojan`, `shadowsocks`, `hysteria2`, `tuic`, `anytls`, `socks`, `http` (`selector`/`urltest` are modeled for later) |
| `Profile::WireGuard { endpoint }` | `endpoints[0]`: `wireguard` (endpoint tags work anywhere an outbound tag does) |
| `Profile::OpenVpn` | rejected with `EngineError::WrongEngine(OpenVpn)` |

There's no `block` outbound (removed in 1.13). Blocking is a route rule with `action: "reject"`.

### 5.1 WireGuard endpoint

```json
{
  "type": "wireguard", "tag": "proxy",
  "address": ["10.0.0.2/32"],
  "private_key": "…",
  "peers": [{ "address": "203.0.113.1", "port": 51820, "public_key": "…", "allowed_ips": ["0.0.0.0/0", "::/0"] }]
}
```

How a `.conf` file maps to it (`src/import/wireguard.rs`):

| `.conf` | Endpoint field |
|---|---|
| `[Interface] Address` | `address` |
| `[Interface] PrivateKey` | `private_key` |
| `[Interface] MTU` | `mtu` |
| `[Peer] Endpoint` | `peers[].address` + `peers[].port` |
| `[Peer] PublicKey` / `PresharedKey` | `public_key` / `pre_shared_key` |
| `[Peer] AllowedIPs` | `allowed_ips` |
| `[Peer] PersistentKeepalive` | `persistent_keepalive_interval` |
| `[Interface] DNS` | ignored (our `dns` section handles DNS) |

### 5.2 Shared outbound pieces (`config/shared/`)

- **TLS** (`TlsOutbound`): `server_name`, `insecure`, `alpn`, `utls` (`UtlsFingerprint` enum), `reality`, `fragment` (**bool**), `fragment_fallback_delay`, `record_fragment`. The Xray-style `{packets, length, interval}` fragment object isn't valid in sing-box.
- **Transport** (`TransportOptions`, tagged on `type`): `http`, `ws`, `quic`, `grpc`, `httpupgrade`. There's no `tcp` transport. Plain TCP means `transport` is unset. gRPC uses `service_name`, not Xray's `serviceName`.
- **Dial fields** (`DialerOptions`, flattened): `detour`, `bind_interface`, `routing_mark`, `connect_timeout`, `domain_resolver` (replaces the deprecated dial `domain_strategy`), …
- **Typed enums**: `Network` (`tcp` / `udp`), `VlessFlow` (`xtls-rprx-vision`), `ShadowsocksMethod`.

## 6. `route`

```json
"route": {
  "rules": [
    { "action": "sniff" },
    { "protocol": ["dns"], "action": "hijack-dns" },
    { "ip_is_private": true, "action": "route", "outbound": "direct" }
  ],
  "final": "proxy",
  "auto_detect_interface": true,
  "default_domain_resolver": "local"
}
```

1. `sniff` must come first, because protocol matching depends on it.
2. `hijack-dns` sends captured DNS packets to our `dns` section. This replaces the old `dns` outbound. Tunnel mode only: proxy clients send domain names, not DNS packets.
3. LAN bypass, only when `Settings.bypass_lan` is set.
4. Routing rules (§6.1).

`final` is `proxy`, or `direct` when `Settings.routing.default` is Direct (whitelist mode).

In the proxy modes `auto_detect_interface` is left out too: without a TUN there is no loop to prevent.

### 6.1 Routing rules (`src/routing.rs` → `generate/routing.rs`)

`Routing::effective_rules()`: the enabled custom rules top to bottom, then the presets' rules (Block before Direct). The first match wins, so custom rules override presets.

| Rule kind | Route rule matcher |
|---|---|
| Domain | `domain_suffix` (the domain and its subdomains) |
| Keyword | `domain_keyword` |
| IP | `ip_cidr` (bare IPs normalized to `/32` / `/128`) |
| Port | `port` + `port_range` in one rule (sing-box ORs them) |
| App | `process_name`, and `process_path` for values with `/` or `\`. Two rules, because sing-box ANDs these fields. `find_process` isn't needed: sing-box turns process lookup on when process rules exist |
| Geosite / GeoIP | `rule_set: ["geosite-<code>"]` / `["geoip-<code>"]` |

Targets: Proxy → `action: route, outbound: proxy`; Direct → `outbound: direct`; Block → `action: reject`.

Presets: Iran direct (`geosite-category-ir` + `geoip-ir`), China direct (`geosite-cn` + `geoip-cn`), Russia direct (`geosite-category-ru` + `geoip-ru`), Block ads (`geosite-category-ads-all`).

**Rule sets** are remote binary `.srs` files from `SagerNet/sing-geosite` and `SagerNet/sing-geoip` (`rule-set` branch), deduplicated by tag:

```json
{ "type": "remote", "tag": "geoip-ir", "format": "binary",
  "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs", "download_detour": "proxy" }
```

- They download through the proxy, since GitHub may be blocked on the direct path.
- They're cached in `cache.db` and refreshed by sing-box (default interval 1d).
- If the first download fails, sing-box doesn't start; `explain()` turns that into a hint.
- `sing-box check` doesn't download them.

**IP rules in the proxy modes:** a SOCKS/HTTP client sends a domain name, so `ip_cidr` / geoip never match on their own. In System proxy and Proxy only modes the generator puts one `{ "action": "resolve" }` right before the first IP or GeoIP rule. It resolves through the default DNS server (`remote`, DoH through the proxy), so nothing leaks. The cost is that later proxied connections go to the resolved IP instead of the domain. Tunnel mode already sees destination IPs and doesn't need it.

`RuleAction` enum: `route`, `route-options`, `reject`, `hijack-dns`, `sniff`, `resolve`. `RouteRule` keeps the client-relevant matchers (`protocol`, `network`, `domain*`, `ip_cidr`, `ip_is_private`, `port*`, `process_name`/`process_path`, `clash_mode`, `rule_set`, `invert`). Rule sets can be `inline`, `local` or `remote`.

## 7. `experimental`

- `cache_file`: Generated, enabled at `<data>/cache.db`.
- `clash_api`: modeled but not emitted yet. It's planned for latency tests and switching `selector` outbounds from the UI (`external_controller: 127.0.0.1:<port>` + a random `secret`).
- `v2ray_api` / `pprof`: not modeled. They need custom sing-box builds.

## 8. Privileges

Tunnel mode needs elevated rights on both platforms (the proxy modes don't):

- **Windows**: the app embeds a manifest with `requireAdministrator` (`windows/app.manifest`, via `build.rs`). UAC prompts at launch, and `cargo run` needs an elevated terminal.
- **Linux**: in Tunnel mode the engine (sing-box, or openvpn, which is Tunnel-only) is started as root through `pkexec`, so every connect shows one admin password dialog. Running as root also means sing-box's `resolvectl domain/default-route/dns/revert` calls on the TUN need no polkit prompts of their own. Proxy modes run sing-box as the user, with no prompt.

  `Process::spawn_elevated` runs `pkexec /bin/sh -c <wrapper> <marker> <engine> <args…>`. The app can't signal a root process, so the wrapper starts the engine in the background and keeps a watcher reading the app's end of a stdin pipe. When the pipe closes (disconnect, quit, or the app crashing), the watcher sends the engine SIGTERM, so it removes its routes and DNS as usual. The wrapper first echoes a marker into the log: until it appears, the engine is still waiting for the password (`Engine::authorized()`). `start_engine` starts the 1.5 s grace period and the 45 s timeout only after that, and allows 120 s for the dialog. pkexec exit codes 126/127 (dialog dismissed, not authorized) map to `ADMIN_REFUSED`. `cache.db` is created as the user before an elevated start, so root doesn't take ownership of it. Test builds (`cfg!(test)`) never elevate.

  An older version used setcap and a polkit rule (`/etc/polkit-1/rules.d/49-cipher-client.rules`) instead. Both were removed from the app, but a system where they were granted keeps them until removed by hand.

## 9. Testing

```sh
cargo test                  # round-trip fixtures + generator assertions
cargo test -- --ignored     # also runs real `sing-box check` on generated configs and fixtures (needs sing-box in PATH)
```

A new fixture must survive deserialize → serialize unchanged. Only use modeled fields, and write list fields as arrays.
