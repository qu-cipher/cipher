# Writing Cipher plugins

A Cipher plugin is **a separate program plus a `plugin.json` manifest**. Cipher never loads plugin
code into itself: it downloads your program from your GitHub releases, checks it, and runs it as a
child process with the arguments and config file your manifest describes.

There are two kinds:

| Kind | What it is | What Cipher does |
|---|---|---|
| **transport** | A local forwarder that carries a config's traffic another way (DNS tunnel, SNI spoofing, obfuscation…) | Starts your program on `127.0.0.1:{listen_port}`, then points the user's config (VLESS, Trojan, …) at that port instead of its server |
| **engine** | Your own VPN core or protocol | Starts your program, which serves **SOCKS5** on `127.0.0.1:{listen_port}`, then runs sing-box in front of it |

Either way, sing-box stays in front, so Tunnel mode, the system proxy, the local proxy and the
user's routing rules keep working without anything from you.

```
transport:  apps → sing-box (or Xray) ──config──▶ 127.0.0.1:{listen_port} [your program] ──▶ your way to the server
engine:     apps → sing-box ──SOCKS5──▶ 127.0.0.1:{listen_port} [your program] ──▶ anywhere
```

## Requirements

Cipher only installs plugins that are open source, and it checks what it can:

- **A public GitHub repository** (`repository`), with a **license file** GitHub recognizes. The
  manifest's `license` must be the same SPDX id GitHub shows (e.g. `MIT`, `Apache-2.0`, `GPL-3.0`).
  Archived repositories install with a warning.
- **Programs from that repository's releases:** every asset URL must start with
  `https://github.com/<owner>/<repo>/releases/download/`.
- **A SHA-256 for every asset.** A download that doesn't match is refused.
- **Manifest API version 1** (`"api": 1`).

Users see your repository, license, version, whether you need admin rights, and this warning
before installing:

> Only add plugins from sources you trust. A plugin is a program that runs on your computer and can
> see all traffic that goes through it. A malicious plugin can steal your data or take over your
> system. The app checks that the file matches its published source, not that the source is safe.

## The manifest

`plugin.json`, usually at the root of your repository (users can then add the plugin by entering
just the repository URL):

```json
{
  "api": 1,
  "id": "dns-tunnel",
  "name": "DNS Tunnel",
  "kind": "transport",
  "version": "1.2.0",
  "description": "Carries TCP configs through DNS queries to your own server.",
  "repository": "https://github.com/example/dns-tunnel",
  "license": "MIT",
  "assets": {
    "linux-x86_64": {
      "url": "https://github.com/example/dns-tunnel/releases/download/v1.2.0/dns-tunnel-linux-amd64.tar.gz",
      "sha256": "9f2c…64 hex digits…",
      "binary": "dns-tunnel-linux-amd64/dns-tunnel"
    },
    "windows-x86_64": {
      "url": "https://github.com/example/dns-tunnel/releases/download/v1.2.0/dns-tunnel-windows-amd64.zip",
      "sha256": "41ab…",
      "binary": "dns-tunnel.exe"
    }
  },
  "args": ["--config", "{config_file}"],
  "config_template": "{ \"listen\": \"127.0.0.1:{listen_port}\", \"domain\": {field.domain:json}, \"forward\": \"{server}:{server_port}\" }",
  "config_file_name": "config.json",
  "ready": { "port": true },
  "network": "tcp",
  "needs_root": false,
  "fields": [
    { "key": "domain", "label": "Tunnel domain", "type": "text", "required": true,
      "hint": "The domain delegated to your server" },
    { "key": "resolvers", "label": "Resolvers", "type": "select", "options": ["system", "public"], "default": "public" }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `api` | yes | Always `1` for now. |
| `id` | yes | Lowercase letters, digits and `-`, at most 32. Stays the same across versions. |
| `name` | yes | Shown in the app. |
| `kind` | yes | `"transport"` or `"engine"`. |
| `version` | yes | Shown in the app. |
| `description` | no | One or two sentences shown before installing. |
| `repository` | yes | `https://github.com/<owner>/<repo>`. |
| `license` | yes | SPDX id; must match what GitHub detects. |
| `assets` | yes | Per platform: `url`, `sha256`, `binary`. Platform keys are `<os>-<arch>` as Rust names them: `linux-x86_64`, `linux-aarch64`, `windows-x86_64`, `windows-aarch64`. Users on other platforms are told there's no build for them. |
| `assets.*.binary` | yes | The program: the downloaded file itself, or its path inside a `.zip`, `.tar.gz`, `.tgz`, `.tar.xz` or `.tar` download. |
| `args` | no | Command-line arguments, with placeholders. No shell is involved, so no quoting is needed. |
| `config_template` | no | Text Cipher writes to a file before starting you; its path is `{config_file}`. |
| `config_file_name` | no | File name for `{config_file}` (default `config`). |
| `files` | no | More files to write before starting you: `{ "file name": "template" }`, with the same placeholders. They go in `{data_dir}`, next to `{config_file}`; refer to one as `{data_dir}/<file name>`. |
| `ready` | yes | When you're ready: `{ "port": true }` (`{listen_port}` accepts TCP connections) or `{ "log": "some text" }` (your output contains that text). |
| `network` | yes | `"tcp"`, `"udp"` or `"both"`; see below. |
| `needs_root` | no | `true` if you need administrator rights; see [Root plugins](#root-plugins). |
| `schemes` | no | Engines only: link schemes you handle; see [Links](#links-engine-plugins). |
| `core` | no | Engines only: you run the user's ordinary configs; see [Core plugins](#core-plugins). |
| `fields` | no | Settings the user fills in per config; see [Fields](#fields). |

Unknown fields are rejected, so typos don't go unnoticed.

### Placeholders

Used in `args`, `config_template` and `files`:

| Placeholder | Value |
|---|---|
| `{listen_port}` | The loopback port you must listen on. **Required** somewhere in `args`, `config_template` or `files`. |
| `{server}`, `{server_port}` | Transports only: the server the user's config pointed at, before Cipher redirected it to you. |
| `{link}` | Engines only: the whole link the config was imported from (empty for configs made from fields). |
| `{outbound}` | Core plugins only: the selected config's outbound as JSON, in your `core.format`. |
| `{field.<key>}` | The value of one of your fields. |
| `{data_dir}` | A folder only your plugin uses (it persists between runs). |
| `{config_file}` | The path of the rendered `config_template` (only when you have one). |

`{name:json}` inserts the value as a JSON string, quotes and escaping included. Use it for values the
user typed (`"domain": {field.domain:json}`). A brace that isn't a placeholder (lowercase name, digits,
`_` and `.` only) is left as it is, so JSON templates need no escaping. Unknown placeholders are an
error when the manifest is read.

### `network`

- **Transports:** what you can carry. TCP-based configs (VLESS, VMess, Trojan, Shadowsocks, AnyTLS,
  and Xray's TCP transports) need `tcp`; QUIC-based ones (Hysteria2, TUIC, mKCP) need `udp`. A
  config your transport can't carry fails to connect with a message saying so.
- **Engines:** what your SOCKS5 proxy relays. With `udp` or `both`, support `UDP ASSOCIATE`.

### Fields

Per-config settings the user fills in when choosing your transport for a config, or when creating a
config for your engine. Each field:

| Key | Meaning |
|---|---|
| `key` | Lowercase letters, digits and `_`; used as `{field.<key>}`. |
| `label` | Shown next to the input. |
| `type` | `text`, `number`, `bool` (values `true`/`false`), `select`, or `lines` (a multi-line box for lists, inserted with its line breaks). |
| `options` | `select` only: the choices. |
| `default` | Used when the user leaves it empty. |
| `required` | The user must fill it in. |
| `hint` | A short explanation under the input. |

Cipher checks the values (numbers parse, selects match) before starting you. Field values are stored
with the user's configs, so don't ask for secrets you wouldn't want saved in the app's state file.

### Links (engine plugins)

An engine can claim link schemes, e.g. `"schemes": ["myproto"]`. When the user adds a
`myproto://…` link (pasted, imported, or from a subscription), Cipher stores it as a config for your
plugin, named after the `#fragment`, and passes the whole link as `{link}`. Cipher never parses it.
Schemes Cipher handles itself (`vless`, `vmess`, `trojan`, `ss`, `hy2`, `tuic`, `anytls`, `wireguard`,
`ovpn`, `psiphon`, …) can't be claimed.

### Core plugins

An engine with a `core` block runs the user's **ordinary configs** (VLESS, Trojan, Hysteria2, …) instead
of bringing its own: a fork of sing-box or Xray, or an engine of your own that reads one of their
outbound formats. Users pick it under *Settings → Core*, next to sing-box and Xray, and it's listed under
*Settings → Engines*.

```json
"core": { "format": "sing-box", "protocols": ["shadowquic"] }
```

| Key | Meaning |
|---|---|
| `format` | `"sing-box"` or `"xray"`: the outbound format you read. `{outbound}` is the config's outbound in it, tagged `proxy`, with the user's anti-DPI options applied (TLS fragment for sing-box, `finalmask` for Xray). |
| `protocols` | `sing-box` format only: outbound types you **add** (names sing-box itself has are refused). Outbounds of these types in sing-box JSON (files, subscriptions, pasted) are kept for you as they are, and **always** run on your plugin, whatever *Core* says. |

Like any engine, you serve SOCKS5 on `127.0.0.1:{listen_port}` and the official sing-box stays in front
for Tunnel mode, the system proxy and routing. So you only need the outbound side; your template wraps
`{outbound}` in your own config:

```json
"config_template": "{ \"inbounds\": [{ \"type\": \"socks\", \"listen\": \"127.0.0.1\", \"listen_port\": {listen_port} }], \"outbounds\": [{outbound}] }"
```

With *Core* set to your plugin, it gets every config its format can carry: all sing-box proxy configs for
`sing-box`; for `xray`, what Xray can run (VLESS, VMess, Trojan, Shadowsocks, and the XHTTP/mKCP configs that
otherwise need Xray). Everything else keeps its built-in engine. Core plugins have no `fields`, `schemes` or
`{link}`. Resolve server domains yourself (e.g. a DNS section in your template): in Tunnel mode your
process's traffic goes direct, but the system resolver goes through the tunnel.

## What your program must do

**Transports:**
- Listen on `127.0.0.1:{listen_port}` (TCP, and/or UDP for `udp`/`both`).
- Carry each connection to the server however you like: to `{server}:{server_port}`, or through your
  own relay that ends there. The user's config dials you as if you were the server: its TLS, SNI and
  Host headers stay the original server's, so you see a normal client stream.

**Engines:**
- Serve SOCKS5 without authentication on `127.0.0.1:{listen_port}`.

**Both:**
- Become ready quickly and say so the way `ready` describes. Cipher waits up to about two minutes
  (this also covers the admin password dialog for root plugins).
- Write logs to stdout/stderr: they go to `<data>/plugin-<id>.log`, and **your last line is shown to
  the user if you exit**. Make it a useful error. (A timestamp like Go's `2026/10/26 17:17:22` and `[tag]`
  prefixes are removed, and a trailing "Press Enter to exit" prompt is skipped.)
- Exit cleanly on **SIGTERM** (Linux), restoring anything you changed (routes, firewall rules). Cipher
  waits about 5 seconds (10 for root plugins) before killing you. On Windows you're killed directly.
- Don't detach or fork into the background: Cipher tracks the process it started.
- Expect to be started fresh for every connection, with a different port.

**Your own connections:** in Tunnel mode, sing-box routes traffic from your process name directly, so it
doesn't loop back through the tunnel. Cipher installs your program as `cipher-plugin-<id>` (plus `.exe`
on Windows), so that name is what's matched. Don't re-exec yourself under another name.

## Root plugins

Set `"needs_root": true` only if you really need it (raw sockets, routes, packet injection).

- The user has to **allow it separately**, after a second warning, at install or later in the Plugins
  tab. Until then your plugin can't run.
- **Linux:** Cipher starts a small helper through pkexec (its own binary, `--elevated-helper`) and runs
  you as root inside it. In Tunnel mode sing-box's TUN runs in the same helper, so the user still sees
  **one password prompt per connection**. You still start before sing-box.
- **Windows:** Cipher itself runs as administrator, so every plugin does, whether or not it sets
  `needs_root`. Users are told this when adding any plugin.
- Your config file and log are created by Cipher as the user; don't change their ownership.

## Developing and testing

**Developer mode** lets you install from a local folder without publishing a release:

```sh
CIPHER_PLUGIN_DEV=1 cipher_client
```

Then *Plugins → Add plugin → Browse…*, and pick your `plugin.json`. If the asset for your platform has a
`binary` path that exists **relative to the manifest's folder** (e.g. `target/release/my-plugin`),
Cipher copies that file instead of downloading. The repository, license and checksum aren't checked, and
the plugin is marked *Development*. Re-add it after each build.

Things to check before publishing:
1. Proxy only mode first, then System proxy, then Tunnel mode.
2. Disconnect and reconnect a few times: ports change, and your program must exit on SIGTERM.
3. Kill your program while connected: the user should see your last log line as the error.
4. For transports, a TLS config with an IP address as the server (SNI must still be right).

## Publishing

1. Tag a release and upload one asset per platform.
2. Put each asset's SHA-256 in `plugin.json` (e.g. `sha256sum dist/*`) and commit it to the default
   branch. Users can then add your plugin with just `https://github.com/<owner>/<repo>`, or with a direct
   link to any `plugin.json` you host.
3. Optional but recommended: publish **build provenance**, so anyone can check a file was built from your
   source by your workflow. Cipher shows "Build provenance: not checked" for now; a later version will
   verify it.

A release workflow that does all of this:

```yaml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write
  attestations: write
jobs:
  build:
    strategy:
      matrix:
        include:
          - { os: ubuntu-22.04, target: x86_64-unknown-linux-gnu, asset: my-plugin-linux-amd64 }
          - { os: windows-latest, target: x86_64-pc-windows-msvc, asset: my-plugin-windows-amd64.exe }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release --target ${{ matrix.target }}
      - shell: bash
        run: |
          mkdir dist
          cp target/${{ matrix.target }}/release/my-plugin* dist/${{ matrix.asset }}
          cd dist && sha256sum ${{ matrix.asset }} > ${{ matrix.asset }}.sha256
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/${{ matrix.asset }}
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

## Official plugins

Official plugins are listed inside Cipher itself, ready to add: their manifests are built into each Cipher
release and published in [`plugins/`](../plugins). They get an *Official* badge, and a newer Cipher release
can offer an *Update*. Any plugin that follows this guide can be installed by URL; the badge and the
listing are the only differences.

| Plugin | Kind | What it is |
|---|---|---|
| [MasterDnsVPN](../plugins/masterdnsvpn.json) | engine | A DNS tunnel to your own [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) server: TCP only (its SOCKS proxy relays UDP for DNS alone). A real example of `files` and a `lines` field. |

## Example: a core

A sing-box fork that adds a protocol:

```json
{
  "api": 1,
  "id": "sing-box-plus",
  "name": "sing-box+",
  "kind": "engine",
  "version": "1.14.3-plus.1",
  "repository": "https://github.com/example/sing-box-plus",
  "license": "GPL-3.0",
  "assets": {
    "linux-x86_64": {
      "url": "https://github.com/example/sing-box-plus/releases/download/v1.14.3-plus.1/sing-box-plus-linux-amd64.tar.gz",
      "sha256": "…",
      "binary": "sing-box-plus/sing-box"
    }
  },
  "core": { "format": "sing-box", "protocols": ["shadowquic"] },
  "args": ["run", "-c", "{config_file}"],
  "config_template": "{ \"log\": { \"level\": \"warn\" }, \"dns\": { \"servers\": [{ \"type\": \"udp\", \"tag\": \"local\", \"server\": \"1.1.1.1\" }] }, \"inbounds\": [{ \"type\": \"socks\", \"listen\": \"127.0.0.1\", \"listen_port\": {listen_port} }], \"outbounds\": [{outbound}], \"route\": { \"default_domain_resolver\": \"local\" } }",
  "config_file_name": "config.json",
  "ready": { "port": true },
  "network": "both"
}
```

## Example: an engine

```json
{
  "api": 1,
  "id": "myproto",
  "name": "MyProto",
  "kind": "engine",
  "version": "0.2.0",
  "repository": "https://github.com/example/myproto",
  "license": "Apache-2.0",
  "assets": {
    "linux-x86_64": {
      "url": "https://github.com/example/myproto/releases/download/v0.2.0/myproto-linux-amd64",
      "sha256": "…",
      "binary": "myproto-linux-amd64"
    }
  },
  "args": ["client", "--socks", "127.0.0.1:{listen_port}", "--link", "{link}", "--state", "{data_dir}"],
  "ready": { "log": "SOCKS5 proxy listening" },
  "network": "both",
  "schemes": ["myproto"]
}
```
