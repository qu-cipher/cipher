# Add-ons plan (anti-DPI, SNI spoofing, DNS tunnels)

Research and plan from 2026-10-26, made before publishing 0.3.0 (Xray core). The `v0.3.0` commits are
local only and **not pushed or tagged yet**, on purpose. The add-ons are planned first so they don't end in
another "added, then switched off" pair of commits, as happened with Psiphon.

## Findings

### sni-spoofing-rust: https://github.com/therealaleph/sni-spoofing-rust
- **What it is:** MIT, Rust, ~860 stars. Latest release v1.0.2 (2026-06-02); **no commits since June**.
- **Technique:** a local TCP forwarder. Right after the TCP handshake it injects a fake TLS ClientHello
  with a deliberately wrong TCP sequence number. Passive DPI sees the fake SNI and whitelists the flow; the
  real server drops the out-of-window packet. Aimed at **Cloudflare-fronted** VLESS/VMess/Trojan configs.
- **Usage:** a `config.json` listener with `listen 127.0.0.1:40443`, `connect <Cloudflare IP>:443` (an IP, not
  a hostname), `fake_sni`, and timeouts. The client config then changes only its address/port to
  `127.0.0.1:40443`; SNI, host, path and TLS stay as they are.
- **Privileges:** raw packets. Linux needs root or `CAP_NET_RAW`, macOS needs sudo (BPF), Windows needs
  Administrator plus the **WinDivert** files next to the executable. The scanner mode needs no privileges.
- **Also a library:** `[lib] sni_spoof_rs` (tokio, socket2, nix; `windivert` on Windows), so it could be compiled
  into Cipher instead of downloaded.
- **Releases:** binaries for Linux amd64/arm64 (+musl), macOS, and a Windows zip (CLI, UI, Xray, Wintun, WinDivert).
- **Risks:**
  - Open issue #31: it works on some networks but breaks on fiber (TCP retransmission, unstable streams).
  - Issue #24: "timeout waiting for fake ACK".
  - It's a port of https://github.com/patterniha/SNI-Spoofing, which is **GPL-3.0** (Python); the port itself is MIT.
    Fine if we run it as a separate program; check again if we compile the library in.

### Slipstream (QUIC over DNS)
- **C original:** https://github.com/EndPositive/slipstream (Apache-2.0). Active (pushed 2026-10-24), but
  release binaries are **Linux only** (client and server, x86_64/arm64).
- **Rust port:** https://github.com/Mygod/slipstream-rust has Windows/macOS/Linux builds but was **archived on
  2026-08-28** (https://github.com/Mygod/slipstream-rust/discussions/111). Its author no longer thinks
  "proxying traffic over QUIC over DNS is the right architecture" and recommends MasterDnsVPN.
- **Server required:** any DNS tunnel needs **the user's own server plus a domain delegated to it**. It can't
  work with public servers.
- **Usage:** the client exposes a local TCP port
  (`--tcp-listen-port 7000 --resolver <resolver> --domain <domain>`); the server forwards to a target, e.g. an Xray inbound.

### MasterDnsVPN: https://github.com/masterking32/MasterDnsVPN
- **What it is:** MIT, Go, ~7.1k stars, pushed 2026-08-29, not archived.
- **Approach:** a DNS tunnel with its own lightweight protocol and ARQ, plus resolver load balancing.
  It claims to be faster and more loss-tolerant than DNSTT and Slipstream (its own benchmark).
- **Releases:** client and server for Linux, macOS, Windows, Termux and many CPUs, with `SHA256SUMS.txt`.
- **Use:** the preferred choice if we add a DNS-tunnel transport.

### Related (not evaluated in depth)
- **SlipNet:** https://github.com/anonvector/SlipNet (AGPL-3.0). An Android and Go CLI client bundling DNSTT,
  NoizDNS and Slipstream.
- **DNS tunneling setup guide:** https://www.samnet.dev/learn/guides/dns-tunneling-guide/

### Built into Xray 26: FinalMask (no add-on needed)
- **Docs:** https://xtls.github.io/en/config/transports/finalmask.html
- **Location:** `streamSettings.finalmask` with `tcp: []`, `udp: []` and `quicParams`. Arrays apply in order,
  first item innermost.
- **TCP masks:**
  - `fragment` (`packets: "tlshello"` or `"1-3"`, plus `lengths`, `delays`, `maxSplit`)
  - `header-custom`, `sudoku`, `filter`
- **UDP masks:**
  - `noise` (`reset`, `rand`, `type: "exp"` packets, `delay`)
  - `salamander` (Hysteria2 obfuscation)
  - `mkcp-legacy` (the old mKCP header camouflage)
  - `xdns`, `xicmp`, `realm`, `udphop`, `header-custom`, `filter`
- **Freedom outbound:** its page (https://xtls.github.io/en/config/outbounds/freedom.html) no longer documents
  `fragment`/`noises`. They appear to have moved to FinalMask.
- **sing-box:** has TLS `fragment` too (`TlsOutbound.fragment`, already modeled in our config).
- **⚠ mKCP headers:** the docs call them legacy. Our `kcpSettings.header` still passes `xray run -test`
  on 26.9.9, but before publishing 0.3.0, check it against the pinned **26.10.21** and move to the
  `mkcp-legacy` FinalMask form if needed.

## Plan

### Phase A: built-in anti-DPI in 0.3.0 (low risk, no new binaries, no root): **done 2026-10-26**
Global toggles in Settings → Anti-DPI. Fragment uses `packets: tlshello, lengths: 100-200, delays: 10-20`;
noise uses `reset: 30-60`, one `rand: 10-20` packet with `delay: 10-16`. mKCP headers: `kcpSettings.header`
still passes on 26.10.21 without a warning, so no migration yet (FinalMask `mkcp-legacy` also passes).
1. **"Fragment TLS hello" option** (per config or global, with presets for packets, lengths and delays):
   Xray FinalMask `fragment` or sing-box `tls.fragment`, depending on the engine.
2. **UDP noise** for QUIC-based configs (Xray FinalMask `noise`).
3. **mKCP header migration** to `mkcp-legacy` if 26.10.21 requires it.
4. Then tag `v0.3.0` and push.

### Phase B: add-on framework (0.4.0)
- **Same shape:** both add-on types are **local forwarders**. The proxy outbound dials `127.0.0.1:<port>`
  instead of the server, and the add-on carries the traffic. This is the same layering as `engine::chain`
  (upstream process plus readiness check), one step lower.
- **An `Addon` abstraction:**
  - install: pinned download plus SHA-256, like `engine::install`
  - spawn
  - readiness check
  - "rewrite the outbound's server address to the local forwarder" (sing-box and Xray outbounds)
  - opt-in per config; listed in Settings → Engines
- **Privileges:** add-ons that need root (SNI spoofing) run inside the **same pkexec wrapper** as Tunnel mode,
  so it stays one password prompt. In the proxy modes they would add one prompt.

### Phase C: add-ons on top of the framework
1. **SNI spoofing:** preferably compile in the `sni_spoof_rs` library and run Cipher's own binary as the
   elevated helper, so nothing extra is downloaded. Prerequisites:
   - the user tests it on their real networks (fiber issue #31)
   - decide how to handle the project going stale
   - Windows needs the WinDivert files
2. **DNS-tunnel transport via MasterDnsVPN** (not Slipstream): only if the users run their own servers.
3. **Later:** Cloudflare clean-IP scanning or fake-SNI scanning (pairs with SNI spoofing).

## Decisions
1. 0.3.0 = Xray + Phase A; external add-ons later. **Decided** (2026-10-26).
2. Do the users run their own servers (DNS tunnels)? **Undecided.**
3. The user has a new idea for the next versions; it may change the order of Phase B/C.
