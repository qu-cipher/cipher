//! OpenVPN's Android protocol on the management socket (its doc/android.txt). Built for Android,
//! OpenVPN doesn't touch the network itself: it asks the app with `>NEED-OK` requests, one per
//! address / route / DNS setting, then `OPENTUN` for the TUN's fd, sent back as SCM_RIGHTS
//! ancillary data with the `needok` reply. Parsed here (testable anywhere); used on Android.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The TUN's shape, for `VpnService.Builder` (see android::establish).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunSpec {
    /// (address, prefix length)
    pub addresses: Vec<(String, u8)>,
    pub routes: Vec<(String, u8)>,
    pub dns: Vec<String>,
    pub search_domains: Vec<String>,
    pub mtu: u16,
}

impl TunSpec {
    /// One setting per line, as CipherVpnService.establish reads it.
    pub fn to_lines(&self) -> String {
        let mut lines = Vec::new();
        lines.extend(self.addresses.iter().map(|(a, p)| format!("address {a} {p}")));
        lines.extend(self.routes.iter().map(|(a, p)| format!("route {a} {p}")));
        lines.extend(self.dns.iter().map(|d| format!("dns {d}")));
        lines.extend(self.search_domains.iter().map(|d| format!("search {d}")));
        if self.mtu > 0 {
            lines.push(format!("mtu {}", self.mtu));
        }
        lines.join("\n")
    }
}

/// A `>NEED-OK:Need '<kind>' confirmation MSG:<message>` line.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: &'a str,
    pub message: &'a str,
}

impl<'a> Request<'a> {
    pub fn parse(line: &'a str) -> Option<Self> {
        let rest = line.trim_end().strip_prefix(">NEED-OK:Need '")?;
        let (kind, rest) = rest.split_once('\'')?;
        let message = rest.split_once(" MSG:").map_or("", |(_, message)| message);
        Some(Request { kind, message })
    }

    /// Records a setting in `spec`. Settings it can't use are confirmed anyway (OpenVPN would
    /// stop otherwise): routes to other interfaces (the server's own address; the app is
    /// outside its VPN anyway), proxies, PROTECTFD (same reason).
    pub fn apply(&self, spec: &mut TunSpec) {
        let parts: Vec<&str> = self.message.split_whitespace().collect();
        match (self.kind, parts.as_slice()) {
            // "10.8.0.6 255.255.255.0 1500 subnet", "10.8.0.6 10.8.0.5 1500 net30"
            ("IFCONFIG", [local, other, mtu, topology, ..]) => {
                let prefix = match *topology {
                    "subnet" => netmask_prefix(other),
                    "net30" => Some(30),
                    _ => netmask_prefix(other).filter(|_| other.starts_with("255.")).or(Some(32)),
                };
                if let Some(prefix) = prefix {
                    spec.addresses.push((local.to_string(), prefix));
                }
                if let Ok(mtu) = mtu.parse() {
                    spec.mtu = mtu;
                }
            }
            // "fd00::1000/64 1500"
            ("IFCONFIG6", [address, ..]) => {
                if let Some((address, prefix)) = address.split_once('/')
                    && let Ok(prefix) = prefix.parse()
                {
                    spec.addresses.push((address.to_string(), prefix));
                }
            }
            // "0.0.0.0 128.0.0.0 10.8.0.1"; with "dev <iface>" it's a route around the VPN.
            ("ROUTE", [network, netmask, rest @ ..]) if !rest.contains(&"dev") => {
                if let (Ok(network), Some(prefix)) = (network.parse::<Ipv4Addr>(), netmask_prefix(netmask)) {
                    let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
                    spec.routes.push((Ipv4Addr::from(u32::from(network) & mask).to_string(), prefix));
                }
            }
            // "2000::/3 vpnservice-tun"
            ("ROUTE6", [route, ..]) => {
                if let Some((network, prefix)) = route.split_once('/')
                    && let (Ok(network), Ok(prefix)) = (network.parse::<Ipv6Addr>(), prefix.parse::<u8>())
                    && prefix <= 128
                {
                    let mask = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
                    spec.routes.push((Ipv6Addr::from(u128::from(network) & mask).to_string(), prefix));
                }
            }
            ("DNSSERVER" | "DNS6SERVER", [server, ..]) => spec.dns.push(server.to_string()),
            ("DNSDOMAIN", [domain, ..]) => spec.search_domains.push(domain.to_string()),
            _ => {}
        }
    }

    /// The reply, for everything but OPENTUN (which carries the fd).
    pub fn reply(&self) -> String {
        // A changed setup gets a new TUN; Android swaps it in before closing the old one.
        let action = if self.kind == "PERSIST_TUN_ACTION" { "OPEN_BEFORE_CLOSE" } else { "ok" };
        format!("needok '{}' {action}\n", self.kind)
    }
}

/// "255.255.255.0" → 24; None for a non-contiguous mask.
fn netmask_prefix(netmask: &str) -> Option<u8> {
    let bits = u32::from(netmask.parse::<Ipv4Addr>().ok()?);
    let prefix = bits.leading_ones();
    (bits.checked_shl(prefix).unwrap_or(0) == 0).then_some(prefix as u8)
}

/// Writes `text` with `fd` attached (SCM_RIGHTS), as OpenVPN reads the OPENTUN reply.
#[cfg(unix)]
pub fn send_with_fd(stream: &std::os::unix::net::UnixStream, text: &str, fd: i32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd_size = std::mem::size_of::<i32>() as u32;
    // u64s keep the control buffer aligned for cmsghdr.
    let mut control = [0u64; 4];
    let mut iov = libc::iovec { iov_base: text.as_ptr() as *mut _, iov_len: text.len() };
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(fd_size) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
        if libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(lines: &[&str]) -> TunSpec {
        let mut spec = TunSpec::default();
        for line in lines {
            Request::parse(line).unwrap().apply(&mut spec);
        }
        spec
    }

    #[test]
    fn parses_requests() {
        let request = Request::parse(">NEED-OK:Need 'IFCONFIG' confirmation MSG:10.8.0.6 255.255.255.0 1500 subnet\r\n").unwrap();
        assert_eq!(request, Request { kind: "IFCONFIG", message: "10.8.0.6 255.255.255.0 1500 subnet" });
        assert_eq!(request.reply(), "needok 'IFCONFIG' ok\n");

        let persist = Request::parse(">NEED-OK:Need 'PERSIST_TUN_ACTION' confirmation MSG:tunmethod").unwrap();
        assert_eq!(persist.reply(), "needok 'PERSIST_TUN_ACTION' OPEN_BEFORE_CLOSE\n");
        assert!(Request::parse(">HOLD:Waiting for hold release:0").is_none());
        assert!(Request::parse(">LOG:1,I,OpenVPN 2.7.8").is_none());
    }

    /// What a typical `redirect-gateway def1` server with IPv6 pushes, in OpenVPN's order.
    #[test]
    fn builds_the_tun_from_pushed_settings() {
        let spec = spec_from(&[
            ">NEED-OK:Need 'PROTECTFD' confirmation MSG:protect_fd_nonlocal",
            ">NEED-OK:Need 'IFCONFIG' confirmation MSG:10.8.0.6 255.255.255.0 1500 subnet",
            ">NEED-OK:Need 'IFCONFIG6' confirmation MSG:fd00:1234::1000/64 1500",
            ">NEED-OK:Need 'ROUTE' confirmation MSG:203.0.113.7 255.255.255.255 192.168.1.1 dev wlan0",
            ">NEED-OK:Need 'ROUTE' confirmation MSG:0.0.0.0 128.0.0.0 10.8.0.1",
            ">NEED-OK:Need 'ROUTE' confirmation MSG:128.0.0.0 128.0.0.0 10.8.0.1",
            ">NEED-OK:Need 'ROUTE' confirmation MSG:10.20.30.40 255.255.0.0 10.8.0.1",
            ">NEED-OK:Need 'ROUTE6' confirmation MSG:2000::/3 vpnservice-tun",
            ">NEED-OK:Need 'DNS6SERVER' confirmation MSG:fd00:1234::1",
            ">NEED-OK:Need 'DNSSERVER' confirmation MSG:10.8.0.1",
            ">NEED-OK:Need 'DNSDOMAIN' confirmation MSG:corp.example",
            ">NEED-OK:Need 'PERSIST_TUN_ACTION' confirmation MSG:tunmethod",
        ]);
        assert_eq!(spec, TunSpec {
            addresses: vec![("10.8.0.6".into(), 24), ("fd00:1234::1000".into(), 64)],
            routes: vec![
                ("0.0.0.0".into(), 1),
                ("128.0.0.0".into(), 1),
                // Host bits cleared: VpnService.Builder rejects them.
                ("10.20.0.0".into(), 16),
                ("2000::".into(), 3),
            ],
            dns: vec!["fd00:1234::1".into(), "10.8.0.1".into()],
            search_domains: vec!["corp.example".into()],
            mtu: 1500,
        });
        assert_eq!(
            spec.to_lines().lines().next_back(),
            Some("mtu 1500"),
        );
    }

    #[test]
    fn net30_and_p2p_topologies() {
        let net30 = spec_from(&[">NEED-OK:Need 'IFCONFIG' confirmation MSG:10.8.0.6 10.8.0.5 1500 net30"]);
        assert_eq!(net30.addresses, vec![("10.8.0.6".into(), 30)]);
        let p2p = spec_from(&[">NEED-OK:Need 'IFCONFIG' confirmation MSG:10.8.0.2 10.8.0.1 1400 p2p"]);
        assert_eq!((p2p.addresses, p2p.mtu), (vec![("10.8.0.2".into(), 32)], 1400));
    }

    #[test]
    fn netmasks() {
        assert_eq!(netmask_prefix("255.255.255.0"), Some(24));
        assert_eq!(netmask_prefix("0.0.0.0"), Some(0));
        assert_eq!(netmask_prefix("255.255.255.255"), Some(32));
        assert_eq!(netmask_prefix("255.0.255.0"), None);
        assert_eq!(netmask_prefix("nonsense"), None);
    }

    /// The fd arrives on the other end as SCM_RIGHTS, the way OpenVPN receives the TUN.
    #[cfg(unix)]
    #[test]
    fn sends_an_fd_with_the_reply() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (ours, theirs) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_with_fd(&ours, "needok 'OPENTUN' ok\n", file.as_raw_fd()).unwrap();

        let mut buffer = [0u8; 64];
        let mut control = [0u64; 4];
        let mut iov = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
        let (received, fd) = unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control) as _;
            let n = libc::recvmsg(theirs.as_raw_fd(), &mut message, 0);
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null() && (*header).cmsg_type == libc::SCM_RIGHTS);
            (n as usize, std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>()))
        };
        assert_eq!(&buffer[..received], b"needok 'OPENTUN' ok\n");
        assert!(fd >= 0 && fd != file.as_raw_fd());
        unsafe { libc::close(fd) };
    }
}
