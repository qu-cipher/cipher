//! Subscription URLs: a (usually base64) list of share links, plus usage info in the headers.

use crate::import::{ImportError, decode_base64, parse_link, singbox_json::parse_singbox_json};
use crate::profile::Profile;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Traffic usage from the `subscription-userinfo` header. Byte counts; `expire` is a Unix timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub upload: u64,
    pub download: u64,
    /// 0 = unlimited.
    pub total: u64,
    pub expire: Option<u64>,
}

impl Usage {
    /// `upload=123; download=456; total=789; expire=1700000000`
    pub fn parse(header: &str) -> Option<Self> {
        let mut usage = Usage::default();
        let mut found = false;

        for part in header.split(';') {
            let Some((key, value)) = part.split_once('=') else { continue };
            // Some panels send floats or empty values.
            let value = value.trim().split('.').next().and_then(|v| v.parse::<u64>().ok());
            match (key.trim().to_ascii_lowercase().as_str(), value) {
                ("upload", Some(v)) => usage.upload = v,
                ("download", Some(v)) => usage.download = v,
                ("total", Some(v)) => usage.total = v,
                ("expire", Some(v)) if v > 0 => usage.expire = Some(v),
                _ => continue,
            }
            found = true;
        }
        found.then_some(usage)
    }

    pub fn used(&self) -> u64 {
        self.upload + self.download
    }
}

/// What a subscription URL returned.
#[derive(Debug, Default)]
pub struct Subscription {
    /// From the `profile-title` header, if the panel sends one.
    pub title: Option<String>,
    pub usage: Option<Usage>,
    pub profiles: Vec<Profile>,
    /// Links that couldn't be imported, with the reason.
    pub skipped: Vec<String>,
}

/// Downloads and parses a subscription. Blocking: call it off the UI thread.
pub fn fetch_subscription(url: &str) -> Result<Subscription, ImportError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();

    // A neutral User-Agent: panels that sniff for Clash/sing-box would send YAML/JSON instead of links.
    let mut response = agent
        .get(url)
        .header("User-Agent", concat!("cipher_client/", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(Box::new)?;

    let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from);
    let usage = header("subscription-userinfo").as_deref().and_then(Usage::parse);
    let title = header("profile-title").map(|t| decode_title(&t));

    let body = response.body_mut().read_to_string().map_err(Box::new)?;

    let mut subscription = parse_subscription_body(&body)?;
    subscription.usage = usage;
    subscription.title = title.filter(|t| !t.is_empty());
    Ok(subscription)
}

/// Parses a subscription body: a sing-box JSON config, base64 of newline-separated links,
/// or the links in plain text.
pub fn parse_subscription_body(body: &str) -> Result<Subscription, ImportError> {
    if let Some(subscription) = parse_singbox_json(body) {
        return match subscription.profiles.is_empty() {
            true => Err(ImportError::Empty),
            false => Ok(subscription),
        };
    }

    let text = if body.contains("://") {
        body.to_owned()
    } else {
        decode_base64(body).ok_or_else(|| ImportError::Invalid("subscription content".into()))?
    };

    let subscription = parse_links(&text);
    if subscription.profiles.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(subscription)
}

/// Parses pasted text: one link per line, a base64 blob of them, or a sing-box JSON config. Never fails;
/// unusable lines end up in `skipped` with the reason.
pub fn parse_links(text: &str) -> Subscription {
    if let Some(subscription) = parse_singbox_json(text) {
        return subscription;
    }

    let decoded;
    let text = match text.contains("://") {
        true => text,
        false => match decode_base64(text) {
            Some(d) => {
                decoded = d;
                &decoded
            }
            None => text,
        },
    };

    let mut subscription = Subscription::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match parse_link(line) {
            Ok(profile) => subscription.profiles.push(profile),
            Err(e) => subscription.skipped.push(format!("{}: {e}", line.split("://").next().unwrap_or(line))),
        }
    }
    subscription
}

/// `profile-title: base64:<b64>` or a plain title.
fn decode_title(title: &str) -> String {
    match title.strip_prefix("base64:") {
        Some(encoded) => decode_base64(encoded).unwrap_or_default(),
        None => title.to_owned(),
    }
    .trim()
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn parses_usage_header() {
        let usage = Usage::parse("upload=1024; download=2048; total=10737418240; expire=1767225600").unwrap();
        assert_eq!(usage, Usage { upload: 1024, download: 2048, total: 10737418240, expire: Some(1767225600) });
        assert_eq!(usage.used(), 3072);

        assert_eq!(Usage::parse("upload=0; download=5.0; total=0; expire=0").unwrap().expire, None);
        assert_eq!(Usage::parse("garbage"), None);
    }

    #[test]
    fn parses_base64_body_and_skips_bad_links() {
        let links = "\
vless://bf000d23-0752-40b4-affe-68f7707a9661@de.example.com:443?security=tls&sni=de.example.com#DE
ssr://d2hhdGV2ZXI#unsupported
trojan://secret@nl.example.com:443#NL
";
        let subscription = parse_subscription_body(&STANDARD.encode(links)).unwrap();
        let names: Vec<_> = subscription.profiles.iter().map(Profile::name).collect();
        assert_eq!(names, ["DE", "NL"]);
        assert_eq!(subscription.skipped.len(), 1);
        assert!(subscription.skipped[0].starts_with("ssr"));
    }

    #[test]
    fn plain_text_body_and_empty_body() {
        let subscription = parse_subscription_body("trojan://secret@nl.example.com:443#NL\n").unwrap();
        assert_eq!(subscription.profiles.len(), 1);

        assert!(matches!(parse_subscription_body("ssr://x"), Err(ImportError::Empty)));
    }

    /// Serves one canned HTTP response from a local socket and fetches it.
    #[test]
    fn fetches_over_http() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/sub/abc", listener.local_addr().unwrap());

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push(line);
            }

            let body = STANDARD.encode("trojan://secret@nl.example.com:443#NL\n");
            let title = STANDARD.encode("My VPN");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nsubscription-userinfo: upload=1; download=2; total=3\r\n\
                 profile-title: base64:{title}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            (&stream).write_all(response.as_bytes()).unwrap();
            request
        });

        let subscription = fetch_subscription(&url).unwrap();
        let request = server.join().unwrap();

        assert!(request[0].starts_with("GET /sub/abc "));
        assert!(request.iter().any(|h| h.to_ascii_lowercase().starts_with("user-agent: cipher_client/")));
        assert_eq!(subscription.title.as_deref(), Some("My VPN"));
        assert_eq!(subscription.usage.unwrap().total, 3);
        assert_eq!(subscription.profiles[0].name(), "NL");
    }

    #[test]
    fn decodes_titles() {
        assert_eq!(decode_title(&format!("base64:{}", STANDARD.encode("My VPN"))), "My VPN");
        assert_eq!(decode_title("Plain"), "Plain");
    }
}
