//! The user's own Psiphon servers → [`Profile::Psiphon`].
//!
//! Two forms:
//! - a **server entry**, what `psiphond generate` writes to `server-entry.dat`: hex of
//!   `"<ip> <web port> <web secret> <web cert> <JSON>"`, where only the JSON matters (the four
//!   legacy fields are often just `0`). Accepted as the bare hex string or as `psiphon://<hex>`,
//!   and passed to the client unchanged as `TargetServerEntry`.
//! - a **client JSON config** for a private Psiphon network (`PropagationChannelId`, `SponsorId`,
//!   server list URLs and keys), kept as given; the local parts are set when connecting.

use crate::import::ImportError;
use crate::profile::{Profile, PsiphonSource};
use serde_json::{Map, Value};

/// Fields a client config must have to reach a Psiphon network.
const REQUIRED: [&str; 2] = ["PropagationChannelId", "SponsorId"];

/// What the app needs from a server entry.
pub struct ServerEntryInfo {
    pub ip: String,
    pub region: Option<String>,
    /// A TCP port for the latency test (OSSH, TLS-OSSH, SSH or meek), if the server has one.
    pub tcp_port: Option<u16>,
}

/// Whether a pasted line is a server entry (and not, say, a base64 blob of links).
pub fn looks_like_server_entry(line: &str) -> bool {
    decode(strip_scheme(line.trim())).is_some()
}

pub fn parse_server_entry(text: &str) -> Result<Profile, ImportError> {
    let entry = strip_scheme(text.trim());
    let info = info(entry).ok_or_else(|| ImportError::Invalid("Psiphon server entry".into()))?;
    let name = match &info.region {
        Some(region) => format!("Psiphon {} ({region})", info.ip),
        None => format!("Psiphon {}", info.ip),
    };
    Ok(Profile::Psiphon { name, source: PsiphonSource::ServerEntry(entry.to_ascii_lowercase()) })
}

pub fn info(server_entry: &str) -> Option<ServerEntryInfo> {
    let json = decode(server_entry)?;
    let ip = json["ipAddress"].as_str().filter(|ip| !ip.is_empty())?.to_owned();
    let region = json["region"].as_str().filter(|r| !r.is_empty()).map(str::to_owned);
    let tcp_port = ["sshObfuscatedPort", "tlsOSSHPort", "sshPort", "meekServerPort"]
        .iter()
        .find_map(|key| json[key].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|&p| p > 0));
    Some(ServerEntryInfo { ip, region, tcp_port })
}

fn strip_scheme(text: &str) -> &str {
    text.strip_prefix("psiphon://").unwrap_or(text)
}

/// Hex → the JSON object after the four space-separated legacy fields.
fn decode(hex: &str) -> Option<Value> {
    if hex.len() < 16 || !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let json = text.splitn(5, ' ').nth(4)?;
    serde_json::from_str::<Value>(json).ok().filter(Value::is_object)
}

/// Whether a text looks like a Psiphon client config.
pub fn looks_like_network(text: &str) -> bool {
    text.contains("\"PropagationChannelId\"")
}

/// Reads a Psiphon client config.
pub fn parse_network(text: &str) -> Result<Map<String, Value>, String> {
    let Ok(Value::Object(network)) = serde_json::from_str(text) else {
        return Err("not a JSON object".into());
    };
    for field in REQUIRED {
        if !network.get(field).and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty()) {
            return Err(format!("{field} is missing"));
        }
    }
    Ok(network)
}

pub fn parse_network_profile(text: &str, name: &str) -> Result<Profile, ImportError> {
    let network = parse_network(text).map_err(|e| ImportError::Invalid(format!("Psiphon config: {e}")))?;
    Ok(Profile::Psiphon { name: name.into(), source: PsiphonSource::Network(network) })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(text: &str) -> String {
        text.bytes().map(|b| format!("{b:02x}")).collect()
    }

    /// Shaped like `psiphond generate` output (compacted legacy prefix).
    pub(crate) fn sample_entry() -> String {
        hex(r#"0 0 0 0 {"tag":"","ipAddress":"203.0.113.7","sshObfuscatedPort":9999,"sshObfuscatedKey":"k","sshUsername":"u","sshPassword":"p","capabilities":["OSSH","handshake","ssh-api-requests"],"region":"DE"}"#)
    }

    pub(crate) const NETWORK: &str = r#"{
        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "0000000000000000",
        "RemoteServerListURLs": [{ "URL": "https://example.com/list", "OnlyAfterAttempts": 0 }],
        "LocalHttpProxyPort": 8080,
        "ListenInterface": "any",
        "EgressRegion": "US"
    }"#;

    #[test]
    fn parses_a_generated_server_entry() {
        let entry = sample_entry();
        assert!(looks_like_server_entry(&entry));

        let Profile::Psiphon { name, source } = parse_server_entry(&format!("  {entry}\n")).unwrap() else { panic!() };
        assert_eq!(name, "Psiphon 203.0.113.7 (DE)");
        assert_eq!(source, PsiphonSource::ServerEntry(entry.clone()));

        let info = info(&entry).unwrap();
        assert_eq!((info.ip.as_str(), info.tcp_port), ("203.0.113.7", Some(9999)));

        // Same entry as a link, in upper case.
        let Profile::Psiphon { source, .. } = parse_server_entry(&format!("psiphon://{}", entry.to_uppercase())).unwrap() else { panic!() };
        assert_eq!(source, PsiphonSource::ServerEntry(entry));
    }

    #[test]
    fn rejects_other_text() {
        assert!(!looks_like_server_entry("dmxlc3M6Ly94eXo="));
        assert!(!looks_like_server_entry("abc"));
        assert!(!looks_like_server_entry(&hex("0 0 0 0 not json")[1..]));
        assert!(!looks_like_server_entry(&hex("0 0 0 0 not json")));
        assert!(!looks_like_server_entry(&hex(r#"0 0 0 {"ipAddress":"1.2.3.4"}"#)));
        assert!(parse_server_entry(&hex(r#"0 0 0 0 {"region":"DE"}"#)).is_err());
    }

    #[test]
    fn imports_through_links_and_subscriptions() {
        let entry = sample_entry();
        let profile = crate::import::parse_link(&format!("psiphon://{entry}")).unwrap();
        assert_eq!(profile.tcp_endpoint(), Some(("203.0.113.7".into(), 9999)));
        assert_eq!(profile.group(), "Psiphon");

        // A body of bare server entries isn't mistaken for base64; links can be mixed in.
        let body = format!("{entry}\ntrojan://pw@a.example.com:443#T\n");
        let parsed = crate::import::parse_links(&body);
        assert_eq!(parsed.profiles.len(), 2, "{:?}", parsed.skipped);
        assert_eq!(parsed.profiles[0].protocol(), "psiphon");

        let parsed = crate::import::parse_links(NETWORK);
        assert!(matches!(&parsed.profiles[..], [Profile::Psiphon { source: PsiphonSource::Network(_), .. }]));
        assert_eq!(parsed.profiles[0].tcp_endpoint(), None);
        assert_eq!(crate::import::parse_links(r#"{ "PropagationChannelId": "x" }"#).skipped.len(), 1);
    }

    #[test]
    fn network_config_is_validated() {
        assert!(looks_like_network(NETWORK));
        assert!(parse_network(NETWORK).is_ok());
        assert_eq!(parse_network(r#"{ "SponsorId": "x" }"#).unwrap_err(), "PropagationChannelId is missing");
        assert_eq!(parse_network(r#"{ "PropagationChannelId": "x", "SponsorId": " " }"#).unwrap_err(), "SponsorId is missing");
        assert!(parse_network("[1]").is_err());

        let Profile::Psiphon { name, source: PsiphonSource::Network(network) } = parse_network_profile(NETWORK, "Home").unwrap() else { panic!() };
        assert_eq!(name, "Home");
        assert_eq!(network["SponsorId"], "0000000000000000");
    }
}
