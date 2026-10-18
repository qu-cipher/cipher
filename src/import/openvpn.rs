//! `.ovpn` files and `ovpn://` links → [`Profile::OpenVpn`]. Files are referenced, not copied,
//! so certificates they point to with relative paths keep working.

use crate::import::{ImportError, decode_base64, uri::decode};
use crate::profile::{OpenVpnConfig, Profile};
use std::{fs, path::Path};

pub fn import_openvpn(path: &Path) -> Result<Profile, ImportError> {
    let text = fs::read_to_string(path)?;
    if remote_host(&text).is_none() {
        return Err(ImportError::Missing("`remote` line in the .ovpn file"));
    }

    let name = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "OpenVPN".into());

    Ok(Profile::OpenVpn { name, config: OpenVpnConfig::File(path.canonicalize()?), credentials: None })
}

/// `ovpn://<base64 of the .ovpn file>#name`, as some subscriptions mix in with proxy links.
pub fn parse_ovpn_link(link: &str) -> Result<Profile, ImportError> {
    let (_, rest) = link.trim().split_once("://").ok_or_else(|| ImportError::Invalid("link".into()))?;
    let (payload, name) = rest.split_once('#').unwrap_or((rest, ""));

    let text = decode_base64(payload).ok_or_else(|| ImportError::Invalid("base64 in ovpn link".into()))?;
    let host = remote_host(&text).ok_or(ImportError::Missing("`remote` line in the OpenVPN config"))?;

    let name = Some(decode(name)).filter(|n| !n.trim().is_empty()).unwrap_or_else(|| host.to_owned());
    Ok(Profile::OpenVpn { name, config: OpenVpnConfig::Inline(text), credentials: None })
}

/// Host of the first `remote <host> [port]` line.
fn remote_host(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("remote")).then(|| words.next()).flatten()
    })
}

/// A bare `auth-user-pass` line means OpenVPN would ask for a username and password on stdin.
/// (`auth-user-pass <file>` reads them from that file instead.)
pub fn config_needs_credentials(text: &str) -> bool {
    text.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("auth-user-pass") && words.next().is_none()
    })
}

/// Whether connecting needs credentials the profile doesn't have yet.
pub fn needs_credentials(profile: &Profile) -> bool {
    match profile {
        Profile::OpenVpn { config, credentials: None, .. } => {
            config.text().is_ok_and(|text| config_needs_credentials(&text))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_credential_prompt() {
        assert!(config_needs_credentials("client\nremote vpn.example.com 1194\nauth-user-pass\n"));
        assert!(config_needs_credentials("auth-user-pass   \r\n"));
        assert!(!config_needs_credentials("auth-user-pass creds.txt\n"));
        assert!(!config_needs_credentials("client\n# auth-user-pass\n"));
    }

    #[test]
    fn parses_ovpn_link() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let config = "client\ndev tun\nremote 203.0.113.7 8446\n<ca>\n-----BEGIN CERTIFICATE-----\n?>>\n</ca>\n";
        let link = format!("ovpn://{}#%F0%9F%87%B9%F0%9F%87%B7%20Turkey", URL_SAFE_NO_PAD.encode(config));
        let profile = parse_ovpn_link(&link).unwrap();
        let Profile::OpenVpn { name, config: OpenVpnConfig::Inline(text), credentials: None } = &profile else {
            panic!("{profile:?}")
        };
        assert_eq!(name, "🇹🇷 Turkey");
        assert_eq!(text, config);
        assert!(!needs_credentials(&profile));

        // No name → the server; no `remote` → rejected.
        let unnamed = format!("ovpn://{}", URL_SAFE_NO_PAD.encode(config));
        assert_eq!(parse_ovpn_link(&unnamed).unwrap().name(), "203.0.113.7");
        let no_remote = format!("ovpn://{}#x", URL_SAFE_NO_PAD.encode("client\n"));
        assert!(matches!(parse_ovpn_link(&no_remote), Err(ImportError::Missing(_))));
    }

    /// state.json written before inline configs existed still loads, and both forms round-trip.
    #[test]
    fn stored_profiles_round_trip() {
        let old = r#"{"kind":"open_vpn","name":"Work","config_path":"/etc/work.ovpn"}"#;
        let profile: Profile = serde_json::from_str(old).unwrap();
        assert!(matches!(&profile, Profile::OpenVpn { config: OpenVpnConfig::File(p), .. } if p == Path::new("/etc/work.ovpn")));
        assert_eq!(serde_json::to_string(&profile).unwrap(), old);

        let inline = Profile::OpenVpn { name: "TR".into(), config: OpenVpnConfig::Inline("remote a 1\n".into()), credentials: None };
        let json = serde_json::to_string(&inline).unwrap();
        assert!(matches!(serde_json::from_str(&json).unwrap(), Profile::OpenVpn { config: OpenVpnConfig::Inline(t), .. } if t == "remote a 1\n"));
    }
}
