//! A forgiving splitter for `scheme://userinfo@host:port/path?query#name` share links.
//! Hand-rolled because real links break strict URL parsers (port ranges, raw base64 in queries).

use crate::import::ImportError;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ShareLink {
    /// Percent-decoded part before `@`.
    pub userinfo: Option<String>,
    /// Host without IPv6 brackets.
    pub host: String,
    /// Raw port spec: `443`, or `443,20000-30000` for Hysteria2 port hopping.
    pub port: String,
    /// Percent-decoded query values; keys are lowercased for case-insensitive lookup.
    pub query: HashMap<String, String>,
    /// Percent-decoded fragment (the display name).
    pub name: Option<String>,
}

impl ShareLink {
    pub fn parse(link: &str) -> Result<Self, ImportError> {
        let link = link.trim();
        let (_, rest) = link.split_once("://").ok_or_else(|| ImportError::Invalid("link".into()))?;

        let (rest, name) = match rest.split_once('#') {
            Some((rest, fragment)) => (rest, Some(decode(fragment)).filter(|n| !n.trim().is_empty())),
            None => (rest, None),
        };
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        // Anything after the authority (`/`, `/path`) carries nothing we use.
        let authority = rest.split('/').next().unwrap_or(rest);

        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((userinfo, host_port)) => (Some(decode(userinfo)), host_port),
            None => (None, authority),
        };
        let (host, port) = split_host_port(host_port)?;

        Ok(Self {
            userinfo,
            host: host.to_owned(),
            port: port.to_owned(),
            query: parse_query(query),
            name,
        })
    }

    /// First port of the port spec.
    pub fn port(&self) -> Result<u16, ImportError> {
        first_port(&self.port).ok_or_else(|| ImportError::Invalid(format!("port `{}`", self.port)))
    }

    /// Non-empty query value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str).filter(|v| !v.is_empty())
    }

    /// Display name, falling back to `host:port`.
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("{}:{}", self.host, self.port))
    }
}

pub fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// `a=1&b=2` → map. `+` is kept as-is: base64 keys in links are rarely form-encoded.
pub fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key).to_ascii_lowercase(), decode(value))
        })
        .collect()
}

/// Splits `host:port` / `[v6]:port`. The port may be empty.
pub fn split_host_port(s: &str) -> Result<(&str, &str), ImportError> {
    let invalid = || ImportError::Invalid(format!("address `{s}`"));

    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
        (host, after.strip_prefix(':').unwrap_or(after))
    } else {
        s.rsplit_once(':').unwrap_or((s, ""))
    };

    if host.is_empty() {
        return Err(invalid());
    }
    Ok((host, port))
}

pub fn first_port(spec: &str) -> Option<u16> {
    spec.split([',', '-', ':']).next()?.trim().parse().ok()
}

/// `443,20000-30000` → sing-box `server_ports` (`["443:443", "20000:30000"]`).
/// `None` when the spec is a single port.
pub fn port_ranges(spec: &str) -> Option<Vec<String>> {
    if !spec.contains([',', '-']) {
        return None;
    }
    let ranges = spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('-') {
            Some((start, end)) => format!("{}:{}", start.trim(), end.trim()),
            None => format!("{part}:{part}"),
        })
        .collect();
    Some(ranges)
}
