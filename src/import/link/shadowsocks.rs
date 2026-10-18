use crate::engine::singbox::{
    config::outbound::{Outbound, shadowsocks::{ShadowsocksMethod, ShadowsocksOutbound}},
    generate::PROXY_TAG,
};
use crate::import::{ImportError, decode_base64, link, uri::{decode, parse_query, split_host_port}};
use crate::profile::Profile;
use serde_json::Value;

/// SIP002 `ss://base64(method:password)@host:port/?plugin=…#name`,
/// plain `ss://method:password@host:port` (2022 ciphers),
/// or legacy `ss://base64(method:password@host:port)#name`.
pub fn parse(link: &str) -> Result<Profile, ImportError> {
    let (_, rest) = link.split_once("://").unwrap_or_default();
    let (rest, name) = match rest.split_once('#') {
        Some((rest, name)) => (rest, Some(decode(name)).filter(|n| !n.trim().is_empty())),
        None => (rest, None),
    };
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let rest = rest.trim_end_matches('/');

    let (credentials, host_port) = match rest.rsplit_once('@') {
        Some((userinfo, host_port)) => {
            let userinfo = decode(userinfo);
            let credentials = decode_base64(&userinfo).filter(|c| c.contains(':')).unwrap_or(userinfo);
            (credentials, host_port.to_owned())
        }
        None => {
            let decoded = decode_base64(rest).ok_or_else(|| ImportError::Invalid("shadowsocks link".into()))?;
            let (credentials, host_port) = decoded
                .rsplit_once('@')
                .ok_or_else(|| ImportError::Invalid("shadowsocks link".into()))?;
            (credentials.to_owned(), host_port.to_owned())
        }
    };

    let (method, password) = credentials.split_once(':').ok_or(ImportError::Missing("method:password"))?;
    let method: ShadowsocksMethod = serde_json::from_value(Value::String(method.to_ascii_lowercase()))
        .map_err(|_| ImportError::Unsupported(format!("cipher `{method}`")))?;

    let (host, port) = split_host_port(&host_port)?;
    let server_port = port.parse().map_err(|_| ImportError::Invalid(format!("port `{port}`")))?;

    let (plugin, plugin_opts) = match parse_query(query).get("plugin").filter(|p| !p.is_empty()) {
        Some(spec) => {
            let (plugin, opts) = spec.split_once(';').unwrap_or((spec, ""));
            let plugin = match plugin {
                "obfs-local" | "simple-obfs" => "obfs-local",
                "v2ray-plugin" => "v2ray-plugin",
                other => return Err(ImportError::Unsupported(format!("plugin `{other}`"))),
            };
            (Some(plugin.to_owned()), Some(opts.to_owned()).filter(|o| !o.is_empty()))
        }
        None => (None, None),
    };

    let outbound = Outbound::Shadowsocks(ShadowsocksOutbound {
        tag: PROXY_TAG.into(),
        server: host.to_owned(),
        server_port,
        method,
        password: password.to_owned(),
        plugin,
        plugin_opts,
        ..Default::default()
    });
    let name = name.unwrap_or_else(|| format!("{host}:{port}"));
    Ok(link::proxy(name, outbound))
}
