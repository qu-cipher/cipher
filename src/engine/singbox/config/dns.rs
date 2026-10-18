use crate::engine::singbox::config::shared::{DialerOptions, TlsOutbound};
use serde::{ Serialize, Deserialize };
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DNS {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,

    /// Tag of the default DNS server. Defaults to the first server.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cache: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_expire: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub independent_cache: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_mapping: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

// DNS servers in the 1.12+ format: `type` + `server` + `server_port`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsServer {
    /// System resolver.
    Local(LocalDnsServer),
    Hosts(HostsDnsServer),
    Udp(PlainDnsServer),
    Tcp(PlainDnsServer),
    Tls(TlsDnsServer),
    Quic(TlsDnsServer),
    Https(HttpsDnsServer),
    H3(HttpsDnsServer),
    Fakeip(FakeIpDnsServer),
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalDnsServer {
    pub tag: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_go: Option<bool>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostsDnsServer {
    pub tag: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub predefined: Option<HashMap<String, Vec<String>>>,
}

/// `udp` / `tcp` servers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlainDnsServer {
    pub tag: String,

    pub server: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

/// `tls` / `quic` servers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsDnsServer {
    pub tag: String,

    pub server: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsOutbound>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

/// `https` / `h3` servers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpsDnsServer {
    pub tag: String,

    pub server: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Defaults to `/dns-query`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsOutbound>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FakeIpDnsServer {
    pub tag: String,

    /// Default: "198.18.0.0/15"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet4_range: Option<String>,

    /// Default: "fc00::/18"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet6_range: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsRuleAction {
    Route,
    RouteOptions,
    Reject,
    Predefined,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRule {
    // ── Action ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<DnsRuleAction>,

    /// Tag of the target DNS server (with `action = "route"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cache: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,

    // ── Matching ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_type: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_keyword: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_regex: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_is_private: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_set: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub invert: Option<bool>,
}
