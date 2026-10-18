use crate::engine::singbox::config::{
    dns::DomainStrategy,
    shared::{DomainResolver, Network},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Route {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSet>,

    /// Tag of the default outbound. Defaults to the first outbound.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_outbound: Option<String>,

    /// Bind outbound connections to the real NIC. Required with TUN to avoid loops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_detect_interface: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mark: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub find_process: Option<bool>,

    /// DNS server used to resolve outbound server domains (1.12+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    Route,
    RouteOptions,
    Reject,
    HijackDns,
    Sniff,
    Resolve,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteRule {
    // ── Action ──
    /// Defaults to `route` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<RuleAction>,

    /// Target outbound (with `action = "route"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,

    /// Sniffers to enable (with `action = "sniff"`). Unset = all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffer: Option<Vec<String>>,

    /// DNS server (with `action = "resolve"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,

    // ── Matching ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Vec<Network>>,

    /// Sniffed protocol: "http", "tls", "quic", "dns", "bittorrent", ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_keyword: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_regex: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_is_private: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip_cidr: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Vec<u16>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_path: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_set: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub invert: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleSet {
    Inline(InlineRuleSet),
    Local(LocalRuleSet),
    Remote(RemoteRuleSet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    Source,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineRuleSet {
    pub tag: String,
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRuleSet {
    pub tag: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleSetFormat>,

    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRuleSet {
    pub tag: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleSetFormat>,

    pub url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<String>,
}
