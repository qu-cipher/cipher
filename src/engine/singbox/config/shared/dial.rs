use serde::{Deserialize, Serialize};
use crate::engine::singbox::config::dns::DomainStrategy;

// Listen options (inbound base)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListenOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_multi_path: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
}

// Dialer options (outbound base)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DialerOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_multi_path: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<String>,

    /// DNS server used to resolve the server's domain (1.12+, replaces `domain_strategy`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolver>,
}

/// Either a DNS server tag or a full resolver object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DomainResolver {
    Tag(String),
    Inline(DomainResolverOptions),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainResolverOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,
}
