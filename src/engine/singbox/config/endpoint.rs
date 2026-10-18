use crate::engine::singbox::config::shared::DialerOptions;
use serde::{Serialize, Deserialize};

/// Endpoints are protocols that act as both inbound and outbound (1.11+).
/// Their tag can be used anywhere an outbound tag is accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Endpoint {
    Wireguard(WireguardEndpoint),
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WireguardEndpoint {
    pub tag: String,

    /// Use the system WireGuard interface instead of the userspace one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<bool>,

    /// Interface name, only used with `system`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    /// Interface addresses (the `Address` line of a wg .conf).
    pub address: Vec<String>,

    pub private_key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    pub peers: Vec<WireguardPeer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<u32>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WireguardPeer {
    pub address: String,
    pub port: u16,

    pub public_key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,

    pub allowed_ips: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_interval: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Vec<u8>>,
}
