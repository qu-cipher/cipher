use serde::{ Serialize, Deserialize };

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunInbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<TunStack>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_mode: Option<DnsMode>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_address: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_route: Option<bool>,

    /// Linux only: use nftables instead of ip rules for better performance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_redirect: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_route: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_address: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_exclude_address: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_interface: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_interface: Option<Vec<String>>,

    // Linux only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_uid: Option<Vec<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_uid: Option<Vec<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gso: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    Disabled,
    Native,
    Hijack,
}

/// How TUN packets become connections. `system` and `mixed` hand TCP to the kernel,
/// where host firewalls (ufw, firewalld, Windows Firewall) can drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    System,
    Gvisor,
    Mixed,
}
