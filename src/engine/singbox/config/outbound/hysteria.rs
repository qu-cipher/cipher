use crate::engine::singbox::config::shared::{DialerOptions, TlsOutbound, Hysteria2Obfs};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hysteria2Outbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub password: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ports: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsOutbound>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_debug: Option<bool>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}