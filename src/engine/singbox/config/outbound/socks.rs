use crate::engine::singbox::config::shared::{DialerOptions, Network};
use serde::{ Serialize, Deserialize };

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SocksOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<bool>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}