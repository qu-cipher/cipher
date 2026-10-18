use crate::engine::singbox::config::shared::DialerOptions;
use serde::{ Serialize, Deserialize };

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectOutbound {
    pub tag: String,

    #[serde(flatten)]
    pub dial: DialerOptions,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<u8>,
}