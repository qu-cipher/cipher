use crate::engine::singbox::config::shared::{DialerOptions, MultiplexOptions, Network};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShadowsocksOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub method: ShadowsocksMethod,
    pub password: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexOptions>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowsocksMethod {
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-192-gcm")]
    Aes192Gcm,
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    Xchacha20IetfPoly1305,
}
