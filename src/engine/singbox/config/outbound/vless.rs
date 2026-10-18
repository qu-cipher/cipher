use crate::engine::singbox::config::shared::{
    DialerOptions,
    Network,
    TransportOptions,
    MultiplexOptions,
    TlsOutbound
};
use serde::{ Serialize, Deserialize };

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VlessOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub uuid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<VlessFlow>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsOutbound>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexOptions>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlessFlow {
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}
