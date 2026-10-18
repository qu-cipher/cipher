use crate::engine::singbox::config::shared::{
    DialerOptions,
    TransportOptions,
    MultiplexOptions,
    TlsOutbound
};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmessOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub uuid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_padding: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_length: Option<bool>,

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