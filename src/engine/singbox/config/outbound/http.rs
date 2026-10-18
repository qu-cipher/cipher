use crate::engine::singbox::config::shared::{DialerOptions, TlsOutbound};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsOutbound>,

    #[serde(flatten)]
    pub dial: DialerOptions,
}