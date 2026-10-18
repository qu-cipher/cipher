use crate::engine::singbox::config::shared::{DialerOptions, TlsOutbound};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnyTlsOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub password: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_session_check_interval: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_session_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_idle_session: Option<u32>,

    /// Required.
    pub tls: TlsOutbound,

    #[serde(flatten)]
    pub dial: DialerOptions,
}
