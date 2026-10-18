use crate::engine::singbox::config::shared::{DialerOptions, Network, TlsOutbound};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TuicOutbound {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub uuid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// "cubic" (default), "new_reno" or "bbr".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,

    /// "native" (default) or "quic".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_over_stream: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub zero_rtt_handshake: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,

    /// Required: TUIC runs over QUIC.
    pub tls: TlsOutbound,

    #[serde(flatten)]
    pub dial: DialerOptions,
}
