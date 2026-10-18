use serde::{ Serialize, Deserialize };
use std::collections::HashMap;

// V2Ray transport. Plain TCP has no transport object: leave `transport` unset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportOptions {
    Http(HttpTransport),
    Ws(WsTransport),
    Quic(QuicTransport),
    Grpc(GrpcTransport),
    HttpUpgrade(HttpUpgradeTransport),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_timeout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicTransport {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrpcTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_timeout: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_without_stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpUpgradeTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}
