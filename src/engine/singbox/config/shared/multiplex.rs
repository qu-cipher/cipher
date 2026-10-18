use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiplexOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// "smux", "yamux" or "h2mux".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_streams: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal: Option<BrutalOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrutalOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u64>,
}
