use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Experimental {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFile>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApi>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_fakeip: Option<bool>,
}

/// Used later for latency tests and switching selector outbounds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClashApi {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,
}
