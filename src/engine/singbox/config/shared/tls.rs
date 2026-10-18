use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsOutbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sni: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityOutbound>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub utls: Option<UtlsOutbound>,

    /// Split the TLS handshake into multiple TCP segments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_fallback_delay: Option<String>,

    /// Split the TLS handshake into multiple TLS records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_fragment: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityOutbound {
    pub enabled: bool,
    pub public_key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtlsOutbound {
    pub enabled: bool,
    pub fingerprint: UtlsFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UtlsFingerprint {
    Chrome,
    Firefox,
    Edge,
    Safari,
    #[serde(rename = "360")]
    Qihoo360,
    Qq,
    Ios,
    Android,
    Random,
    Randomized,
}
