use serde::{ Serialize, Deserialize };
use crate::engine::singbox::config::shared::ListenOptions;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MixedInbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(flatten)]
    pub listen: ListenOptions,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<MixedUser>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_system_proxy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedUser {
    pub username: String,
    pub password: String,
}
