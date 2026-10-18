use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Obfs {
    /// Only "salamander" is supported by sing-box.
    #[serde(rename = "type")]
    pub obfs_type: String,
    pub password: String,
}
