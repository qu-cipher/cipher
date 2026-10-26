//! Turns share links, subscription bodies and config files into [`Profile`]s.

use base64::{Engine, engine::general_purpose::{STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT}};

pub mod uri;
pub mod link;
pub mod wireguard;
pub mod openvpn;
pub mod psiphon;
pub mod xray;
pub mod subscription;
pub mod singbox_json;

pub use link::parse_link;
pub use wireguard::parse_wireguard_conf;
pub use openvpn::{import_openvpn, needs_credentials};
pub use subscription::{Subscription, Usage, fetch_subscription, parse_links};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("unsupported link type `{0}`")]
    UnsupportedScheme(String),

    #[error("unsupported {0}")]
    Unsupported(String),

    #[error("missing {0}")]
    Missing(&'static str),

    #[error("invalid {0}")]
    Invalid(String),

    #[error("no usable configs found")]
    Empty,

    #[error("download failed: {0}")]
    Http(#[from] Box<ureq::Error>),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Decodes base64 in any of the variants found in the wild:
/// standard or URL-safe alphabet, with or without padding, wrapped across lines.
pub(crate) fn decode_base64(input: &str) -> Option<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD_PAD_INDIFFERENT
        .decode(&compact)
        .or_else(|_| URL_SAFE_PAD_INDIFFERENT.decode(&compact))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}
