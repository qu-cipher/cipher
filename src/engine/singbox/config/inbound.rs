use serde::{Deserialize, Serialize};
use crate::engine::singbox::config::inbound::{
    tun::TunInbound,
    mixed::MixedInbound,
};

pub mod tun;
pub mod mixed;

// Client-side inbounds only: TUN captures system traffic,
// mixed exposes an optional local SOCKS/HTTP proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Inbound {
    Tun(TunInbound),
    Mixed(MixedInbound),
}
