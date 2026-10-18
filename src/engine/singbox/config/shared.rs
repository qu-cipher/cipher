use serde::{Deserialize, Serialize};

pub mod transport;
pub mod dial;
pub mod multiplex;
pub mod tls;
pub mod hysteria;

pub use dial::{DialerOptions, DomainResolver, ListenOptions};
pub use transport::TransportOptions;
pub use multiplex::MultiplexOptions;
pub use tls::TlsOutbound;
pub use hysteria::Hysteria2Obfs;

/// Restricts an outbound/rule to one network. Unset = both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}
