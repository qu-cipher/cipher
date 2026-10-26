use crate::profile::{Profile, Settings};

pub mod chain;
pub mod elevated;
pub mod install;
pub mod paths;
pub mod process;
pub mod singbox;
pub mod openvpn;
pub mod plugin;
pub mod psiphon;
pub mod xray;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    SingBox,
    OpenVpn,
    /// Psiphon's client, chained behind sing-box.
    Psiphon,
    /// Xray-core, chained behind sing-box.
    Xray,
    /// An engine plugin, chained behind sing-box.
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Stopped,
    Running,
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("`{0}` was not found next to the app or in PATH")]
    BinaryNotFound(String),

    #[error("this profile needs the {0:?} engine")]
    WrongEngine(EngineKind),

    #[error("this OpenVPN config needs a username and password")]
    CredentialsRequired,

    #[error("OpenVPN configs only work in Tunnel mode")]
    TunnelOnly,

    #[error("the engine is already running")]
    AlreadyRunning,

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("couldn't install the engine: {0}")]
    Install(String),

    #[error("{0}")]
    Plugin(String),


    #[error("could not determine the app data directory")]
    NoDataDir,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// A VPN backend that runs a profile in a child process.
pub trait Engine {
    fn start(&mut self, profile: &Profile, settings: &Settings) -> Result<(), EngineError>;
    fn stop(&mut self) -> Result<(), EngineError>;
    fn status(&mut self) -> Status;

    /// Whether the tunnel is actually up (some engines keep connecting after the process starts).
    fn ready(&mut self) -> bool {
        true
    }

    /// False while the engine waits for the admin password (Tunnel mode on Linux).
    fn authorized(&mut self) -> bool {
        true
    }

    /// Help from a transport plugin running under this engine; call before `start`.
    fn assist(&mut self, _assist: Assist) {}
}

/// What a transport plugin passes to the engine above it.
#[derive(Clone, Default)]
pub struct Assist {
    /// The admin helper the plugin runs in: sing-box's TUN joins it (one password prompt).
    pub elevated: Option<std::sync::Arc<elevated::Elevated>>,
    /// Process names sing-box routes direct (the plugin's own connections).
    pub direct_processes: Vec<String>,
}

impl EngineKind {
    /// Whether sing-box serves the connection (and with it the local proxy and routing rules).
    pub fn runs_singbox(self) -> bool {
        matches!(self, EngineKind::SingBox | EngineKind::Psiphon | EngineKind::Xray | EngineKind::Plugin)
    }
}

/// The engine for a config with these settings: its own, or a core plugin (see `plugin::runs_on_core`).
pub fn kind_for(profile: &Profile, settings: &Settings) -> EngineKind {
    match plugin::runs_on_core(profile, settings) {
        true => EngineKind::Plugin,
        false => profile.engine_kind(),
    }
}

pub fn engine_for(kind: EngineKind) -> Box<dyn Engine + Send> {
    match kind {
        EngineKind::SingBox => Box::new(singbox::SingBoxEngine::default()),
        EngineKind::OpenVpn => Box::new(openvpn::OpenVpnEngine::default()),
        EngineKind::Psiphon => Box::new(psiphon::PsiphonEngine::default()),
        EngineKind::Xray => Box::new(xray::XrayEngine::default()),
        EngineKind::Plugin => Box::new(plugin::PluginEngine::default()),
    }
}
