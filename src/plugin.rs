//! Plugins: separate programs described by a `plugin.json` manifest, never code loaded into the app.
//!
//! - A **transport** plugin is a local forwarder under an existing config (SNI spoofing, DNS
//!   tunnels): it listens on `127.0.0.1:{listen_port}`, and the config dials that instead of its server.
//! - An **engine** plugin is someone's own VPN core: it serves SOCKS5 on `127.0.0.1:{listen_port}`,
//!   with sing-box in front (see `engine::chain`), so every mode and the routing rules work.
//!
//! Plugins must be open source: a GitHub repository, a license, and release assets with SHA-256
//! checksums (checked in [`install`]). The developer guide is `docs/plugins.md`.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{LazyLock, RwLock},
};

pub mod install;

/// Manifest format version this app understands.
pub const API_VERSION: u32 = 1;
/// The manifest's file name, in a plugin folder and in a plugin's repository.
pub const MANIFEST_FILE: &str = "plugin.json";
/// What the app records about an installed plugin, next to its manifest.
const INSTALL_FILE: &str = "install.json";

/// Official plugins, pinned in the app: (manifest URL, SHA-256 of the manifest).
/// Only a Cipher release can add to this list, which is what makes a plugin "official".
pub const OFFICIAL: &[(&str, &str)] = &[];

/// Link schemes the app parses itself; plugins can't claim them.
const BUILT_IN_SCHEMES: [&str; 15] = [
    "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "anytls", "wireguard", "wg", "ovpn",
    "openvpn", "psiphon", "http", "https",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub api: u32,
    /// Lowercase letters, digits and `-`; also the plugin's folder name.
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// `https://github.com/<owner>/<repo>`: the plugin's source code.
    pub repository: String,
    /// SPDX license id, e.g. `MIT`, `GPL-3.0-only`.
    pub license: String,
    /// Per platform (`linux-x86_64`, `linux-aarch64`, `windows-x86_64`, …): where to get the program.
    pub assets: BTreeMap<String, Asset>,
    /// Command-line arguments, with placeholders.
    #[serde(default)]
    pub args: Vec<String>,
    /// Text written to `{config_file}` before the plugin starts, with placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_template: Option<String>,
    /// File name for `{config_file}` (some programs care about the extension).
    #[serde(default = "default_config_name")]
    pub config_file_name: String,
    /// When the plugin is ready to carry traffic.
    pub ready: Ready,
    /// What the plugin forwards (transports: what the config needs; engines: what its SOCKS proxy relays).
    pub network: Network,
    /// The plugin needs administrator rights (raw sockets, routes). The user has to allow it separately.
    #[serde(default)]
    pub needs_root: bool,
    /// Engine plugins: link schemes it accepts (`myproto://…`). The whole link is passed as `{link}`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemes: Vec<String>,
    /// Per-config settings the user fills in; used as `{field.<key>}`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
}

fn default_config_name() -> String {
    "config".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Transport,
    Engine,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// A release download of `repository`: `<repository>/releases/download/<tag>/<file>`.
    pub url: String,
    pub sha256: String,
    /// The program: the file itself, or its path inside a `.zip`/`.tar.gz`/`.tgz`/`.tar.xz` download.
    pub binary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Ready {
    /// `{listen_port}` accepts TCP connections.
    Port(bool),
    /// The plugin's output contains this text.
    Log(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// Lowercase letters, digits and `_`.
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: FieldKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default: String,
    #[serde(default)]
    pub required: bool,
    /// `select` fields: the choices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Number,
    Bool,
    Select,
}

/// A transport plugin chosen for a config (stored with the config), with its field values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportUse {
    pub plugin: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

/// What the app records when it installs a plugin (`install.json` in the plugin folder).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallRecord {
    /// Where the manifest came from (a URL, or a local path in developer mode).
    pub source: String,
    /// SHA-256 of the program as installed.
    pub sha256: String,
    pub official: bool,
    /// The user allowed this plugin to run as administrator (only asked when `needs_root`).
    pub root_allowed: bool,
    /// Installed from a local folder with `CIPHER_PLUGIN_DEV=1`, without the release checks.
    #[serde(default)]
    pub development: bool,
}

/// An installed plugin: its manifest, install record and program path.
#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub manifest: Manifest,
    pub record: InstallRecord,
    pub binary: PathBuf,
}

impl Installed {
    /// Whether it may run now: plugins that need root only once the user allowed it.
    pub fn usable(&self) -> bool {
        !self.manifest.needs_root || self.record.root_allowed
    }
}

/// `<data>/plugins`
pub fn plugins_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("plugins")
}

/// The platform key for `assets`, e.g. `linux-x86_64`.
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `https://github.com/<owner>/<repo>` → `(owner, repo)`.
pub fn github_repo(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://github.com/")?;
    let (owner, repo) = rest.split_once('/')?;
    let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    (ok(owner) && ok(repo)).then_some((owner, repo))
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self, String> {
        let manifest: Manifest = serde_json::from_str(text).map_err(|e| format!("not a valid {MANIFEST_FILE}: {e}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Checks everything that doesn't need the network.
    pub fn validate(&self) -> Result<(), String> {
        if self.api != API_VERSION {
            return Err(format!("needs plugin API {}, this app supports {API_VERSION}: update Cipher", self.api));
        }
        if !valid_id(&self.id) {
            return Err(format!("invalid id `{}` (lowercase letters, digits and -, at most 32)", self.id));
        }
        for (what, value) in [("name", &self.name), ("version", &self.version), ("license", &self.license)] {
            if value.trim().is_empty() {
                return Err(format!("{what} is missing"));
            }
        }
        if github_repo(&self.repository).is_none() {
            return Err("repository must be a GitHub repository URL (https://github.com/<owner>/<repo>)".into());
        }
        if self.assets.is_empty() {
            return Err("no assets".into());
        }
        let releases = format!("{}/releases/download/", self.repository);
        for (platform, asset) in &self.assets {
            if !asset.url.starts_with(&releases) {
                return Err(format!("{platform}: the asset must be a release download of {}", self.repository));
            }
            if asset.sha256.len() != 64 || !asset.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{platform}: sha256 must be 64 hex digits"));
            }
            let binary = Path::new(&asset.binary);
            if asset.binary.is_empty() || binary.is_absolute() || asset.binary.split(['/', '\\']).any(|part| part == "..") {
                return Err(format!("{platform}: binary must be a relative path"));
            }
        }
        if self.config_file_name.is_empty() || self.config_file_name.contains(['/', '\\']) || self.config_file_name.starts_with('.') {
            return Err("config_file_name must be a plain file name".into());
        }
        if let Ready::Log(text) = &self.ready && text.is_empty() {
            return Err("ready.log must not be empty".into());
        }

        let mut keys = Vec::new();
        for field in &self.fields {
            if !valid_key(&field.key) {
                return Err(format!("invalid field key `{}` (lowercase letters, digits and _)", field.key));
            }
            if keys.contains(&field.key.as_str()) {
                return Err(format!("field `{}` is listed twice", field.key));
            }
            keys.push(&field.key);
            if field.kind == FieldKind::Select && field.options.is_empty() {
                return Err(format!("select field `{}` has no options", field.key));
            }
        }

        match self.kind {
            Kind::Transport if !self.schemes.is_empty() => return Err("only engine plugins can have schemes".into()),
            Kind::Engine => {
                for scheme in &self.schemes {
                    let ok = !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b));
                    if !ok {
                        return Err(format!("invalid scheme `{scheme}`"));
                    }
                    if BUILT_IN_SCHEMES.contains(&scheme.as_str()) {
                        return Err(format!("`{scheme}` links are handled by the app itself"));
                    }
                }
            }
            _ => {}
        }

        // Placeholders: only the ones this kind gets, and declared fields.
        let template = self.config_template.as_deref().into_iter();
        for text in self.args.iter().map(String::as_str).chain(template) {
            for name in placeholders(text) {
                let known = match name.strip_prefix("field.") {
                    Some(key) => keys.contains(&key),
                    None => match name {
                        "listen_port" | "data_dir" => true,
                        "config_file" => self.config_template.is_some(),
                        "server" | "server_port" => self.kind == Kind::Transport,
                        "link" => self.kind == Kind::Engine,
                        _ => false,
                    },
                };
                if !known {
                    return Err(format!("unknown placeholder `{{{name}}}`"));
                }
            }
        }
        if !self.args.iter().any(|a| a.contains("{listen_port}"))
            && !self.config_template.as_deref().is_some_and(|t| t.contains("{listen_port}"))
        {
            return Err("{listen_port} must appear in args or config_template".into());
        }
        Ok(())
    }

    pub fn asset(&self) -> Option<&Asset> {
        self.assets.get(&platform_key())
    }

    /// Checks a config's field values: required ones are set, numbers and bools parse, selects match.
    /// Missing values get their defaults.
    pub fn fill_fields(&self, values: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
        let mut filled = BTreeMap::new();
        for field in &self.fields {
            let value = values.get(&field.key).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
            let value = value.unwrap_or_else(|| field.default.clone());
            if value.is_empty() {
                if field.required {
                    return Err(format!("{} is required", field.label));
                }
            } else {
                let ok = match field.kind {
                    FieldKind::Text => true,
                    FieldKind::Number => value.parse::<f64>().is_ok(),
                    FieldKind::Bool => value == "true" || value == "false",
                    FieldKind::Select => field.options.contains(&value),
                };
                if !ok {
                    return Err(format!("{}: `{value}` isn't valid", field.label));
                }
            }
            filled.insert(field.key.clone(), value);
        }
        Ok(filled)
    }
}

/// A placeholder at the start of `text`: `{name}` or `{name:json}`, where the name is lowercase
/// letters, digits, `_` and `.`. Returns (name, json, length). Any other `{` is a literal brace,
/// so JSON templates need no escaping.
fn placeholder_at(text: &str) -> Option<(&str, bool, usize)> {
    let inner = &text[1..text.find('}')?];
    let (name, json) = match inner.strip_suffix(":json") {
        Some(name) => (name, true),
        None => (inner, false),
    };
    let ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');
    ok.then_some((name, json, inner.len() + 2))
}

/// The placeholder names in a text.
fn placeholders(text: &str) -> Vec<&str> {
    text.match_indices('{').filter_map(|(i, _)| placeholder_at(&text[i..]).map(|(name, ..)| name)).collect()
}

/// Values for the placeholders when a plugin starts.
pub type Values = HashMap<String, String>;

/// Fills in placeholders: `{name}` as is, `{name:json}` as a JSON string (with quotes).
pub fn render(text: &str, values: &Values) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        match placeholder_at(&rest[start..]) {
            Some((name, json, len)) => {
                let value = values.get(name).ok_or_else(|| format!("no value for `{{{name}}}`"))?;
                match json {
                    true => out.push_str(&serde_json::to_string(value).unwrap_or_default()),
                    false => out.push_str(value),
                }
                rest = &rest[start + len..];
            }
            None => {
                out.push('{');
                rest = &rest[start + 1..];
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Field values as placeholder values (`field.<key>`).
pub fn field_values(fields: &BTreeMap<String, String>) -> Values {
    fields.iter().map(|(k, v)| (format!("field.{k}"), v.clone())).collect()
}

// ───────────────────────────── Installed plugins ─────────────────────────────

/// Reads one installed plugin from `<data>/plugins/<id>`.
pub fn load(data_dir: &Path, id: &str) -> Result<Installed, String> {
    if !valid_id(id) {
        return Err(format!("invalid plugin id `{id}`"));
    }
    let dir = plugins_dir(data_dir).join(id);
    let text = fs::read_to_string(dir.join(MANIFEST_FILE)).map_err(|_| format!("the plugin `{id}` isn't installed"))?;
    let manifest: Manifest = serde_json::from_str(&text).map_err(|e| format!("plugin `{id}`: {e}"))?;
    let record = fs::read_to_string(dir.join(INSTALL_FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<InstallRecord>(&text).ok())
        .ok_or_else(|| format!("plugin `{id}` is incomplete: install it again"))?;
    let binary = dir.join(binary_name(&manifest));
    Ok(Installed { manifest, record, binary })
}

/// Every installed plugin, sorted by name. Broken folders are skipped.
pub fn installed(data_dir: &Path) -> Vec<Installed> {
    let Ok(entries) = fs::read_dir(plugins_dir(data_dir)) else { return Vec::new() };
    let mut plugins: Vec<Installed> = entries
        .flatten()
        .filter_map(|entry| load(data_dir, &entry.file_name().to_string_lossy()).ok())
        .collect();
    plugins.sort_by_key(|p| p.manifest.name.to_lowercase());
    plugins
}

/// The program's file name in the plugin folder: `cipher-plugin-<id>` (plus `.exe` on Windows),
/// whatever the download called it. Its process name is then predictable for the direct-routing rule.
pub fn binary_name(manifest: &Manifest) -> String {
    format!("cipher-plugin-{}{}", manifest.id, std::env::consts::EXE_SUFFIX)
}

pub fn save_record(data_dir: &Path, id: &str, record: &InstallRecord) -> std::io::Result<()> {
    let path = plugins_dir(data_dir).join(id).join(INSTALL_FILE);
    fs::write(path, serde_json::to_string_pretty(record)?)
}

/// Link schemes claimed by installed engine plugins: scheme → plugin id.
static SCHEMES: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(Default::default);

/// Refreshes the scheme table from the installed plugins (on start and after installs/removals).
pub fn register_schemes(plugins: &[Installed]) {
    let table = plugins
        .iter()
        .filter(|p| p.manifest.kind == Kind::Engine)
        .flat_map(|p| p.manifest.schemes.iter().map(|s| (s.clone(), p.manifest.id.clone())))
        .collect();
    *SCHEMES.write().unwrap() = table;
}

/// The engine plugin that handles `scheme` links, if one is installed.
pub fn scheme_owner(scheme: &str) -> Option<String> {
    SCHEMES.read().unwrap().get(&scheme.to_ascii_lowercase()).cloned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Tests that change the global scheme table take this first.
    pub(crate) static SCHEMES_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    pub(crate) fn transport() -> Manifest {
        Manifest::parse(&format!(r#"{{
            "api": 1, "id": "dns-tunnel", "name": "DNS Tunnel", "kind": "transport", "version": "1.0.0",
            "repository": "https://github.com/example/dns-tunnel", "license": "MIT",
            "assets": {{ "{platform}": {{ "url": "https://github.com/example/dns-tunnel/releases/download/v1.0.0/dt.tar.gz", "sha256": "{SHA}", "binary": "dt/dns-tunnel" }} }},
            "args": ["-c", "{{config_file}}"],
            "config_template": "{{\"listen\": \"127.0.0.1:{{listen_port}}\", \"domain\": {{field.domain:json}}, \"target\": \"{{server}}:{{server_port}}\"}}",
            "config_file_name": "config.json",
            "ready": {{ "port": true }},
            "network": "tcp",
            "fields": [
                {{ "key": "domain", "label": "Tunnel domain", "type": "text", "required": true }},
                {{ "key": "resolvers", "label": "Resolvers", "type": "select", "options": ["system", "public"], "default": "public" }}
            ]
        }}"#, platform = platform_key())).unwrap()
    }

    pub(crate) fn engine() -> Manifest {
        Manifest::parse(&format!(r#"{{
            "api": 1, "id": "myproto", "name": "MyProto", "kind": "engine", "version": "0.2.0",
            "repository": "https://github.com/example/myproto", "license": "Apache-2.0",
            "assets": {{ "{platform}": {{ "url": "https://github.com/example/myproto/releases/download/v0.2.0/myproto", "sha256": "{SHA}", "binary": "myproto" }} }},
            "args": ["--socks", "127.0.0.1:{{listen_port}}", "--link", "{{link}}"],
            "ready": {{ "log": "listening" }},
            "network": "both",
            "needs_root": true,
            "schemes": ["myproto"]
        }}"#, platform = platform_key())).unwrap()
    }

    #[test]
    fn valid_manifests_parse() {
        assert_eq!(transport().kind, Kind::Transport);
        assert_eq!(transport().config_file_name, "config.json");
        assert_eq!(engine().ready, Ready::Log("listening".into()));
        assert!(engine().needs_root);
        assert_eq!(github_repo("https://github.com/example/myproto"), Some(("example", "myproto")));
        assert_eq!(github_repo("https://gitlab.com/example/myproto"), None);
        assert_eq!(github_repo("https://github.com/example/myproto/tree/main"), None);
    }

    #[test]
    fn invalid_manifests_are_refused() {
        let broken = |change: fn(&mut Manifest)| {
            let mut manifest = transport();
            change(&mut manifest);
            manifest.validate().unwrap_err()
        };
        assert!(broken(|m| m.api = 2).contains("update Cipher"));
        assert!(broken(|m| m.id = "Bad Id".into()).contains("invalid id"));
        assert!(broken(|m| m.license = " ".into()).contains("license"));
        assert!(broken(|m| m.repository = "https://example.com/x".into()).contains("GitHub"));
        assert!(broken(|m| m.assets.values_mut().for_each(|a| a.url = "https://evil.example/x".into())).contains("release download"));
        assert!(broken(|m| m.assets.values_mut().for_each(|a| a.url = "https://github.com/other/repo/releases/download/v1/x".into())).contains("release download"));
        assert!(broken(|m| m.assets.values_mut().for_each(|a| a.sha256 = "abc".into())).contains("sha256"));
        assert!(broken(|m| m.assets.values_mut().for_each(|a| a.binary = "../../bin/sh".into())).contains("relative"));
        assert!(broken(|m| m.args.push("{link}".into())).contains("unknown placeholder"));
        assert!(broken(|m| m.args.push("{field.nope}".into())).contains("unknown placeholder"));
        assert!(broken(|m| m.schemes.push("x".into())).contains("only engine"));
        assert!(broken(|m| m.config_template = None).contains("unknown placeholder `{config_file}`"));

        let mut engine = engine();
        engine.schemes = vec!["vless".into()];
        assert!(engine.validate().unwrap_err().contains("handled by the app"));
        let mut engine = self::engine();
        engine.args = vec!["--link".into(), "{link}".into()];
        assert!(engine.validate().unwrap_err().contains("{listen_port}"));
        assert!(Manifest::parse(r#"{ "api": 1, "surprise": true }"#).is_err());
    }

    #[test]
    fn renders_placeholders() {
        let values: Values = [("listen_port", "40123"), ("field.domain", "t.example.com\"x"), ("server", "1.2.3.4"), ("server_port", "443")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let template = transport().config_template.unwrap();
        assert_eq!(
            render(&template, &values).unwrap(),
            r#"{"listen": "127.0.0.1:40123", "domain": "t.example.com\"x", "target": "1.2.3.4:443"}"#
        );
        assert_eq!(render("{ \"a\": {listen_port} } {Not-A-Placeholder}", &values).unwrap(), "{ \"a\": 40123 } {Not-A-Placeholder}");
        assert!(render("{missing}", &values).is_err());
    }

    #[test]
    fn fills_and_checks_fields() {
        let manifest = transport();
        assert_eq!(manifest.fill_fields(&BTreeMap::new()).unwrap_err(), "Tunnel domain is required");
        let filled = manifest.fill_fields(&BTreeMap::from([("domain".into(), " t.example.com ".into())])).unwrap();
        assert_eq!(filled["domain"], "t.example.com");
        assert_eq!(filled["resolvers"], "public");
        let bad = BTreeMap::from([("domain".into(), "x".into()), ("resolvers".into(), "mine".into())]);
        assert!(manifest.fill_fields(&bad).unwrap_err().contains("isn't valid"));
    }

    #[test]
    fn engine_plugins_claim_schemes() {
        let _lock = SCHEMES_LOCK.lock().unwrap();
        let record = InstallRecord { source: String::new(), sha256: SHA.into(), official: false, root_allowed: false, development: false };
        let plugin = Installed { manifest: engine(), record, binary: PathBuf::new() };
        assert!(!plugin.usable());
        register_schemes(&[plugin]);
        assert_eq!(scheme_owner("MyProto").as_deref(), Some("myproto"));
        assert_eq!(scheme_owner("vless"), None);
        register_schemes(&[]);
    }
}
