//! Adding a plugin: fetch its manifest, check the repository on GitHub, then download the
//! program from the repository's releases and check its SHA-256.
//!
//! Developer mode (`CIPHER_PLUGIN_DEV=1`): a manifest picked from a local folder may use a program
//! built in that folder (its `binary` path, relative to the manifest), without the GitHub and
//! checksum checks. Such plugins are marked "Development" in the app.

use super::{
    InstallRecord, Installed, Kind, MANIFEST_FILE, Manifest, OFFICIAL, OFFICIAL_SOURCE, binary_name, github_repo, official_text, plugins_dir,
    save_record,
};
use crate::engine::install::{download, file_sha256, verify_sha256};
use crate::engine::{paths, process::hide_console};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Turns on developer mode (local plugin folders without the release checks).
pub const DEV_ENV: &str = "CIPHER_PLUGIN_DEV";
const MANIFEST_LIMIT: u64 = 256 * 1024;
const USER_AGENT: &str = concat!("cipher_client/", env!("CARGO_PKG_VERSION"));

/// What the app found out about a plugin before installing it, shown in the add dialog.
#[derive(Debug, Clone)]
pub struct Review {
    pub manifest: Manifest,
    /// The manifest exactly as fetched (saved as is).
    pub text: String,
    pub source: String,
    pub official: bool,
    pub development: bool,
    /// Things the user should know but that don't block the install (archived repository, …).
    pub warnings: Vec<String>,
    /// The local folder the manifest came from (developer mode).
    local_dir: Option<PathBuf>,
}

pub fn dev_mode() -> bool {
    std::env::var_os(DEV_ENV).is_some_and(|v| v == "1")
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(20))).build().into()
}

fn get_text(url: &str) -> Result<String, String> {
    let mut response = agent()
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("couldn't download {url}: {e}"))?;
    response
        .body_mut()
        .with_config()
        .limit(MANIFEST_LIMIT)
        .read_to_string()
        .map_err(|e| format!("couldn't read {url}: {e}"))
}

/// What the user typed: a manifest URL, a GitHub repository (its `plugin.json` on the default
/// branch), or a local `plugin.json` / folder.
fn manifest_location(source: &str) -> Result<Location, String> {
    let source = source.trim();
    if let Some((owner, repo)) = github_repo(source.trim_end_matches('/')) {
        return Ok(Location::Url(format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{MANIFEST_FILE}")));
    }
    if source.starts_with("https://") {
        return Ok(Location::Url(source.to_owned()));
    }
    if source.starts_with("http://") {
        return Err("use an https:// link".into());
    }
    let path = PathBuf::from(source);
    let path = if path.is_dir() { path.join(MANIFEST_FILE) } else { path };
    match path.is_file() {
        true => Ok(Location::File(path)),
        false => Err("enter a plugin link, a GitHub repository, or pick a plugin.json".into()),
    }
}

enum Location {
    Url(String),
    File(PathBuf),
}

/// Fetches and checks everything before the user decides. Blocking: call it off the UI thread.
pub fn review(source: &str) -> Result<Review, String> {
    let (text, local_dir) = match manifest_location(source)? {
        Location::Url(url) => (get_text(&url)?, None),
        Location::File(path) => {
            let text = fs::read_to_string(&path).map_err(|e| format!("couldn't read {}: {e}", path.display()))?;
            (text, path.parent().map(Path::to_owned))
        }
    };
    let manifest = Manifest::parse(&text)?;
    // The exact text of a built-in manifest (e.g. added by its published URL).
    let official = OFFICIAL.contains(&text.as_str());

    // Developer mode: a local folder whose program is built right there.
    let development = local_dir.as_ref().is_some_and(|dir| {
        dev_mode() && manifest.asset().is_some_and(|asset| dir.join(&asset.binary).is_file())
    });
    if manifest.asset().is_none() && !development {
        return Err(format!("{} has no build for this system ({})", manifest.name, super::platform_key()));
    }

    let mut warnings = Vec::new();
    match development {
        true => warnings.push("Development plugin: the repository, license and checksum aren't checked.".into()),
        false => warnings.extend(check_repository(&manifest)?),
    }
    if cfg!(windows) {
        warnings.push("On Windows, Cipher runs as administrator, so every plugin does too.".into());
    }
    Ok(Review { manifest, text, source: source.trim().to_owned(), official, development, warnings, local_dir })
}

/// Reviews an official plugin from its built-in manifest (nothing to fetch but the repository check).
pub fn review_official(id: &str) -> Result<Review, String> {
    let text = official_text(id).ok_or_else(|| format!("`{id}` isn't an official plugin"))?;
    let manifest = Manifest::parse(text)?;
    if manifest.asset().is_none() {
        return Err(format!("{} has no build for this system ({})", manifest.name, super::platform_key()));
    }
    let mut warnings = check_repository(&manifest)?;
    if cfg!(windows) {
        warnings.push("On Windows, Cipher runs as administrator, so every plugin does too.".into());
    }
    let source = format!("{OFFICIAL_SOURCE}/{id}.json");
    Ok(Review { manifest, text: text.to_owned(), source, official: true, development: false, warnings, local_dir: None })
}

/// The repository must exist, be public, and carry the license the manifest claims.
fn check_repository(manifest: &Manifest) -> Result<Vec<String>, String> {
    let (owner, repo) = github_repo(&manifest.repository).ok_or("invalid repository")?;
    let api = format!("https://api.github.com/repos/{owner}/{repo}");
    let response = agent()
        .get(&api)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call();
    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(404)) => return Err(format!("{} doesn't exist or isn't public", manifest.repository)),
        Err(ureq::Error::StatusCode(403 | 429)) => return Err("GitHub's rate limit was hit; try again in a while".into()),
        Err(e) => return Err(format!("couldn't check the repository on GitHub: {e}")),
    };
    let body = response.body_mut().read_to_string().map_err(|e| format!("couldn't read GitHub's answer: {e}"))?;
    let info: Value = serde_json::from_str(&body).map_err(|e| format!("unexpected answer from GitHub: {e}"))?;
    repository_warnings(manifest, &info)
}

fn repository_warnings(manifest: &Manifest, info: &Value) -> Result<Vec<String>, String> {
    if info["private"].as_bool() != Some(false) {
        return Err(format!("{} isn't a public repository", manifest.repository));
    }
    let mut warnings = Vec::new();
    match info["license"]["spdx_id"].as_str() {
        None => return Err(format!("{} has no license file; plugins must be open source", manifest.repository)),
        Some("NOASSERTION") => warnings.push(format!(
            "GitHub couldn't identify the repository's license; the plugin says {}.",
            manifest.license
        )),
        Some(spdx) if !spdx.eq_ignore_ascii_case(&manifest.license) => {
            return Err(format!("the plugin says its license is {}, but the repository's is {spdx}", manifest.license));
        }
        Some(_) => {}
    }
    if info["archived"].as_bool() == Some(true) {
        warnings.push("The repository is archived: the plugin is no longer maintained.".into());
    }
    Ok(warnings)
}

/// Downloads, checks and installs a reviewed plugin, replacing an older version.
/// Blocking: call it off the UI thread.
pub fn install(data_dir: &Path, review: &Review, root_allowed: bool) -> Result<Installed, String> {
    let manifest = &review.manifest;
    let dir = plugins_dir(data_dir).join(&manifest.id);
    let staging = plugins_dir(data_dir).join(format!(".{}-staging", manifest.id));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;

    let result = (|| {
        let program = staging.join(binary_name(manifest));
        if review.development {
            let asset = manifest.asset().ok_or("no build for this system")?;
            let local = review.local_dir.as_ref().ok_or("no local folder")?.join(&asset.binary);
            fs::copy(&local, &program).map_err(|e| format!("couldn't copy {}: {e}", local.display()))?;
        } else {
            let asset = manifest.asset().ok_or("no build for this system")?;
            let file_name = asset.url.rsplit('/').next().unwrap_or("download");
            let download_path = staging.join(file_name);
            download(&asset.url, &download_path).map_err(|e| e.to_string())?;
            verify_sha256(&download_path, &asset.sha256).map_err(|e| e.to_string())?;
            extract(&download_path, &asset.binary, &staging, &program)?;
        }
        make_executable(&program)?;
        let sha256 = file_sha256(&program).map_err(|e| e.to_string())?;
        paths::write_private(&staging.join(MANIFEST_FILE), &review.text).map_err(|e| e.to_string())?;

        // Swap the new folder in only once everything worked.
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for name in [binary_name(manifest), MANIFEST_FILE.to_owned()] {
            fs::rename(staging.join(&name), dir.join(&name)).map_err(|e| e.to_string())?;
        }
        let record = InstallRecord {
            source: review.source.clone(),
            sha256,
            official: review.official,
            root_allowed: manifest.needs_root && root_allowed,
            development: review.development,
        };
        save_record(data_dir, &manifest.id, &record).map_err(|e| e.to_string())?;
        super::load(data_dir, &manifest.id)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// The program from the download: the file itself, or `binary` inside an archive.
fn extract(download: &Path, binary: &str, staging: &Path, to: &Path) -> Result<(), String> {
    let name = download.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if name.ends_with(".zip") {
        let file = fs::File::open(download).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("couldn't open the zip: {e}"))?;
        let mut entry = archive.by_name(binary).map_err(|_| format!("`{binary}` isn't in the download"))?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        return fs::write(to, bytes).map_err(|e| e.to_string());
    }
    if [".tar.gz", ".tgz", ".tar.xz", ".tar"].iter().any(|ext| name.ends_with(ext)) {
        let unpacked = staging.join("unpacked");
        fs::create_dir_all(&unpacked).map_err(|e| e.to_string())?;
        let mut command = Command::new("tar");
        command.arg("-xf").arg(download).arg("-C").arg(&unpacked);
        hide_console(&mut command);
        let output = command.output().map_err(|e| format!("couldn't run tar: {e}"))?;
        if !output.status.success() {
            return Err(format!("couldn't unpack the download: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        let found = unpacked.join(binary);
        if !found.is_file() {
            return Err(format!("`{binary}` isn't in the download"));
        }
        return fs::rename(found, to).map_err(|e| e.to_string());
    }
    fs::rename(download, to).map_err(|e| e.to_string())
}

fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let _ = path;
    Ok(())
}

/// Removes an installed plugin. Configs that use it stay, and say so when connecting.
pub fn remove(data_dir: &Path, id: &str) -> Result<(), String> {
    let dir = plugins_dir(data_dir).join(id);
    if !super::valid_id(id) || !dir.is_dir() {
        return Err(format!("the plugin `{id}` isn't installed"));
    }
    fs::remove_dir_all(dir).map_err(|e| e.to_string())
}

/// What the add dialog should say about the plugin's kind.
pub fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Transport => "Transport",
        Kind::Engine => "Engine",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::tests::{engine, transport};
    use serde_json::json;

    #[test]
    fn repository_checks() {
        let manifest = transport();
        let public = json!({ "private": false, "archived": false, "license": { "spdx_id": "MIT" } });
        assert!(repository_warnings(&manifest, &public).unwrap().is_empty());

        let private = json!({ "private": true, "license": { "spdx_id": "MIT" } });
        assert!(repository_warnings(&manifest, &private).unwrap_err().contains("public"));
        let unlicensed = json!({ "private": false, "license": null });
        assert!(repository_warnings(&manifest, &unlicensed).unwrap_err().contains("no license"));
        let other = json!({ "private": false, "license": { "spdx_id": "GPL-3.0" } });
        assert!(repository_warnings(&manifest, &other).unwrap_err().contains("GPL-3.0"));

        let odd = json!({ "private": false, "archived": true, "license": { "spdx_id": "NOASSERTION" } });
        assert_eq!(repository_warnings(&manifest, &odd).unwrap().len(), 2);
    }

    #[test]
    fn manifest_locations() {
        let Location::Url(url) = manifest_location("https://github.com/example/myproto/").unwrap() else { panic!() };
        assert_eq!(url, "https://raw.githubusercontent.com/example/myproto/HEAD/plugin.json");
        let Location::Url(url) = manifest_location(" https://example.com/p/plugin.json ").unwrap() else { panic!() };
        assert_eq!(url, "https://example.com/p/plugin.json");
        assert!(manifest_location("http://example.com/plugin.json").is_err());
        assert!(manifest_location("/nonexistent/plugin.json").is_err());
    }

    /// The real install path without the network: a development plugin from a local folder,
    /// and an archive download handled by `extract`.
    #[test]
    fn installs_and_removes_a_development_plugin() {
        let root = std::env::temp_dir().join(format!("cipher_plugin_install_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (source, data) = (root.join("src"), root.join("data"));
        fs::create_dir_all(source.join("myproto")).unwrap();
        fs::create_dir_all(&data).unwrap();

        let mut manifest = engine();
        manifest.needs_root = false;
        let text = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(source.join("plugin.json"), &text).unwrap();
        fs::write(source.join("myproto").join("x"), "").unwrap();
        fs::write(source.join("myproto-bin"), "#!/bin/sh\necho listening\n").unwrap();
        for asset in manifest.assets.values_mut() {
            asset.binary = "myproto-bin".into();
        }
        let text = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(source.join("plugin.json"), &text).unwrap();

        let review = Review {
            manifest: manifest.clone(),
            text,
            source: source.display().to_string(),
            official: false,
            development: true,
            warnings: Vec::new(),
            local_dir: Some(source.clone()),
        };
        let installed = install(&data, &review, false).unwrap();
        assert!(installed.binary.is_file());
        assert!(installed.record.development && !installed.record.root_allowed);
        assert_eq!(crate::plugin::installed(&data).len(), 1);

        remove(&data, "myproto").unwrap();
        assert!(crate::plugin::installed(&data).is_empty());
        assert!(remove(&data, "myproto").is_err());

        // A zip with the program in a sub folder.
        let zip_path = root.join("p.zip");
        {
            let mut writer = zip::ZipWriter::new(fs::File::create(&zip_path).unwrap());
            writer.start_file("dist/prog", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut writer, b"binary").unwrap();
            writer.finish().unwrap();
        }
        let out = root.join("prog");
        extract(&zip_path, "dist/prog", &root, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"binary");
        assert!(extract(&zip_path, "nope", &root, &out).unwrap_err().contains("isn't in the download"));
        fs::remove_dir_all(&root).unwrap();
    }
}
