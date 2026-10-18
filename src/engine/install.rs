//! Finds the engine binaries, reports their versions, and installs sing-box.
//!
//! sing-box is downloaded from the official GitHub release, pinned to the version the generated
//! configs are tested against, and checked against the release's SHA-256 before it is used.

use crate::engine::{EngineError, paths, process::hide_console};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub const SINGBOX_VERSION: &str = "1.14.3";

/// Official release archives: (file name suffix, SHA-256 from GitHub's asset digests).
const SINGBOX_ASSETS: [(&str, &str); 4] = [
    ("linux-amd64.tar.gz", "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"),
    ("linux-arm64.tar.gz", "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e"),
    ("windows-amd64.zip", "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518"),
    ("windows-arm64.zip", "195b35424c6e3f5913954c7f08c5d8ba2d2199f6d18eb27a3972a5a29cdaa78c"),
];
const DOWNLOAD_LIMIT: u64 = 200 * 1024 * 1024;

pub struct EngineInfo {
    pub path: PathBuf,
    pub version: String,
}

/// Locates an engine and asks it for its version (`sing-box version`, `openvpn --version`).
pub fn installed(name: &str) -> Option<EngineInfo> {
    let path = paths::find_binary(name).ok()?;
    let flag = if name == "openvpn" { "--version" } else { "version" };
    let mut command = Command::new(&path);
    command.arg(flag);
    hide_console(&mut command);
    let output = command.output().ok()?;

    // "sing-box version 1.14.3" / "OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL …]"
    let text = String::from_utf8_lossy(&output.stdout);
    let version = text
        .lines()
        .next()?
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))?
        .to_owned();
    Some(EngineInfo { path, version })
}

/// The release archive for this OS/CPU: (file name suffix, SHA-256).
fn platform_asset() -> Option<(&'static str, &'static str)> {
    let suffix = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64.tar.gz",
        ("linux", "aarch64") => "linux-arm64.tar.gz",
        ("windows", "x86_64") => "windows-amd64.zip",
        ("windows", "aarch64") => "windows-arm64.zip",
        _ => return None,
    };
    SINGBOX_ASSETS.into_iter().find(|(s, _)| *s == suffix)
}

/// Downloads, verifies and installs sing-box into `<data>/bin`. Blocking.
pub fn install_singbox(data_dir: &Path) -> Result<EngineInfo, EngineError> {
    let (suffix, sha256) = platform_asset()
        .ok_or_else(|| EngineError::Install("there is no sing-box build for this platform".into()))?;
    let file_name = format!("sing-box-{SINGBOX_VERSION}-{suffix}");
    let url = format!("https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/{file_name}");

    let archive = data_dir.join(&file_name);
    let result = download(&url, &archive)
        .and_then(|()| verify_sha256(&archive, sha256))
        .and_then(|()| extract_into_bin(&archive, data_dir));
    let _ = fs::remove_file(&archive);
    result?;

    installed("sing-box").ok_or_else(|| EngineError::Install("sing-box was installed but doesn't run".into()))
}

fn download(url: &str, to: &Path) -> Result<(), EngineError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .build()
        .into();
    let failed = |e: ureq::Error| EngineError::Install(format!("download failed: {e}"));

    let mut response = agent.get(url).call().map_err(failed)?;
    let mut reader = response.body_mut().with_config().limit(DOWNLOAD_LIMIT).reader();
    let mut file = File::create(to)?;
    std::io::copy(&mut reader, &mut file)?;
    file.flush()?;
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str) -> Result<(), EngineError> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    let actual: String = context.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();

    if actual == expected {
        Ok(())
    } else {
        Err(EngineError::Install("the download is corrupted (checksum mismatch)".into()))
    }
}

/// Unpacks the release archive (it holds one `sing-box-<version>-<platform>/` folder)
/// and moves its files into `<data>/bin`.
fn extract_into_bin(archive: &Path, data_dir: &Path) -> Result<(), EngineError> {
    let staging = data_dir.join("sing-box-staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;

    // GNU tar handles .tar.gz; the bsdtar shipped with Windows 10+ also handles .zip.
    let mut command = Command::new("tar");
    command.arg("-xf").arg(archive).arg("-C").arg(&staging);
    hide_console(&mut command);
    let output = command.output()?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&staging);
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(EngineError::Install(format!("couldn't unpack the download: {reason}")));
    }

    let result = (|| {
        let folder = fs::read_dir(&staging)?
            .flatten()
            .map(|entry| entry.path())
            .find(|path| path.is_dir())
            .ok_or_else(|| EngineError::Install("unexpected archive layout".into()))?;

        let bin = paths::bin_dir(data_dir);
        fs::create_dir_all(&bin)?;
        for entry in fs::read_dir(folder)?.flatten() {
            let target = bin.join(entry.file_name());
            let _ = fs::remove_file(&target);
            fs::rename(entry.path(), target)?;
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny archive shaped like a sing-box release.
    fn fake_release(dir: &Path) -> PathBuf {
        let folder = dir.join(format!("sing-box-{SINGBOX_VERSION}-linux-amd64"));
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("sing-box"), "#!/bin/sh\necho 'sing-box version 1.14.3'\n").unwrap();
        fs::write(folder.join("libcronet.so"), "lib").unwrap();
        let archive = dir.join("release.tar.gz");
        let status = Command::new("tar")
            .arg("-czf").arg(&archive)
            .arg("-C").arg(dir)
            .arg(folder.file_name().unwrap())
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(folder).unwrap();
        archive
    }

    #[test]
    fn checksum_and_extraction() {
        let dir = std::env::temp_dir().join("cipher_client_install_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let archive = fake_release(&dir);

        let wrong = "0".repeat(64);
        assert!(matches!(verify_sha256(&archive, &wrong), Err(EngineError::Install(_))));

        let bytes = fs::read(&archive).unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        verify_sha256(&archive, &hex).unwrap();

        extract_into_bin(&archive, &dir).unwrap();
        assert!(paths::bin_dir(&dir).join("sing-box").is_file());
        assert!(paths::bin_dir(&dir).join("libcronet.so").is_file());
        assert!(!dir.join("sing-box-staging").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_platform_has_a_pinned_release() {
        assert!(platform_asset().is_some());
    }

    /// Downloads the real release from GitHub (about 30 MB) into a temp dir and verifies it.
    #[test]
    #[ignore = "downloads from GitHub"]
    fn downloads_the_real_release() {
        let dir = std::env::temp_dir().join("cipher_client_download_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (suffix, sha256) = platform_asset().unwrap();
        let archive = dir.join(format!("sing-box-{SINGBOX_VERSION}-{suffix}"));

        download(&format!("https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-{suffix}"), &archive).unwrap();
        verify_sha256(&archive, sha256).unwrap();
        extract_into_bin(&archive, &dir).unwrap();

        let output = Command::new(paths::bin_dir(&dir).join(format!("sing-box{}", std::env::consts::EXE_SUFFIX))).arg("version").output().unwrap();
        assert!(String::from_utf8_lossy(&output.stdout).starts_with(&format!("sing-box version {SINGBOX_VERSION}")));
        fs::remove_dir_all(&dir).unwrap();
    }
}
