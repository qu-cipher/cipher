//! Finds the engine binaries, reports their versions, and installs sing-box and Psiphon.
//!
//! sing-box is downloaded from the official GitHub release, pinned to the version the generated
//! configs are tested against, and checked against the release's SHA-256 before it is used.
//! Psiphon has no release binaries: its ConsoleClient builds live in the
//! `psiphon-tunnel-core-binaries` repo, pinned here to a commit and checked the same way.

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

/// Commit of Psiphon-Labs/psiphon-tunnel-core-binaries (2026-10-05, ConsoleClient rev c4a09096ab).
pub const PSIPHON_COMMIT: &str = "33ff79e89260f3adf92e846b96b3369b86a819d8";
/// (path in that repo, SHA-256). Windows only has a 32-bit build; it runs on 64-bit Windows too.
const PSIPHON_LINUX_X64: (&str, &str) =
    ("linux/psiphon-tunnel-core-x86_64", "046ca168da25d2c0e61c1c15e2b73bfbb67f5208112a4c94fe58fc5aab784f19");
const PSIPHON_WINDOWS: (&str, &str) =
    ("windows/psiphon-tunnel-core-i686.exe", "34139a07deca9e9b94e5b55ebdf5e2583ca87f3d838873f105488681d22f4a0e");

pub struct EngineInfo {
    pub path: PathBuf,
    pub version: String,
}

/// Locates an engine and asks it for its version
/// (`sing-box version`, `openvpn --version`, `psiphon-tunnel-core -version`).
pub fn installed(name: &str) -> Option<EngineInfo> {
    let path = paths::find_binary(name).ok()?;
    let flag = match name {
        "openvpn" => "--version",
        crate::engine::psiphon::BINARY => "-version",
        _ => "version",
    };
    let mut command = Command::new(&path);
    command.arg(flag);
    hide_console(&mut command);
    let output = command.output().ok()?;
    let version = parse_version(name, &String::from_utf8_lossy(&output.stdout))?;
    Some(EngineInfo { path, version })
}

/// "sing-box version 1.14.3" / "OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL …]" → the first number.
/// Psiphon has no version number, only the git revision it was built from: "  Revision: c4a09096ab".
/// (sing-box prints a `Revision:` line too, so that's only read for Psiphon.)
fn parse_version(name: &str, text: &str) -> Option<String> {
    if name == crate::engine::psiphon::BINARY {
        let revision = text.lines().find_map(|line| line.trim().strip_prefix("Revision:"))?;
        return Some(format!("rev {}", revision.trim()));
    }
    let version = text
        .lines()
        .next()?
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))?;
    Some(version.to_owned())
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

/// Downloads, verifies and installs Psiphon's ConsoleClient into `<data>/bin`. Blocking.
pub fn install_psiphon(data_dir: &Path) -> Result<EngineInfo, EngineError> {
    let (path, sha256) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => PSIPHON_LINUX_X64,
        ("windows", _) => PSIPHON_WINDOWS,
        _ => return Err(EngineError::Install("there is no Psiphon build for this platform".into())),
    };
    let url = format!("https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/{PSIPHON_COMMIT}/{path}");

    let bin = paths::bin_dir(data_dir);
    fs::create_dir_all(&bin)?;
    let target = bin.join(format!("{}{}", crate::engine::psiphon::BINARY, std::env::consts::EXE_SUFFIX));
    let partial = target.with_extension("download");
    let result = download(&url, &partial)
        .and_then(|()| verify_sha256(&partial, sha256))
        .and_then(|()| {
            make_executable(&partial)?;
            let _ = fs::remove_file(&target);
            Ok(fs::rename(&partial, &target)?)
        });
    let _ = fs::remove_file(&partial);
    result?;

    installed(crate::engine::psiphon::BINARY)
        .ok_or_else(|| EngineError::Install("Psiphon was installed but doesn't run".into()))
}

fn make_executable(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    let _ = path;
    Ok(())
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

    #[test]
    fn parses_engine_versions() {
        let singbox = "sing-box version 1.14.3\n\nEnvironment: go1.27.2 linux/amd64\nTags: with_gvisor\nRevision: 926876328c5be556512483815621f4791f2844d7\nCGO: enabled\n";
        assert_eq!(parse_version("sing-box", singbox).unwrap(), "1.14.3");
        assert_eq!(parse_version("openvpn", "OpenVPN 2.7.8 x86_64-pc-linux-gnu [SSL (OpenSSL)]\n").unwrap(), "2.7.8");
        let psiphon = "Psiphon Console Client\n  Build Date: 2026-10-05\n  Built With: go1.24\n  Repository: github.com/Psiphon-Labs/psiphon-tunnel-core\n  Revision: c4a09096ab\n";
        assert_eq!(parse_version(crate::engine::psiphon::BINARY, psiphon).unwrap(), "rev c4a09096ab");
        assert_eq!(parse_version("sing-box", ""), None);
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
