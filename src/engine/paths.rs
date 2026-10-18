use crate::engine::EngineError;
use std::{env, fs, io, path::{Path, PathBuf}};

/// Per-user app data directory (configs, logs, cache), created on first use.
/// Linux: ~/.local/share/cipher_client, Windows: %APPDATA%\cipher_client
pub fn data_dir() -> Result<PathBuf, EngineError> {
    let dir = dirs::data_dir().ok_or(EngineError::NoDataDir)?.join("cipher_client");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Where downloaded engines are installed.
pub fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bin")
}

/// Finds an engine binary: next to our executable, then downloaded ones, then PATH.
pub fn find_binary(name: &str) -> Result<PathBuf, EngineError> {
    let file_name = format!("{name}{}", env::consts::EXE_SUFFIX);

    let beside_exe = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&file_name)));

    let downloaded = data_dir().ok().map(|dir| bin_dir(&dir).join(&file_name));

    let in_path = env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(&file_name));

    beside_exe
        .into_iter()
        .chain(downloaded)
        .chain(in_path)
        .find(|candidate| candidate.is_file())
        .ok_or(EngineError::BinaryNotFound(file_name))
}

/// Writes a file only the current user can read (configs hold credentials).
/// On Windows the per-user data dir is already private.
pub fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
