use crate::engine::EngineError;
use std::{fs, io, path::{Path, PathBuf}};

/// Per-user app data directory (configs, logs, cache), created on first use.
/// Linux: ~/.local/share/cipher_client, Windows: %APPDATA%\cipher_client, Android: the app's files dir
pub fn data_dir() -> Result<PathBuf, EngineError> {
    #[cfg(test)]
    if let Some(dir) = TEST_DATA_DIR.with(|d| d.borrow().clone()) {
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }
    #[cfg(target_os = "android")]
    let dir = ANDROID_DATA_DIR.get().cloned().ok_or(EngineError::NoDataDir)?;
    #[cfg(not(target_os = "android"))]
    let dir = dirs::data_dir().ok_or(EngineError::NoDataDir)?.join("cipher_client");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The app's private files dir, from the activity (set once at startup, before the store loads).
#[cfg(target_os = "android")]
static ANDROID_DATA_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
pub fn set_android_data_dir(dir: PathBuf) {
    let _ = ANDROID_DATA_DIR.set(dir);
}

#[cfg(test)]
thread_local! {
    /// A test's own data dir (this thread only), so tests never touch the real one.
    pub static TEST_DATA_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Where downloaded engines are installed.
pub fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bin")
}

/// Finds an engine binary bundled in the APK. Android only runs programs installed with the app,
/// from its native library dir, named like libraries: sing-box → libsingbox.so. That dir is the
/// one holding our own library.
#[cfg(target_os = "android")]
pub fn find_binary(name: &str) -> Result<PathBuf, EngineError> {
    let file_name = format!("lib{}.so", name.replace('-', ""));
    native_library_dir()
        .map(|dir| dir.join(&file_name))
        .filter(|path| path.is_file())
        .ok_or(EngineError::BinaryNotFound(file_name))
}

/// The folder of the loaded `libcipher_client.so` (from /proc/self/maps; no Java call needed).
#[cfg(target_os = "android")]
fn native_library_dir() -> Option<PathBuf> {
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    let lib = maps.lines().find_map(|line| line.split_whitespace().nth(5).filter(|p| p.ends_with("/libcipher_client.so")))?;
    Path::new(lib).parent().map(Path::to_path_buf)
}

/// Finds an engine binary: next to our executable, then downloaded ones, then PATH.
#[cfg(not(target_os = "android"))]
pub fn find_binary(name: &str) -> Result<PathBuf, EngineError> {
    use std::env;
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
