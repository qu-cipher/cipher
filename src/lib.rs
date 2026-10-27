//! The whole app. A library so Android can load it as `libcipher_client.so` (entry: `android_main`);
//! the desktop binary (main.rs) just calls [`main`].

#[cfg(target_os = "android")]
mod android;
mod app;
mod engine;
mod import;
mod profile;
mod routing;
mod plugin;
mod store;

slint::include_modules!();

/// The desktop entry point.
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Started as root through pkexec when a plugin needs admin rights (see engine::elevated).
    if std::env::args().nth(1).as_deref() == Some(engine::elevated::HELPER_ARG) {
        engine::elevated::run_helper();
        return Ok(());
    }
    app::run()
}

/// Called by Android's NativeActivity once the library is loaded.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(android: slint::android::AndroidApp) {
    android::init(&android);
    if let Some(dir) = android.internal_data_path() {
        engine::paths::set_android_data_dir(dir);
    }
    if let Err(e) = slint::android::init(android) {
        eprintln!("cipher_client: Slint failed to start: {e}");
        return;
    }
    if let Err(e) = app::run() {
        eprintln!("cipher_client: {e}");
    }
}
