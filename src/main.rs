// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod engine;
mod import;
mod profile;
mod routing;
mod plugin;
mod store;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Started as root through pkexec when a plugin needs admin rights (see engine::elevated).
    if std::env::args().nth(1).as_deref() == Some(engine::elevated::HELPER_ARG) {
        engine::elevated::run_helper();
        return Ok(());
    }
    app::run()
}
