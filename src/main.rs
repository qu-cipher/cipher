// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod engine;
mod import;
mod profile;
mod routing;
mod store;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    app::run()
}
