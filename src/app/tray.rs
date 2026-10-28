//! The desktop tray icon, and what closing the window does (quit, or hide to the tray).

use super::{Ctx, toggle_connection, window};
use crate::{AppWindow, ConnectionState, Tray};
use slint::{CloseRequestResponse, ComponentHandle};
use std::cell::RefCell;

thread_local! {
    /// Lives on the UI thread, like the window (a tray handle isn't `Send`).
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

/// Shows the tray icon and routes the window's close button (ours and the window manager's).
pub(super) fn init(ui: &AppWindow, ctx: &Ctx) {
    ui.on_close_window({
        let (weak, ctx) = (ui.as_weak(), ctx.clone());
        move || {
            if let Some(ui) = weak.upgrade() {
                close(&ui, &ctx);
            }
        }
    });
    ui.window().on_close_requested({
        let (weak, ctx) = (ui.as_weak(), ctx.clone());
        move || {
            if let Some(ui) = weak.upgrade() {
                close(&ui, &ctx);
            }
            CloseRequestResponse::KeepWindowShown
        }
    });

    // Tests drive the UI headlessly: no icon on the developer's desktop.
    if cfg!(any(target_os = "android", test)) {
        return;
    }
    let tray = match Tray::new() {
        Ok(tray) => tray,
        Err(e) => {
            eprintln!("cipher_client: no tray icon: {e}");
            return;
        }
    };
    tray.on_show_window({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                window::show(&ui);
            }
        }
    });
    tray.on_toggle_connection({
        let (weak, ctx) = (ui.as_weak(), ctx.clone());
        move || {
            if let Some(ui) = weak.upgrade() {
                toggle_connection(&ui, &ctx);
            }
        }
    });
    tray.on_quit(|| {
        let _ = slint::quit_event_loop();
    });
    let _ = tray.show();
    TRAY.with(|t| *t.borrow_mut() = Some(tray));
    update(ConnectionState::Disconnected, false);
}

/// Mirrors the connection state (icon, tooltip, the menu's Connect item).
pub(super) fn update(state: ConnectionState, cancelling: bool) {
    TRAY.with(|t| {
        let tray = t.borrow();
        let Some(tray) = tray.as_ref() else { return };
        let (status, action) = match state {
            ConnectionState::Connected => ("Connected", "Disconnect"),
            ConnectionState::Connecting => ("Connecting…", "Cancel"),
            ConnectionState::Disconnecting => ("Disconnecting…", "Disconnect"),
            _ => ("Disconnected", "Connect"),
        };
        tray.set_connected(state == ConnectionState::Connected);
        tray.set_status(format!("Cipher: {status}").into());
        tray.set_action(action.into());
        // Like the power button: disconnecting can't be interrupted, a cancel only once.
        tray.set_action_enabled(state != ConnectionState::Disconnecting && !cancelling);
    });
}

/// Quits, or with "Close to tray" on hides the window: the connection keeps running and the
/// tray brings it back. Without a tray to come back from, it minimizes instead.
fn close(ui: &AppWindow, ctx: &Ctx) {
    if !ctx.store.lock().unwrap().settings.close_to_tray {
        let _ = slint::quit_event_loop();
    } else if TRAY.with(|t| t.borrow().is_some()) && host_available() {
        window::hide(ui);
    } else {
        ui.window().set_minimized(true);
    }
}

/// Linux trays are StatusNotifierItems: some desktops (GNOME without an extension) show none,
/// and a hidden window could then never come back.
#[cfg(all(unix, not(target_os = "android")))]
fn host_available() -> bool {
    std::process::Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.kde.StatusNotifierWatcher",
        ])
        .output()
        .is_ok_and(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).contains("boolean true"))
}

#[cfg(not(all(unix, not(target_os = "android"))))]
fn host_available() -> bool {
    true
}
