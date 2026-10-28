//! The desktop window's size and place. The size (and whether it's maximized) is saved on exit
//! and restored on the next start. The position only lasts for this run: hidden to the tray and
//! shown again, the window comes back where it was, while a new start is placed by the system.

use super::Ctx;
use crate::AppWindow;
use crate::store::WindowSize;
use slint::{ComponentHandle, LogicalSize, PhysicalPosition};
use std::cell::Cell;

/// The smallest size the layout allows (`min-width` / `min-height` in main-window.slint).
const MIN_WIDTH: u32 = 400;
const MIN_HEIGHT: u32 = 520;
/// Ignores a corrupt saved size.
const MAX: u32 = 16384;

thread_local! {
    /// The last size while neither maximized nor minimized: what the next start opens at.
    static NORMAL: Cell<Option<LogicalSize>> = const { Cell::new(None) };
    /// Where the window was when it was hidden to the tray, and whether it was maximized.
    static HIDDEN: Cell<Option<(PhysicalPosition, bool)>> = const { Cell::new(None) };
}

/// Before the first show: the size from the last run.
pub(super) fn restore(ui: &AppWindow, saved: Option<WindowSize>) {
    // A phone's window fills the screen.
    let Some(saved) = saved.filter(|_| !cfg!(target_os = "android")) else { return };
    let size = LogicalSize::new(saved.width.clamp(MIN_WIDTH, MAX) as f32, saved.height.clamp(MIN_HEIGHT, MAX) as f32);
    ui.window().set_size(size);
    NORMAL.set(Some(size));
    if saved.maximized {
        ui.window().set_maximized(true);
    }
}

/// After every resize: remembers the size unless it's maximized or minimized.
pub(super) fn resized(ui: &AppWindow) {
    let window = ui.window();
    if window.is_maximized() || window.is_minimized() || !window.is_visible() {
        return;
    }
    let size = window.size().to_logical(window.scale_factor());
    // Minimizing can report a tiny size before the state catches up.
    if size.width >= MIN_WIDTH as f32 - 1.0 && size.height >= MIN_HEIGHT as f32 - 1.0 {
        NORMAL.set(Some(size));
    }
}

/// Hides to the tray, remembering where the window was.
pub(super) fn hide(ui: &AppWindow) {
    let window = ui.window();
    HIDDEN.set(Some((window.position(), window.is_maximized())));
    let _ = ui.hide();
}

/// Shows the window again (from the tray) as it was hidden: size, maximized and, where the
/// system allows it, position.
pub(super) fn show(ui: &AppWindow) {
    let window = ui.window();
    if let Some((position, maximized)) = HIDDEN.take() {
        if destroyed_on_hide() {
            // Slint creates a new window at its preferred size (820x520) unless one is set, and
            // still counts it as maximized, so maximizing again would do nothing: reset that.
            // Done before showing, the new window is simply created this way. Its position is up
            // to the compositor: Wayland doesn't let apps place windows.
            if let Some(size) = NORMAL.get() {
                window.set_size(size);
            }
            if maximized {
                window.set_maximized(false);
                window.set_maximized(true);
            }
        } else if !maximized {
            // A hidden window keeps its size and state; a window manager may still move it.
            // (Changing maximized here would show it early on Windows.)
            window.set_position(position);
        }
    }
    let _ = ui.show();
    window.set_minimized(false);
}

/// Whether hiding destroys the window, as Slint does on Wayland (which can't hide one).
fn destroyed_on_hide() -> bool {
    let set = |name| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    let wayland = cfg!(all(unix, not(target_vendor = "apple"), not(target_os = "android")))
        && (set("WAYLAND_DISPLAY") || set("WAYLAND_SOCKET"))
        && !std::env::var("SLINT_BACKEND").is_ok_and(|backend| backend.contains("x11"));
    wayland || set("SLINT_DESTROY_WINDOW_ON_HIDE")
}

/// On exit: saves the size for the next start.
pub(super) fn save(ui: &AppWindow, ctx: &Ctx) {
    if cfg!(target_os = "android") {
        return;
    }
    let window = ui.window();
    let maximized = match HIDDEN.get() {
        Some((_, maximized)) => maximized,
        None => window.is_maximized(),
    };
    let size = NORMAL.get().unwrap_or_else(|| window.size().to_logical(window.scale_factor()));
    if size.width < 1.0 || size.height < 1.0 {
        return;
    }
    let saved = WindowSize { width: size.width.round() as u32, height: size.height.round() as u32, maximized };
    let mut store = ctx.store.lock().unwrap();
    if store.window != Some(saved) {
        store.window = Some(saved);
        if let Err(e) = store.save() {
            eprintln!("cipher_client: couldn't save the window size: {e}");
        }
    }
}
