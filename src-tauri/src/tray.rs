// System tray: Open Pier, a live "Tunnels" submenu (name + status symbol,
// click toggles the tunnel) and Quit.
//
// Threading rules (verified against tauri 2.12 / muda 0.20):
//   * Menu item events are dispatched on the MAIN thread through the tao event
//     loop, and `TrayIcon::set_menu` internally marshals to the main thread and
//     BLOCKS the caller until it runs. Calling `set_menu` from the main thread
//     (e.g. from a menu event handler) therefore deadlocks — it must only be
//     called from non-main threads. All refreshes go through
//     `request_refresh`, which spawns onto the async runtime first.
//   * Both triggers (`tunnel://state` from the engine's tokio workers and
//     `tunnels://config-changed` from the command layer) arrive on arbitrary
//     threads; the spawn below makes the "never on the main thread"
//     guarantee explicit.
//
// Menu refresh is EVENT-DRIVEN: `tunnel://state` covers status changes,
// `tunnels://config-changed` (emitted by commands.rs on every successful
// tunnels.json mutation) covers create/rename/delete — the former 1s
// fingerprint polling thread is gone.

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
    AppHandle, Listener, Manager,
};

use crate::commands::{AppState, TUNNELS_CONFIG_EVENT};
use crate::engine::TUNNEL_STATE_EVENT;
use crate::models::{Backend, TunnelStatus};

const TRAY_ID: &str = "pier-tray";
/// Prefix for per-tunnel menu item ids: `<prefix><tunnel id>`.
const TOGGLE_PREFIX: &str = "pier-toggle:";

/// Set while a menu refresh task is queued or running, to coalesce bursts of
/// `tunnel://state` events into a single rebuild.
static REFRESH_PENDING: AtomicBool = AtomicBool::new(false);

fn fmt_display(prefix: &str) -> String {
    format!("{prefix} {}", crate::brand::DISPLAY_NAME_ZH)
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_menu(app)?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip(crate::brand::DISPLAY_NAME_ZH);

    if let Ok(icon) = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png")) {
        // macOS 菜单栏模板图：随深/浅色菜单栏自动反色（v0.1.1 双图标修复——
        // tauri.conf.json 的声明式 trayIcon 已移除，托盘统一由这里创建）。
        builder = builder.icon(icon).icon_as_template(true);
    }

    let tray = builder.build(app)?;

    // Menu events run on the main thread: only quick, non-blocking work here.
    tray.on_menu_event(handle_menu_event);

    // Rebuild the menu whenever a tunnel status changes (start/stop/reconnect,
    // including the auto-start pass that runs right after this setup).
    let state_handle = app.clone();
    app.listen(TUNNEL_STATE_EVENT, move |_event| {
        request_refresh(&state_handle);
    });

    // Config changes (create/rename/delete) never emit a status event; the
    // command layer emits TUNNELS_CONFIG_EVENT on every successful
    // tunnels.json mutation instead of the old polling thread.
    let config_handle = app.clone();
    app.listen(TUNNELS_CONFIG_EVENT, move |_event| {
        request_refresh(&config_handle);
    });

    Ok(())
}

/// Queue a menu rebuild on the async runtime (never on the main thread).
fn request_refresh(app: &AppHandle) {
    if REFRESH_PENDING.swap(true, Ordering::SeqCst) {
        return; // a rebuild is already queued
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        refresh_menu(&handle);
        REFRESH_PENDING.store(false, Ordering::SeqCst);
    });
}

/// Rebuild the tray menu from the current store + engine state and swap it in.
/// Must not be called from the main thread (see module docs).
fn refresh_menu(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    match build_menu(app) {
        Ok(menu) => {
            if let Err(e) = tray.set_menu(Some(menu)) {
                eprintln!("[pier] failed to refresh tray menu: {e}");
            }
        }
        Err(e) => eprintln!("[pier] failed to build tray menu: {e}"),
    }
}

/// Build the full menu: Open Pier | Tunnels submenu | Quit Pier.
fn build_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let show = MenuItem::with_id(app, "show", fmt_display("打开"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", fmt_display("退出"), true, None::<&str>)?;
    let sep_before = PredefinedMenuItem::separator(app)?;
    let sep_after = PredefinedMenuItem::separator(app)?;

    let tunnels = Submenu::with_id(app, "tunnels", "Tunnels", true)?;
    match app.try_state::<AppState>() {
        // tray::setup runs before commands::init_runtime manages AppState, so
        // the state may genuinely be missing on the very first build.
        None => {
            let loading =
                MenuItem::with_id(app, "tunnels-loading", "Loading…", false, None::<&str>)?;
            tunnels.append(&loading)?;
        }
        Some(state) => {
            let configs = state.store.load();
            if configs.is_empty() {
                let empty =
                    MenuItem::with_id(app, "tunnels-empty", "No tunnels yet", false, None::<&str>)?;
                tunnels.append(&empty)?;
            }
            for cfg in configs {
                let status = state
                    .engine
                    .snapshot(&cfg.id)
                    .map(|st| st.status)
                    .unwrap_or(TunnelStatus::Stopped);
                let label = format!(
                    "{} {} · {} :{}",
                    status_symbol(status),
                    cfg.name,
                    backend_label(cfg.backend),
                    cfg.local_port
                );
                let item = MenuItem::with_id(
                    app,
                    format!("{TOGGLE_PREFIX}{}", cfg.id),
                    label,
                    true,
                    None::<&str>,
                )?;
                tunnels.append(&item)?;
            }
        }
    }

    Menu::with_items(app, &[&show, &sep_before, &tunnels, &sep_after, &quit])
}

/// ● running / ◌ connecting / ○ stopped
fn status_symbol(status: TunnelStatus) -> &'static str {
    match status {
        TunnelStatus::Running => "●",
        TunnelStatus::Starting | TunnelStatus::Reconnecting => "◌",
        TunnelStatus::Stopped | TunnelStatus::Error => "○",
    }
}

fn backend_label(backend: Backend) -> &'static str {
    match backend {
        Backend::Cloudflare => "cloudflare",
        Backend::Bore => "bore",
        Backend::Frp => "frp",
        Backend::CloudflareNamed => "cloudflare",
    }
}

fn handle_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id.as_ref() {
        "show" => show_main_window(app),
        "quit" => app.exit(0),
        id => {
            if let Some(tunnel_id) = id.strip_prefix(TOGGLE_PREFIX) {
                toggle_tunnel(app, tunnel_id);
            }
        }
    }
}

/// Start the tunnel if it is idle, stop it if it is active.
fn toggle_tunnel(app: &AppHandle, id: &str) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let engine = state.engine.clone();
    let store = state.store.clone();
    let id = id.to_string();

    // The engine API is async; hand the work off instead of blocking the main
    // thread. State transitions emit `tunnel://state`, which rebuilds the menu.
    tauri::async_runtime::spawn(async move {
        let running = engine
            .snapshot(&id)
            .map(|st| !matches!(st.status, TunnelStatus::Stopped | TunnelStatus::Error))
            .unwrap_or(false);
        let result = if running {
            engine.stop(&id).await
        } else {
            match store.get(&id) {
                Ok(Some(cfg)) => engine.clone().start(cfg).await,
                Ok(None) => Err(format!("tunnel not found: {id}")),
                Err(e) => Err(e),
            }
        };
        if let Err(e) = result {
            eprintln!("[pier] tray toggle for tunnel {id} failed: {e}");
        }
    });
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
