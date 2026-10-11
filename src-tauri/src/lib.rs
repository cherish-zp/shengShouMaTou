mod binman;
mod brand;
mod cloudflare;
mod commands;
mod diagnostics;
mod engine;
mod forwarder;
mod frp_deploy;
mod frp_import;
mod models;
mod providers;
mod secrets_store;
mod servers_store;
mod ssh;
mod store;
mod tray;
mod util;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Must be the first plugin: a second launch (another copy of the app
        // from a different path, double-open, etc.) exits immediately and
        // brings the existing instance's window to the front — without this,
        // two tray icons and two processes can coexist.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            // 开机自启的实例带 --hidden 启动：窗口保持隐藏，仅托盘常驻。
            Some(vec!["--hidden"]),
        ))
        .setup(|app| {
            #[cfg(desktop)]
            tray::setup(app.handle())?;
            commands::init_runtime(app.handle())?;
            // 主窗口默认隐藏（tauri.conf.json visible: false）：手动启动时
            // 显示并聚焦，保持原有关闭前的体验；--hidden（开机自启）保持隐藏。
            if !std::env::args().any(|arg| arg == "--hidden") {
                tray::show_main_window(app.handle());
            }
            Ok(())
        })
        // 关闭主窗口 = 隐藏到托盘，不退出应用；退出只走托盘菜单的
        // app.exit(0)（不经过 CloseRequested，RunEvent::Exit 清理不受影响）。
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_tunnels,
            commands::create_tunnel,
            commands::update_tunnel,
            commands::delete_tunnel,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::get_state,
            commands::list_states,
            commands::read_binary_status,
            commands::install_binary,
            commands::list_servers,
            commands::add_server,
            commands::remove_server,
            commands::test_server,
            commands::deploy_server,
            commands::undeploy_server,
            commands::get_server_status,
            commands::import_frpc_config,
            commands::diagnose_tunnel,
            commands::get_tunnel_logs,
            commands::clear_tunnel_logs,
            commands::clear_all_tunnel_logs,
            commands::get_storage_usage,
            commands::clear_cache,
            commands::set_tunnel_auth,
            commands::cf_verify_token,
            commands::cf_list_zones,
            commands::cf_provision,
            commands::cf_deprovision,
            commands::cf_update_hostname,
            commands::cf_get_api_token,
            commands::cf_list_zones_stored,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                commands::shutdown(app_handle);
            }
        });
}
