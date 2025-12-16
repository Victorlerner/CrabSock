#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod startup;

use crab_sock::commands::*;
use crab_sock::utils::init_logging;
use crab_sock::config_manager::ConfigManager;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use crab_sock::openvpn::OpenVpnManager;
use tauri::Manager;
use tauri::Emitter;
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::menu::{Menu, MenuItem};
use startup::activate_main_window;

fn main() {
    // On Linux disable WebKitGTK DMA-BUF renderer to avoid GPU/DRM permission issues when using capabilities/elevation
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        // Increase RLIMIT_NOFILE to avoid EMFILE under TUN + proxy load
        unsafe {
            use libc::{rlimit, setrlimit, RLIMIT_NOFILE};
            let lim = rlimit { rlim_cur: 262144, rlim_max: 262144 };
            let _ = setrlimit(RLIMIT_NOFILE, &lim);
        }
    }

    // On Windows release builds: if launched from an existing console (cmd/powershell),
    // attach to it so stdout/stderr prints are visible. If started from Explorer, do nothing.
    #[cfg(all(windows, not(debug_assertions)))]
    {
        use std::fs::OpenOptions;
        use std::os::windows::io::IntoRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::{AttachConsole, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, STD_INPUT_HANDLE};
        unsafe {
            // Try to attach; ignore failure (means no parent console)
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
            if let Ok(f) = OpenOptions::new().write(true).open("CONOUT$") {
                let h = HANDLE(f.into_raw_handle());
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
                let _ = SetStdHandle(STD_ERROR_HANDLE, h);
            }
            if let Ok(f) = OpenOptions::new().read(true).open("CONIN$") {
                let h = HANDLE(f.into_raw_handle());
                let _ = SetStdHandle(STD_INPUT_HANDLE, h);
            }
        }
    }

    init_logging();
    log::info!("[MAIN] Starting CrabSock Tauri app");

    // Parse CLI overrides (e.g., from elevation relaunch)
    let startup_args = startup::parse_startup_args();
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let auto_ovpn: Option<String> = startup_args.auto_ovpn.clone();
    let elevated_relaunch: bool = startup_args.elevated_relaunch;
    let routing_override: Option<String> = startup_args.routing_override.clone();

    // On Linux sing-box is started via pkexec wrapper - capabilities are NOT required
    #[cfg(target_os = "linux")]
    {
        log::info!("[MAIN][LINUX] TUN mode will use pkexec wrapper - no capability setup needed");
    }

    // Cross-platform early-exit guard (only active on Windows) to avoid duplicates
    if startup::should_exit_early(elevated_relaunch) {
        return;
    }

    // Инициализируем конфиги при старте приложения
    tauri::async_runtime::block_on(async {
        match ConfigManager::new() {
            Ok(config_manager) => {
                match config_manager.load_configs().await {
                    Ok(config_file) => {
                        log::info!("[MAIN] Initialized config directory with {} configs", config_file.configs.len());
                    }
                    Err(e) => {
                        log::error!("[MAIN] Failed to initialize configs: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("[MAIN] Failed to create config manager: {}", e);
            }
        }
    });

    // Handle Ctrl+C / console close to gracefully tear down external processes
    {
        let _ = ctrlc::set_handler(|| {
            // Fire-and-forget: best effort cleanup without creating a new runtime
            std::thread::spawn(|| {
                tauri::async_runtime::spawn(async {
                    crab_sock::commands::disconnect_vpn_silent().await;
                    // Stop OpenVPN if running (silent, no UI events)
                    crab_sock::openvpn::OpenVpnManager::disconnect_silent();
                    let _ = crab_sock::commands::disable_tun_mode().await;
                    let _ = crab_sock::commands::clear_system_proxy().await;
                });
                // Give the async tasks a moment, then exit
                std::thread::sleep(std::time::Duration::from_millis(200));
                std::process::exit(0);
            });
        });
    }

    let builder = startup::build_tauri_builder(elevated_relaunch);

    builder
        .setup(move |app| {
            // Create tray icon and handle clicks to show window
            let icon = app.default_window_icon().cloned().expect("default window icon missing");
            // Tray menu
            let show_item = MenuItem::with_id(app, "show", "Show app", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit app", true, None::<&str>)?;
            let menu = Menu::new(app)?;
            menu.append(&show_item)?;
            menu.append(&quit_item)?;

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .tooltip("CrabSock")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_tray_icon_event(|icon, event| {
                    match event {
                        // Left click opens menu; double-click shows window
                        TrayIconEvent::DoubleClick { .. } => {
                            activate_main_window(&icon.app_handle());
                        }
                        TrayIconEvent::Click { .. } => { /* Tauri will show menu itself */ }
                        _ => {}
                    }
                })
                .on_menu_event(|icon, event| {
                    match event.id.as_ref() {
                        "show" => {
                            activate_main_window(&icon.app_handle());
                        }
                        "quit" => {
                            // Graceful shutdown: first stop proxy (kills sing-box), then TUN and system proxy
                            let app = icon.app_handle().clone();
                            tauri::async_runtime::spawn(async move {
                                // Stop proxy first (kills sing-box if running)
                                disconnect_vpn_silent().await;
                                // Stop OpenVPN if running
                                crab_sock::openvpn::OpenVpnManager::disconnect_silent();
                                // Then tear down TUN and system proxy
                                let _ = disable_tun_mode().await;
                                let _ = clear_system_proxy().await;
                                let _ = app.exit(0);
                            });
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            // Emit routing override to frontend after window appears (so UI select updates)
            if let Some(mode) = routing_override.clone() {
                let app_handle = app.handle().clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        if app_handle.get_webview_window("main").is_some() { break; }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    let payload = serde_json::json!({ "mode": mode });
                    // Broadcast to all windows
                    for (_, w) in app_handle.webview_windows() {
                        let _ = w.emit("routing-mode", &payload);
                    }
                });
            }

            // If relaunched elevated with --openvpn-connect, connect after window becomes available
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            if elevated_relaunch {
                if let Some(name) = auto_ovpn.clone() {
                    let app_handle = app.handle().clone();
                    std::thread::spawn(move || {
                    // Wait up to ~5s for the main window to exist
                    for _ in 0..50 {
                            if app_handle.get_webview_window("main").is_some() { break; }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                        if let Err(e) = OpenVpnManager::connect(&app_handle, &name) {
                        log::error!("[MAIN] Auto OpenVPN connect failed: {}", e);
                    } else {
                        log::info!("[MAIN] Auto OpenVPN connect started for '{}'", name);
                    }
                });
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Minimize to tray instead of exiting
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            parse_proxy_config,
            ensure_admin_for_tun,
            exit_app,
            connect_vpn,
            disconnect_vpn,
            openvpn_get_recent_logs,
            openvpn_current_status,
            get_status,
            get_ip,
            start_connection_monitoring,
            load_configs,
            save_config,
            remove_config,
            get_config_path,
            get_settings,
            set_routing_mode,
            set_system_proxy,
            clear_system_proxy,
            enable_tun_mode,
            disable_tun_mode,
            is_tun_mode_enabled,
            // OpenVPN
            openvpn_list_configs,
            openvpn_add_config,
            openvpn_remove_config,
            openvpn_connect,
            openvpn_disconnect,
            openvpn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
