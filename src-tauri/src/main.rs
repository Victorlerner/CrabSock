#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use crab_sock::commands::*;
use crab_sock::utils::init_logging;
use crab_sock::config_manager::ConfigManager;
#[cfg(target_os = "linux")]
use crab_sock::linux_capabilities::{has_cap_net_admin, set_cap_net_admin_via_pkexec, set_cap_net_admin_via_sudo};

fn main() {
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

    #[cfg(target_os = "linux")]
    {
        let is_debug = cfg!(debug_assertions);
        let skip = std::env::var("CRABSOCK_SKIP_CAP_CHECK").is_ok();
        if !is_debug && !skip {
            if !has_cap_net_admin() {
                log::info!("[MAIN] cap_net_admin is missing, attempting to set via pkexec/sudo");
                match set_cap_net_admin_via_pkexec().or_else(|_| set_cap_net_admin_via_sudo()) {
                    Ok(_) => {
                        log::info!("[MAIN] cap_net_admin successfully set on startup, restarting to apply capabilities");
                        if let Ok(exe) = std::env::current_exe() {
                            let args: Vec<String> = std::env::args().skip(1).collect();
                            let _ = std::process::Command::new(exe).args(args).spawn();
                        }
                        std::process::exit(0);
                    }
                    Err(e) => log::warn!("[MAIN] Failed to set cap_net_admin on startup: {}", e),
                }
            }
        } else {
            log::info!("[MAIN] Skipping capability setup (debug build or CRABSOCK_SKIP_CAP_CHECK set)");
        }
    }

    // Инициализируем конфиги при старте приложения
    tokio::runtime::Runtime::new().unwrap().block_on(async {
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

    tauri::Builder::default()
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Останавливаем закрытие до завершения очистки (одноразово)
                static mut SHUTTING_DOWN: bool = false;
                let do_cleanup = unsafe { if SHUTTING_DOWN { false } else { SHUTTING_DOWN = true; true } };
                if do_cleanup {
                    api.prevent_close();
                    use tauri::Manager;
                    let app = window.app_handle().clone();
                    // Асинхронно останавливаем TUN/прокси и завершаем процесс
                    tauri::async_runtime::spawn(async move {
                        let _ = disable_tun_mode().await;
                        let _ = clear_system_proxy().await;
                        // disconnect_vpn требует window, но закрывать окно нам не нужно — завершаем app
                        // Если нужно, можно вызвать disconnect_vpn через скрытое окно
                        let _ = app.exit(0);
                    });
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            parse_proxy_config,
            connect_vpn,
            disconnect_vpn,
            get_status,
            get_ip,
            start_connection_monitoring,
            load_configs,
            save_config,
            remove_config,
            get_config_path,
            set_system_proxy,
            clear_system_proxy,
            enable_tun_mode,
            disable_tun_mode,
            is_tun_mode_enabled
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
