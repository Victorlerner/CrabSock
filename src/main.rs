use crab_sock::commands::*;
use crab_sock::utils::init_logging;
use crab_sock::config_manager::ConfigManager;

fn main() {
    init_logging();
    log::info!("[MAIN] Starting CrabSock Tauri app");

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
            update_settings,
            get_config_path,
            set_system_proxy,
            clear_system_proxy,
            enable_tun_mode,
            disable_tun_mode,
            is_tun_mode_enabled,
                request_tun_permissions,
                request_tun_permissions_sudo,
                check_tun_capability_command,
                build_release_version,
                restart_application
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
