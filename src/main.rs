use crab_sock::commands::*;
use crab_sock::utils::init_logging;

fn main() {
    init_logging();
    log::info!("[MAIN] Starting CrabSock Tauri app");

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            parse_proxy_config,
            connect_vpn,
            disconnect_vpn,
            get_status,
            get_ip,
            start_connection_monitoring
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
