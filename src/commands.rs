use crate::config::ProxyConfig;
use crate::proxy::{ProxyManager, ConnectionStatus};
use crate::config_manager::{ConfigManager, ConfigFile, AppSettings};
use crate::system_proxy::{SystemProxyManager, ProxySettings};
use crate::tun_manager::TunManager;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use serde::Serialize;
use tauri::Emitter;

static PROXY_MANAGER: Lazy<Mutex<ProxyManager>> = Lazy::new(|| Mutex::new(ProxyManager::new()));
static SYSTEM_PROXY_MANAGER: Lazy<Mutex<SystemProxyManager>> = Lazy::new(|| Mutex::new(SystemProxyManager::new()));
static TUN_MANAGER: Lazy<Mutex<TunManager>> = Lazy::new(|| Mutex::new(TunManager::new()));

#[derive(Debug, Clone, Serialize)]
pub struct StatusEvent {
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpInfo {
    pub ip: String,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEvent {
    pub status: String,
    pub ip: Option<String>,
    pub country: Option<String>,
}

#[tauri::command]
pub async fn parse_proxy_config(config_string: String) -> Result<ProxyConfig, String> {
    log::info!("[PARSE] Received config string: {}", config_string);

    let config = ProxyConfig::from_config_string(&config_string)
        .map_err(|e| e.to_string())?;

    log::info!("[PARSE] Successfully parsed config: {:?}", config);
    Ok(config)
}

#[tauri::command]
pub async fn connect_vpn(window: tauri::Window, config: ProxyConfig) -> Result<(), String> {
    log::info!("[CONNECT] Starting VPN connection with config: {:?}", config);

    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.connect(config).await
    };

    match result {
        Ok(_) => {
            log::info!("[CONNECT] VPN proxy started successfully");
            
            // Ждем немного, чтобы прокси успел запуститься
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Проверяем IP для подтверждения работы прокси
            match get_ip().await {
                Ok(ip_info) => {
                    log::info!("[CONNECT] IP verification successful: {} ({})", ip_info.ip, ip_info.country.as_ref().unwrap_or(&"Unknown".to_string()));
                    
                    // Небольшая задержка перед отправкой события
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    
                    // Отправляем обычное событие статуса
                    println!("[STDOUT] Sending status event to frontend: status=connected");
                    
                    let status_result = window.emit("status", StatusEvent {
                        status: "connected".into(),
                    });
                    
                    match status_result {
                        Ok(_) => println!("[STDOUT] Successfully sent status event to frontend"),
                        Err(e) => println!("[STDOUT] Failed to send status event: {:?}", e),
                    }
                    
                    // Отправляем событие о верификации IP
                    println!("[STDOUT] Sending ip_verified event to frontend: ip={}, country={:?}", 
                        ip_info.ip, ip_info.country);
                    
                    let ip_result = window.emit("ip_verified", ip_info);
                    
                    match ip_result {
                        Ok(_) => println!("[STDOUT] Successfully sent ip_verified event to frontend"),
                        Err(e) => println!("[STDOUT] Failed to send ip_verified event: {:?}", e),
                    }
                    
                    log::info!("[CONNECT] VPN connected and verified successfully");
                    Ok(())
                }
                Err(e) => {
                    log::warn!("[CONNECT] VPN connected but IP verification failed: {}", e);
                    
                    // Даже если проверка IP не удалась, считаем подключение успешным
                    let _ = window.emit("status", StatusEvent {
                        status: "connected".into(),
                    });
                    
                    log::info!("[CONNECT] VPN connected (IP verification failed)");
                    Ok(())
                }
            }
        }
        Err(e) => {
            log::error!("[CONNECT] VPN connection failed: {}", e);
            let _ = window.emit("status", StatusEvent {
                status: "disconnected".into(),
            });
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub async fn disconnect_vpn(window: tauri::Window) -> Result<(), String> {
    log::info!("[DISCONNECT] Disconnecting VPN");

    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.disconnect().await
    };

    match result {
        Ok(_) => {
            let _ = window.emit("status", StatusEvent {
                status: "disconnected".into(),
            });

            log::info!("[DISCONNECT] VPN disconnected");
            Ok(())
        }
        Err(e) => {
            log::error!("[DISCONNECT] VPN disconnect failed: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub async fn get_status() -> String {
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };
    
    let status_str = match status {
        ConnectionStatus::Disconnected => "disconnected",
        ConnectionStatus::Connecting => "connecting",
        ConnectionStatus::Connected => "connected",
        ConnectionStatus::Error(_) => "error",
    };
    
    log::info!("[STATUS] {}", status_str);
    status_str.into()
}

#[tauri::command]
pub async fn start_connection_monitoring(window: tauri::Window) -> Result<(), String> {
    log::info!("[MONITOR] Starting connection monitoring");
    
    tokio::spawn(async move {
        let mut last_status = "disconnected".to_string();
        
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            
            let current_status = {
                let manager = PROXY_MANAGER.lock().await;
                let status = manager.get_status().await;
                
                match status {
                    ConnectionStatus::Disconnected => "disconnected",
                    ConnectionStatus::Connecting => "connecting", 
                    ConnectionStatus::Connected => "connected",
                    ConnectionStatus::Error(_) => "error",
                }
            };
            
            if current_status != last_status {
                log::info!("[MONITOR] Status changed: {} -> {}", last_status, current_status);
                
                let _ = window.emit("status", StatusEvent {
                    status: current_status.into(),
                });
                
                last_status = current_status.to_string();
            }
            
            // Если подключены, проверяем IP каждые 30 секунд
            if current_status == "connected" {
                match get_ip().await {
                    Ok(ip_info) => {
                        log::info!("[MONITOR] IP check successful: {} ({})", ip_info.ip, ip_info.country.as_ref().unwrap_or(&"Unknown".to_string()));
                        println!("[STDOUT] Monitor: Sending connection_update event: status=connected, ip={}, country={:?}", 
                            ip_info.ip, ip_info.country);
                        
                        let result = window.emit("connection_update", ConnectionEvent {
                            status: "connected".into(),
                            ip: Some(ip_info.ip),
                            country: ip_info.country,
                        });
                        
                        match result {
                            Ok(_) => println!("[STDOUT] Monitor: Successfully sent connection_update event"),
                            Err(e) => println!("[STDOUT] Monitor: Failed to send connection_update event: {:?}", e),
                        }
                    }
                    Err(e) => {
                        log::warn!("[MONITOR] IP check failed: {}", e);
                        println!("[STDOUT] Monitor: IP check failed: {}", e);
                        // Если IP проверка не удалась несколько раз подряд, возможно подключение упало
                        // Но пока не меняем статус автоматически
                    }
                }
            }
        }
    });
    
    Ok(())
}

#[tauri::command]
pub async fn get_ip() -> Result<IpInfo, String> {
    log::info!("[IP] Fetching external IP");

    // Создаем клиент с SOCKS5 прокси
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5://127.0.0.1:1080")
            .map_err(|e| format!("Failed to create SOCKS5 proxy: {}", e))?)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let resp = client.get("https://ipinfo.io/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch IP info: {}", e))?;

    let json: serde_json::Value = resp.json()
        .await
        .map_err(|e| format!("Failed to parse IP JSON: {}", e))?;

    let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let country = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());

    log::info!("[IP] Fetched IP: {}, Country: {:?}", ip, country);

    Ok(IpInfo { ip, country })
}

// Команды для работы с конфигами
#[tauri::command]
pub async fn load_configs() -> Result<ConfigFile, String> {
    log::info!("[CONFIG] Loading configs from file system");
    
    let config_manager = ConfigManager::new()
        .map_err(|e| format!("Failed to create config manager: {}", e))?;
    
    let config_file = config_manager.load_configs().await
        .map_err(|e| format!("Failed to load configs: {}", e))?;
    
    log::info!("[CONFIG] Loaded {} configs", config_file.configs.len());
    Ok(config_file)
}

#[tauri::command]
pub async fn save_config(config: ProxyConfig) -> Result<(), String> {
    log::info!("[CONFIG] Saving config: {}", config.name);
    
    let config_manager = ConfigManager::new()
        .map_err(|e| format!("Failed to create config manager: {}", e))?;
    
    config_manager.add_config(config).await
        .map_err(|e| format!("Failed to save config: {}", e))?;
    
    log::info!("[CONFIG] Config saved successfully");
    Ok(())
}

#[tauri::command]
pub async fn remove_config(config: ProxyConfig) -> Result<(), String> {
    log::info!("[CONFIG] Removing config: {}", config.name);
    
    let config_manager = ConfigManager::new()
        .map_err(|e| format!("Failed to create config manager: {}", e))?;
    
    config_manager.remove_config(&config).await
        .map_err(|e| format!("Failed to remove config: {}", e))?;
    
    log::info!("[CONFIG] Config removed successfully");
    Ok(())
}

#[tauri::command]
pub async fn update_settings(settings: AppSettings) -> Result<(), String> {
    log::info!("[CONFIG] Updating settings");
    
    let config_manager = ConfigManager::new()
        .map_err(|e| format!("Failed to create config manager: {}", e))?;
    
    config_manager.update_settings(settings).await
        .map_err(|e| format!("Failed to update settings: {}", e))?;
    
    log::info!("[CONFIG] Settings updated successfully");
    Ok(())
}

#[tauri::command]
pub async fn get_config_path() -> Result<String, String> {
    let config_manager = ConfigManager::new()
        .map_err(|e| format!("Failed to create config manager: {}", e))?;
    
    let path = config_manager.get_config_path().to_string_lossy().to_string();
    log::info!("[CONFIG] Config path: {}", path);
    Ok(path)
}

// Команды для управления системным прокси
#[tauri::command]
pub async fn set_system_proxy() -> Result<(), String> {
    log::info!("[SYSTEM_PROXY] Enabling system proxy");
    
    // Получаем текущий статус прокси
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };

    match status {
        ConnectionStatus::Connected => {
            // Проверяем, включен ли TUN режим
            let tun_mode = {
                let system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                system_manager.is_tun_mode()
            };

            if tun_mode {
                // Если включен TUN режим, просто включаем его
                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                system_manager.set_tun_mode(true).await
                    .map_err(|e| format!("Failed to enable TUN mode: {}", e))?;
            } else {
                // Устанавливаем системный прокси на наш SOCKS5 прокси
                let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                
                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                system_manager.set_system_proxy(&proxy_settings).await
                    .map_err(|e| format!("Failed to set system proxy: {}", e))?;
            }
            
            log::info!("[SYSTEM_PROXY] System proxy enabled successfully");
            Ok(())
        }
        _ => {
            Err("VPN must be connected to enable system proxy".to_string())
        }
    }
}

#[tauri::command]
pub async fn clear_system_proxy() -> Result<(), String> {
    log::info!("[SYSTEM_PROXY] Disabling system proxy");
    
    let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
    system_manager.clear_system_proxy().await
        .map_err(|e| format!("Failed to clear system proxy: {}", e))?;
    
    log::info!("[SYSTEM_PROXY] System proxy disabled successfully");
    Ok(())
}

// Команды для управления TUN режимом
#[tauri::command]
pub async fn enable_tun_mode() -> Result<(), String> {
    log::info!("[TUN] Enabling TUN mode");
    println!("[STDOUT] TUN mode enable requested");
    
    // Получаем текущий статус прокси
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };

    match status {
        ConnectionStatus::Connected => {
            println!("[STDOUT] VPN is connected, starting TUN interface");
            
            // Сначала проверяем capability
            let has_capability = check_tun_capability().await;
            println!("[STDOUT] TUN capability check: {}", has_capability);
            
            // Запускаем TUN интерфейс
            let mut tun_manager = TUN_MANAGER.lock().await;
            match tun_manager.start().await {
                Ok(_) => {
                    println!("[STDOUT] TUN interface started successfully");

                    // Включаем TUN режим в системном прокси менеджере
                    let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                    system_manager.set_tun_mode(true).await
                        .map_err(|e| {
                            println!("[STDOUT] Failed to enable TUN mode: {}", e);
                            format!("Failed to enable TUN mode: {}", e)
                        })?;
                    
                    println!("[STDOUT] TUN mode enabled successfully - all traffic routed through VPN");
                    log::info!("[TUN] TUN mode enabled successfully");
                    Ok(())
                }
                Err(e) => {
                    println!("[STDOUT] Failed to start TUN interface: {}", e);
                    
                    // Проверяем, связана ли ошибка с правами
                    let error_msg = e.to_string();
                    if error_msg.contains("permissions") || error_msg.contains("sudo") || error_msg.contains("capability") || error_msg.contains("Insufficient") {
                        if has_capability {
                            println!("[STDOUT] TUN capability is set but interface creation failed - this might be a development mode issue");
                            Err("TUN capability is set but interface creation failed. This might be due to running in development mode. Please try building and running the release version.".to_string())
                        } else {
                            Err("TUN Mode requires administrator privileges. Please grant permissions first.".to_string())
                        }
                    } else {
                        Err(format!("Failed to start TUN interface: {}", e))
                    }
                }
            }
        }
        _ => {
            let error_msg = "VPN must be connected to enable TUN mode";
            println!("[STDOUT] {}", error_msg);
            Err(error_msg.to_string())
        }
    }
}

#[tauri::command]
pub async fn disable_tun_mode() -> Result<(), String> {
    log::info!("[TUN] Disabling TUN mode");
    println!("[STDOUT] TUN mode disable requested");
    
    // Отключаем TUN режим в системном прокси менеджере
    let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
    system_manager.set_tun_mode(false).await
        .map_err(|e| {
            println!("[STDOUT] Failed to disable TUN mode: {}", e);
            format!("Failed to disable TUN mode: {}", e)
        })?;

    println!("[STDOUT] TUN mode disabled in system proxy manager");

    // Останавливаем TUN интерфейс
    let mut tun_manager = TUN_MANAGER.lock().await;
    tun_manager.stop().await
        .map_err(|e| {
            println!("[STDOUT] Failed to stop TUN interface: {}", e);
            format!("Failed to stop TUN interface: {}", e)
        })?;
    
    println!("[STDOUT] TUN mode disabled successfully");
    log::info!("[TUN] TUN mode disabled successfully");
    Ok(())
}

#[tauri::command]
pub async fn is_tun_mode_enabled() -> Result<bool, String> {
    let system_manager = SYSTEM_PROXY_MANAGER.lock().await;
    Ok(system_manager.is_tun_mode())
}

#[derive(Debug, Clone, Serialize)]
pub struct TunPermissionResult {
    pub success: bool,
    pub message: String,
    pub needs_restart: bool,
}

#[tauri::command]
pub async fn request_tun_permissions() -> Result<TunPermissionResult, String> {
    log::info!("[TUN] Requesting TUN permissions");
    println!("[STDOUT] TUN: Requesting TUN permissions");
    
    // Проверяем, есть ли pkexec
    let pkexec_check = std::process::Command::new("which")
        .arg("pkexec")
        .output();
    
    if pkexec_check.is_err() || !pkexec_check.unwrap().status.success() {
        println!("[STDOUT] TUN: pkexec not found");
        return Ok(TunPermissionResult {
            success: false,
            message: "pkexec not found. Please install pkexec first.".to_string(),
            needs_restart: false,
        });
    }
    
    // Получаем путь к исполняемому файлу
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {}", e))?;
    
    println!("[STDOUT] TUN: Setting capability cap_net_admin=ep for: {}", current_exe.display());
    
    // Устанавливаем capability через pkexec
    let output = std::process::Command::new("pkexec")
        .args(&["setcap", "cap_net_admin=ep", &current_exe.to_string_lossy()])
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                println!("[STDOUT] TUN: Capability set successfully");
                log::info!("[TUN] Capability set successfully");
                
                Ok(TunPermissionResult {
                    success: true,
                    message: "Permissions granted successfully. Please build release version for TUN Mode.".to_string(),
                    needs_restart: true,
                })
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                println!("[STDOUT] TUN: Failed to set capability: {}", error);
                
                // Проверяем, отменил ли пользователь диалог
                if error.contains("cancelled") || error.contains("canceled") || error.contains("Request dismissed") || output.status.code() == Some(1) {
                    Ok(TunPermissionResult {
                        success: false,
                        message: "Permission request was cancelled by user. You may be temporarily locked out due to failed authentication attempts.".to_string(),
                        needs_restart: false,
                    })
                } else {
                    Ok(TunPermissionResult {
                        success: false,
                        message: format!("Failed to set capability: {}", error),
                        needs_restart: false,
                    })
                }
            }
        }
        Err(e) => {
            println!("[STDOUT] TUN: Failed to run pkexec: {}", e);
            Ok(TunPermissionResult {
                success: false,
                message: format!("Failed to run pkexec: {}", e),
                needs_restart: false,
            })
        }
    }
}

#[tauri::command]
pub async fn restart_application() -> Result<(), String> {
    log::info!("[TUN] Restart application requested - but we don't restart in development mode");
    println!("[STDOUT] TUN: Restart application requested - but we don't restart in development mode");
    
    // В development mode не перезапускаем приложение
    // Вместо этого просто возвращаем успех
    Ok(())
}

#[tauri::command]
pub async fn request_tun_permissions_sudo() -> Result<TunPermissionResult, String> {
    log::info!("[TUN] Requesting TUN permissions via sudo");
    println!("[STDOUT] TUN: Requesting TUN permissions via sudo");
    
    // Получаем путь к исполняемому файлу
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {}", e))?;
    
    println!("[STDOUT] TUN: Setting capability cap_net_admin=ep via sudo for: {}", current_exe.display());
    
    // Устанавливаем capability через sudo
    let output = std::process::Command::new("sudo")
        .args(&["setcap", "cap_net_admin=ep", &current_exe.to_string_lossy()])
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                println!("[STDOUT] TUN: Capability set successfully via sudo");
                log::info!("[TUN] Capability set successfully via sudo");
                
                Ok(TunPermissionResult {
                    success: true,
                    message: "Permissions granted successfully via sudo. Please build release version for TUN Mode.".to_string(),
                    needs_restart: true,
                })
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                println!("[STDOUT] TUN: Failed to set capability via sudo: {}", error);
                
                Ok(TunPermissionResult {
                    success: false,
                    message: format!("Failed to set capability via sudo: {}", error),
                    needs_restart: false,
                })
            }
        }
        Err(e) => {
            println!("[STDOUT] TUN: Failed to run sudo: {}", e);
            Ok(TunPermissionResult {
                success: false,
                message: format!("Failed to run sudo: {}", e),
                needs_restart: false,
            })
        }
    }
}

#[tauri::command]
pub async fn check_tun_capability_command() -> Result<bool, String> {
    Ok(check_tun_capability().await)
}

async fn check_tun_capability() -> bool {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };
    
    // Проверяем capability через getcap
    let output = std::process::Command::new("getcap")
        .arg(&current_exe)
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                println!("[STDOUT] TUN: Current capabilities: {}", output_str);
                output_str.contains("cap_net_admin")
            } else {
                println!("[STDOUT] TUN: getcap failed: {}", String::from_utf8_lossy(&output.stderr));
                false
            }
        }
        Err(e) => {
            println!("[STDOUT] TUN: Failed to run getcap: {}", e);
            false
        }
    }
}

#[tauri::command]
pub async fn build_release_version() -> Result<String, String> {
    log::info!("[BUILD] Building release version");
    println!("[STDOUT] BUILD: Building release version");
    
    // Получаем путь к проекту Tauri
    let project_path = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?
        .join("src-tauri");
    
    println!("[STDOUT] BUILD: Project path: {}", project_path.display());
    
    // Запускаем сборку
    let output = std::process::Command::new("cargo")
        .args(&["build", "--release"])
        .current_dir(&project_path)
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                let release_path = project_path.join("target/release/crab-sock");
                println!("[STDOUT] BUILD: Release build successful: {}", release_path.display());
                
                // Устанавливаем capability для release версии
                let setcap_output = std::process::Command::new("sudo")
                    .args(&["setcap", "cap_net_admin=ep", &release_path.to_string_lossy()])
                    .output();
                
                match setcap_output {
                    Ok(setcap_output) => {
                        if setcap_output.status.success() {
                            println!("[STDOUT] BUILD: Capability set for release version");
                            Ok(format!("Release version built successfully: {}", release_path.display()))
                        } else {
                            let error = String::from_utf8_lossy(&setcap_output.stderr);
                            println!("[STDOUT] BUILD: Failed to set capability: {}", error);
                            Ok(format!("Release version built but capability setting failed: {}", error))
                        }
                    }
                    Err(e) => {
                        println!("[STDOUT] BUILD: Failed to run pkexec: {}", e);
                        Ok(format!("Release version built but capability setting failed: {}", e))
                    }
                }
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                println!("[STDOUT] BUILD: Build failed: {}", error);
                Err(format!("Build failed: {}", error))
            }
        }
        Err(e) => {
            println!("[STDOUT] BUILD: Failed to run cargo: {}", e);
            Err(format!("Failed to run cargo: {}", e))
        }
    }
}
