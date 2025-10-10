use crate::config::ProxyConfig;
use crate::proxy::{ProxyManager, ConnectionStatus};
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use serde::Serialize;
use tauri::Emitter;

static PROXY_MANAGER: Lazy<Mutex<ProxyManager>> = Lazy::new(|| Mutex::new(ProxyManager::new()));

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
