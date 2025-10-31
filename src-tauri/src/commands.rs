use crate::config::ProxyConfig;
use crate::proxy::{ProxyManager, ConnectionStatus};
use crate::config_manager::{ConfigManager, ConfigFile, AppSettings, RoutingMode};
use crate::system_proxy::{SystemProxyManager, ProxySettings};
use crate::tun_manager::TunManager;
use crate::linux_capabilities::has_cap_net_admin;
#[cfg(target_os = "windows")]
use crate::windows_firewall::ensure_firewall_rules_allow;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use serde::Serialize;
use tauri::Emitter;
#[cfg(target_os = "windows")]
use std::process::Stdio;

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
    // Do not log secrets; only log scheme
    let scheme = if config_string.starts_with("ss://") {
        "ss"
    } else if config_string.starts_with("vmess://") {
        "vmess"
    } else if config_string.starts_with("vless://") {
        "vless"
    } else if config_string.starts_with("trojan://") {
        "trojan"
    } else {
        "unknown"
    };
    log::info!("[PARSE] Received config string (scheme={}): [REDACTED]", scheme);

    let config = ProxyConfig::from_config_string(&config_string)
        .map_err(|e| e.to_string())?;

    // Log masked config (password replaced by asterisks of equal length)
    log::info!("[PARSE] Successfully parsed config: {:?}", config.masked());
    Ok(config)
}

#[tauri::command]
pub async fn ensure_admin_for_tun() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        if is_elevated_windows() { return Ok(true); }
        // Try to relaunch elevated via PowerShell (UAC prompt)
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_str = exe.to_string_lossy().replace('"', "\"");
        let ps = format!(
            "Start-Process -FilePath \"{}\" -Verb RunAs -ArgumentList '--set-routing=tun'",
            exe_str
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            // Advise frontend to let this instance exit; elevated one will start
            Ok(false)
        } else {
            Err("Failed to trigger elevation".into())
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(true)
    }
}

#[tauri::command]
pub async fn exit_app(app: tauri::AppHandle) -> Result<(), String> {
    let _ = app.exit(0);
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    // Use PowerShell to check admin group membership to avoid Win32 FFI
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        ])
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(Stdio::null())
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            return s.contains("true");
        }
    }
    false
}

#[tauri::command]
pub async fn connect_vpn(window: tauri::Window, config: ProxyConfig) -> Result<(), String> {
    // Log masked config to avoid leaking secrets
    log::info!("[CONNECT] Starting VPN connection with config: {:?}", config.masked());

    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.connect(config.clone()).await
    };

    match result {
        Ok(_) => {
            log::info!("[CONNECT] VPN proxy started successfully");
            // Export remote server host/port for TUN route exclusions (Windows)
            #[cfg(target_os = "windows")]
            {
                // Common route exclusion (for any upstream)
                std::env::set_var("SS_REMOTE_HOST", config.server.clone());
                std::env::set_var("SS_REMOTE_PORT", config.port.to_string());
                // Export outbound params for sing-box TUN integration
                match config.proxy_type {
                    crate::config::ProxyType::VLESS => {
                        std::env::set_var("SB_OUTBOUND_TYPE", "vless");
                        std::env::set_var("SB_VLESS_SERVER", &config.server);
                        std::env::set_var("SB_VLESS_PORT", config.port.to_string());
                        if let Some(uuid) = &config.uuid { std::env::set_var("SB_VLESS_UUID", uuid); }
                        if let Some(security) = &config.security { std::env::set_var("SB_VLESS_SECURITY", security); }
                        if let Some(sni) = &config.sni { std::env::set_var("SB_VLESS_SNI", sni); }
                        if let Some(fp) = &config.fingerprint { std::env::set_var("SB_VLESS_FP", fp); }
                        if let Some(flow) = &config.flow { std::env::set_var("SB_VLESS_FLOW", flow); }
                        if let Some(pbk) = &config.reality_public_key { std::env::set_var("SB_VLESS_PBK", pbk); }
                        if let Some(sid) = &config.reality_short_id { std::env::set_var("SB_VLESS_SID", sid); }
                        if let Some(spx) = &config.reality_spx { std::env::set_var("SB_VLESS_SPX", spx); }
                    }
                    crate::config::ProxyType::Shadowsocks => {
                        // For TUN use sing-box outbound=shadowsocks directly to upstream
                        std::env::set_var("SB_OUTBOUND_TYPE", "shadowsocks");
                        std::env::set_var("SB_SS_SERVER", &config.server);
                        std::env::set_var("SB_SS_PORT", config.port.to_string());
                        if let Some(method) = &config.method { std::env::set_var("SB_SS_METHOD", method); }
                        if let Some(password) = &config.password { std::env::set_var("SB_SS_PASSWORD", password); }
                    }
                    _ => {
                        std::env::set_var("SB_OUTBOUND_TYPE", "socks");
                    }
                }
            }
            // On Windows, proactively allow app in firewall (single prompt, cached by checking existing rules)
            #[cfg(target_os = "windows")]
            if let Err(e) = ensure_firewall_rules_allow() { log::warn!("[CONNECT][WIN] firewall allow failed: {}", e); }
            
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
                    
                    // Помечаем прокси как Connected только после успешной проверки
                    {
                        let manager = PROXY_MANAGER.lock().await;
                        manager.mark_connected().await;
                    }

                    // Отправляем событие о верификации IP
                    println!("[STDOUT] Sending ip_verified event to frontend: ip={}, country={:?}", 
                        ip_info.ip, ip_info.country);
                    
                    let ip_result = window.emit("ip_verified", ip_info);
                    
                    match ip_result {
                        Ok(_) => println!("[STDOUT] Successfully sent ip_verified event to frontend"),
                        Err(e) => println!("[STDOUT] Failed to send ip_verified event: {:?}", e),
                    }
                    
                    // Применяем режим маршрутизации из настроек (по умолчанию SystemProxy)
                    let settings = ConfigManager::new()
                        .map_err(|e| e.to_string())?
                        .load_configs().await
                        .map_err(|e| e.to_string())?
                        .settings;
                    match settings.routing_mode {
                        RoutingMode::Tun => {
                            log::info!("[ROUTING] Applying routing mode: TUN");
                            println!("[STDOUT] ROUTING: Applying mode TUN");
                            // Clear system proxy on all platforms when switching to TUN
                            let _ = clear_system_proxy().await;
                            if let Err(e) = enable_tun_mode().await { log::warn!("[CONNECT] Failed to enable TUN mode automatically: {}", e); }
                        }
                        RoutingMode::SystemProxy => {
                            log::info!("[ROUTING] Applying routing mode: SystemProxy");
                            println!("[STDOUT] ROUTING: Applying mode SystemProxy");
                            // Ensure TUN is disabled if it was on
                            let _ = disable_tun_mode().await;
                            // Устанавливаем системный прокси на наш локальный SOCKS5
                            let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                            let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                            if let Err(e) = system_manager.set_system_proxy(&proxy_settings).await {
                                log::warn!("[CONNECT] Failed to set system proxy automatically: {}", e);
                            }
                        }
                    }

                    log::info!("[CONNECT] VPN connected and verified successfully");
                    Ok(())
                }
                Err(e) => {
                    log::warn!("[CONNECT] VPN connected but IP verification failed: {}", e);
                    // also reflect error in ProxyManager
                    {
                        let manager = PROXY_MANAGER.lock().await;
                        manager.mark_error(e.clone()).await;
                    }
                    
                    // Не включаем системный прокси/TUN при провале проверки IP, чтобы не ломать сеть
                    let _ = window.emit("status", StatusEvent {
                        status: "connected".into(),
                    });
                    
                    log::info!("[CONNECT] VPN connected (IP verification failed) - system proxy unchanged");
                    Ok(())
                }
            }
        }
        Err(e) => {
            // If already connected/connecting, gracefully disconnect and retry once
            if matches!(e, crate::error::VpnError::AlreadyConnected) {
                log::warn!("[CONNECT] Already connected - attempting seamless reconnect with new config");
                {
                    let manager = PROXY_MANAGER.lock().await;
                    let _ = manager.disconnect().await;
                }
                // brief pause to let tasks tear down sockets
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

                let retry = {
                    let manager = PROXY_MANAGER.lock().await;
                    manager.connect(config).await
                };

                match retry {
                    Ok(_) => {
                        log::info!("[CONNECT] Reconnect attempt started after seamless disconnect");
                        // fall through to the same success path by recursively verifying IP
                        // Ждем немного, чтобы прокси успел запуститься
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        match get_ip().await {
                            Ok(ip_info) => {
                                let _ = window.emit("status", StatusEvent { status: "connected".into() });
                                {
                                    let manager = PROXY_MANAGER.lock().await;
                                    manager.mark_connected().await;
                                }
                                let _ = window.emit("ip_verified", ip_info);
                                let settings = ConfigManager::new().map_err(|e| e.to_string())?.load_configs().await.map_err(|e| e.to_string())?.settings;
                                match settings.routing_mode {
                                    RoutingMode::Tun => {
                                        log::info!("[ROUTING] Applying routing mode: TUN");
                                        println!("[STDOUT] ROUTING: Applying mode TUN");
                                        let _ = clear_system_proxy().await;
                                        if let Err(e) = enable_tun_mode().await { log::warn!("[CONNECT] Failed to enable TUN mode automatically: {}", e); }
                                    }
                                    RoutingMode::SystemProxy => {
                                        log::info!("[ROUTING] Applying routing mode: SystemProxy");
                                        println!("[STDOUT] ROUTING: Applying mode SystemProxy");
                                        let _ = disable_tun_mode().await;
                                        let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                                        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                                        let _ = system_manager.set_system_proxy(&proxy_settings).await;
                                    }
                                }
                                Ok(())
                            }
                            Err(e) => {
                                log::warn!("[CONNECT] Reconnect started but IP verification failed: {}", e);
                                {
                                    let manager = PROXY_MANAGER.lock().await;
                                    manager.mark_error(e.clone()).await;
                                }
                                let _ = window.emit("status", StatusEvent { status: "connected".into() });
                                Ok(())
                            }
                        }
                    }
                    Err(e2) => {
                        log::error!("[CONNECT] Reconnect failed: {}", e2);
                        let _ = window.emit("error", serde_json::json!({ "message": e2.to_string() }));
                        let _ = window.emit("status", StatusEvent { status: "disconnected".into() });
                        Err(e2.to_string())
                    }
                }
            } else {
                log::error!("[CONNECT] VPN connection failed: {}", e);
                let _ = window.emit("error", serde_json::json!({
                    "message": e.to_string(),
                }));
                let _ = window.emit("status", StatusEvent { status: "disconnected".into() });
                Err(e.to_string())
            }
        }
    }
}

#[tauri::command]
pub async fn disconnect_vpn(window: tauri::Window) -> Result<(), String> {
    log::info!("[DISCONNECT] Disconnecting VPN");

    // Сначала отключаем TUN и системный прокси. Делаем это в отдельной задаче, чтобы жесткий трафик мог завершиться корректно
    let tun_task = tauri::async_runtime::spawn(async move {
        let _ = disable_tun_mode().await;
    });

    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.disconnect().await
    };

    match result {
        Ok(_) => {
            let _ = window.emit("status", StatusEvent {
                status: "disconnected".into(),
            });

            let _ = tun_task.await; // дожидаемся выключения TUN
            log::info!("[DISCONNECT] VPN disconnected");
            Ok(())
        }
        Err(e) => {
            log::error!("[DISCONNECT] VPN disconnect failed: {}", e);
            Err(e.to_string())
        }
    }
}

// Internal helper for shutdown paths where we don't need to emit window events
pub async fn disconnect_vpn_silent() {
    let manager = PROXY_MANAGER.lock().await;
    let _ = manager.disconnect().await;
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

    // Определяем текущий статус и режим маршрутизации, чтобы понять, использовать ли локальный SOCKS
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };
    let routing_mode = ConfigManager::new()
        .map_err(|e| e.to_string())?
        .load_configs().await
        .map_err(|e| e.to_string())?
        .settings
        .routing_mode;

    let client_builder = reqwest::Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(10))
        .tcp_keepalive(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(8))
        .timeout(std::time::Duration::from_secs(12))
        .no_proxy();

    // Если SystemProxy — проверяем через локальный SOCKS, иначе (Tun/другое) — без прокси
    let use_socks = matches!(status, ConnectionStatus::Connected | ConnectionStatus::Connecting)
        && matches!(routing_mode, RoutingMode::SystemProxy);
    let client = if use_socks {
        let proxy_url = std::env::var("SOCKS_PROXY").unwrap_or_else(|_| "socks5h://127.0.0.1:1080".to_string());
        client_builder
            .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| format!("Failed to create SOCKS5 proxy: {}", e))?)
            .build()
            .map_err(|e| format!("Failed to create proxied HTTP client: {}", e))?
    } else {
        client_builder
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?
    };

    // Набор публичных сервисов для получения IP. Идем по порядку, пока не получится.
    // 1) ipinfo.io — ip + country
    // 2) ipwho.is — ip + country_code
    // 3) ip-api.com — query + countryCode
    // 4) api.ipify.org — только ip
    // 5) icanhazip.com — только ip (text/plain)
    let mut last_error: Option<String> = None;

    // ipinfo.io
    if last_error.is_none() {
        match client.get("https://ipinfo.io/json").send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str()) {
                                let country = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let ip = ip_str.to_string();
                                log::info!("[IP] Fetched via ipinfo.io: {} {:?}", ip, country);
                                return Ok(IpInfo { ip, country });
                            }
                        }
                        Err(e) => { last_error = Some(format!("ipinfo parse error: {}", e)); }
                    }
                } else {
                    last_error = Some(format!("ipinfo status: {}", resp.status()));
                }
            }
            Err(e) => { last_error = Some(format!("ipinfo request error: {}", e)); }
        }
    }

    // ipwho.is
    match client.get("https://ipwho.is/").send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str()) {
                            let country = json.get("country_code").and_then(|v| v.as_str()).map(|s| s.to_string());
                            let ip = ip_str.to_string();
                            log::info!("[IP] Fetched via ipwho.is: {} {:?}", ip, country);
                            return Ok(IpInfo { ip, country });
                        }
                    }
                    Err(e) => { last_error = Some(format!("ipwho.is parse error: {}", e)); }
                }
            } else {
                last_error = Some(format!("ipwho.is status: {}", resp.status()));
            }
        }
        Err(e) => { last_error = Some(format!("ipwho.is request error: {}", e)); }
    }

    // ip-api.com
    match client.get("https://ip-api.com/json").send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if let Some(ip_str) = json.get("query").and_then(|v| v.as_str()) {
                            let country = json.get("countryCode").and_then(|v| v.as_str()).map(|s| s.to_string());
                            let ip = ip_str.to_string();
                            log::info!("[IP] Fetched via ip-api.com: {} {:?}", ip, country);
                            return Ok(IpInfo { ip, country });
                        }
                    }
                    Err(e) => { last_error = Some(format!("ip-api parse error: {}", e)); }
                }
            } else {
                last_error = Some(format!("ip-api status: {}", resp.status()));
            }
        }
        Err(e) => { last_error = Some(format!("ip-api request error: {}", e)); }
    }

    // api.ipify.org
    match client.get("https://api.ipify.org?format=json").send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str()) {
                            let ip = ip_str.to_string();
                            log::info!("[IP] Fetched via ipify: {}", ip);
                            return Ok(IpInfo { ip, country: None });
                        }
                    }
                    Err(e) => { last_error = Some(format!("ipify parse error: {}", e)); }
                }
            } else {
                last_error = Some(format!("ipify status: {}", resp.status()));
            }
        }
        Err(e) => { last_error = Some(format!("ipify request error: {}", e)); }
    }

    // icanhazip.com (plain text)
    match client.get("https://icanhazip.com").send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.text().await {
                    Ok(text) => {
                        let ip = text.trim().to_string();
                        if !ip.is_empty() {
                            log::info!("[IP] Fetched via icanhazip: {}", ip);
                            return Ok(IpInfo { ip, country: None });
                        }
                    }
                    Err(e) => { last_error = Some(format!("icanhazip parse error: {}", e)); }
                }
            } else {
                last_error = Some(format!("icanhazip status: {}", resp.status()));
            }
        }
        Err(e) => { last_error = Some(format!("icanhazip request error: {}", e)); }
    }

    Err(last_error.unwrap_or_else(|| "Failed to fetch IP from all providers".to_string()))
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

// App settings
#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    let manager = ConfigManager::new().map_err(|e| e.to_string())?;
    let file = manager.load_configs().await.map_err(|e| e.to_string())?;
    Ok(file.settings)
}

#[tauri::command]
pub async fn set_routing_mode(mode: String) -> Result<(), String> {
    let manager = ConfigManager::new().map_err(|e| e.to_string())?;
    let mut file = manager.load_configs().await.map_err(|e| e.to_string())?;
    let new_mode = match mode.to_lowercase().as_str() { "tun" => RoutingMode::Tun, _ => RoutingMode::SystemProxy };
    let old_mode = file.settings.routing_mode.clone();

    if old_mode != new_mode { log::info!("[ROUTING] Switching routing mode: {:?} -> {:?}", old_mode, new_mode); println!("[STDOUT] ROUTING: switch {:?} -> {:?}", old_mode, new_mode); }

    file.settings.routing_mode = new_mode.clone();
    manager.save_configs(&file).await.map_err(|e| e.to_string())?;

    // Live-apply when connected
    let status = {
        let proxy_manager = PROXY_MANAGER.lock().await;
        proxy_manager.get_status().await
    };
    if matches!(status, ConnectionStatus::Connected) {
        match new_mode {
            RoutingMode::Tun => {
                // Switch to TUN: always clear system proxy so kernel routing dominates
                log::info!("[ROUTING] Live-apply: enabling TUN (clearing system proxy)");
                let _ = clear_system_proxy().await; // ignore errors
                if let Err(e) = enable_tun_mode().await { log::warn!("[ROUTING] Live-apply TUN failed: {}", e); }
            }
            RoutingMode::SystemProxy => {
                // Switch to System Proxy: disable TUN, set proxy
                log::info!("[ROUTING] Live-apply: enabling System Proxy (disabling TUN)");
                let _ = disable_tun_mode().await;
                let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                if let Err(e) = system_manager.set_system_proxy(&proxy_settings).await { log::warn!("[ROUTING] Live-apply System Proxy failed: {}", e); }
            }
        }
    }

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

// removed update_settings: settings UI eliminated

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
            let has_capability = has_cap_net_admin();
            println!("[STDOUT] TUN capability check: {}", has_capability);
            
            // Запускаем TUN интерфейс
            let mut tun_manager = TUN_MANAGER.lock().await;
            match tun_manager.start().await {
                Ok(_) => {
                    println!("[STDOUT] TUN interface started successfully");

                    // В TUN режиме на Windows системный прокси не включаем
                    #[cfg(not(target_os = "windows"))]
                    {
                        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                        system_manager.set_tun_mode(true).await
                            .map_err(|e| {
                                println!("[STDOUT] Failed to enable TUN mode: {}", e);
                                format!("Failed to enable TUN mode: {}", e)
                            })?;
                    }
                    
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

