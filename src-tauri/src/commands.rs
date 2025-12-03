use crate::config::ProxyConfig;
use crate::proxy::{ProxyManager, ConnectionStatus};
use crate::config_manager::{ConfigManager, ConfigFile, AppSettings, RoutingMode};
use crate::system_proxy::{SystemProxyManager, ProxySettings};
use crate::tun_manager::TunManager;
#[cfg(target_os = "windows")]
use crate::windows_firewall::ensure_firewall_rules_allow;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use serde::Serialize;
use tauri::Emitter;
#[cfg(target_os = "windows")]
use std::process::Stdio;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;
use crate::openvpn;
use crate::openvpn::{OpenVpnManager, OpenVpnConfigInfo};

#[cfg(target_os = "macos")]
fn is_root_macos() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn relaunch_elevated_with_args_macos(args: &[&str]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let app_bundle = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| "Failed to locate .app bundle".to_string())?;
    let app_path = app_bundle.to_string_lossy().to_string();
    // Build shell-safe single-quoted args: 'foo' becomes 'foo' with internal ' escaped as '\''.
    fn sh_single_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
    let args_joined = args.iter().map(|a| sh_single_quote(a)).collect::<Vec<_>>().join(" ");
    // Write a temporary script that relaunches the app with args
    let mut script_path = std::env::temp_dir();
    script_path.push("crabsock-relaunch-elev.sh");
    let script = format!(
        "#!/bin/sh\nset -e\nexport PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin\nopen -n {} --args {}\n",
        sh_single_quote(&app_path),
        args_joined
    );
    std::fs::write(&script_path, script).map_err(|e| e.to_string())?;
    if let Ok(meta) = std::fs::metadata(&script_path) {
        let mut p = meta.permissions();
        p.set_mode(0o755);
        let _ = std::fs::set_permissions(&script_path, p);
    }
    // Run the script via AppleScript with admin privileges
    let osa = format!(
        "do shell script \"/bin/sh '{}'\" with administrator privileges",
        script_path.to_string_lossy().replace('"', "\\\"")
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &osa])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else {
        let se = String::from_utf8_lossy(&out.stderr);
        Err(format!("Failed to trigger elevation (osascript): {}", se.trim()))
    }
}

#[cfg(target_os = "macos")]
fn macos_tun_routes_ready() -> bool {
    use std::process::Command;
    if let Ok(out) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let mut has_utun_default = false;
            let mut has_half_0 = false;
            let mut has_half_128 = false;
            // macOS sometimes prints segmented coverage instead of 0/1; track common segments via utun*
            let mut seg_hits = 0usize;
            let seg_targets = ["1", "2/7", "4/6", "8/5", "16/4", "32/3", "64/2"];
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Typical macOS columns: Destination Gateway Flags Netif Expire
                if parts.len() < 4 { continue; }
                let dest = parts[0];
                // Netif is usually the penultimate column
                let netif_idx = if parts.len() >= 4 { parts.len().saturating_sub(2) } else { continue };
                let netif = parts[netif_idx];
                if netif.starts_with("utun") {
                    if dest == "default" { has_utun_default = true; }
                    if dest == "0/1" || dest == "0.0.0.0/1" { has_half_0 = true; }
                    if dest == "128/1" || dest == "128.0.0.0/1" { has_half_128 = true; }
                    if seg_targets.iter().any(|t| t == &dest) {
                        seg_hits += 1;
                    }
                }
            }
            // Consider ready if:
            // - default route via utun*, or
            // - both half routes present, or
            // - 128/1 present and we see several segmented routes via utun* (covers 0/1 split pattern)
            return has_utun_default || (has_half_0 && has_half_128) || (has_half_128 && seg_hits >= 4);
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn relaunch_elevated_with_args(args: &[&str]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_str = exe.to_string_lossy().replace('"', "\"");
    // Join args with spaces; escape single quotes for PowerShell string literal
    let joined = args.iter().map(|a| a.replace("'", "''")).collect::<Vec<_>>().join(" ");
    let ps = format!(
        "Start-Process -FilePath \"{}\" -Verb RunAs -WindowStyle Hidden -ArgumentList '{}'",
        exe_str, joined
    );
    let status = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command", &ps])
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() { Ok(()) } else { Err("Failed to trigger elevation".into()) }
}

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

// ===================== OpenVPN Commands =====================
#[tauri::command]
pub async fn openvpn_list_configs(app: tauri::AppHandle) -> Result<Vec<OpenVpnConfigInfo>, String> {
    OpenVpnManager::list_configs(&app)
}

#[tauri::command]
pub async fn openvpn_add_config(app: tauri::AppHandle, name: String, content: String) -> Result<(), String> {
    OpenVpnManager::add_config(&app, &name, &content)
}

#[tauri::command]
pub async fn openvpn_remove_config(app: tauri::AppHandle, name: String) -> Result<(), String> {
    OpenVpnManager::remove_config(&app, &name)
}

#[tauri::command]
pub async fn openvpn_connect(app: tauri::AppHandle, name: String) -> Result<(), String> {
    // On Windows: ensure the whole app is elevated, do not elevate openvpn.exe directly
    #[cfg(target_os = "windows")]
    {
        if !is_elevated_windows() {
            let arg = format!(r#"--openvpn-connect="{}""#, name.replace('"', "\""));
            relaunch_elevated_with_args(&["--elevated-relaunch", &arg])?;
            let _ = app.exit(0);
            return Ok(());
        }
    }

    OpenVpnManager::connect(&app, &name)
}

#[tauri::command]
pub async fn openvpn_disconnect(app: tauri::AppHandle) -> Result<(), String> {
    OpenVpnManager::disconnect(&app)
}

#[tauri::command]
pub async fn openvpn_status() -> Result<(bool, bool), String> {
    Ok(OpenVpnManager::status())
}

// === OpenVPN log/status helpers for frontend replay ===
#[tauri::command]
pub async fn openvpn_get_recent_logs(limit: usize) -> Result<Vec<String>, String> {
    Ok(openvpn::get_recent_logs(limit))
}

#[tauri::command]
pub async fn openvpn_current_status() -> Result<openvpn::OpenVpnStatusEvent, String> {
    Ok(openvpn::current_status_event())
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
        // Relaunch elevated via shared helper (single UAC prompt)
        relaunch_elevated_with_args(&["--elevated-relaunch", "--set-routing=tun"])?;
        // Advise frontend to let this instance exit; elevated one will start
        Ok(false)
    }
    #[cfg(target_os = "macos")]
    {
        if is_root_macos() { return Ok(true); }
        // Relaunch elevated via AppleScript (admin privileges) passing routing override
        relaunch_elevated_with_args_macos(&["--elevated-relaunch", "--set-routing=tun"])
            .map_err(|e| format!("Failed to request admin privileges: {}", e))?;
        // The elevated instance will start separately; this one should exit
        Ok(false)
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux sing-box is started via a pkexec wrapper (similar to nekoray)
        // Privileges are requested automatically when TUN starts - capabilities are NOT required
        log::info!("[TUN][LINUX] TUN will use pkexec wrapper - no pre-setup needed");
        Ok(true)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Ok(true)
    }
}


#[tauri::command]
pub async fn exit_app(app: tauri::AppHandle) -> Result<(), String> {
    // Ensure OpenVPN and sing-box are stopped before exiting
    // Stop proxy pipelines (sing-box/shadowsocks) silently
    disconnect_vpn_silent().await;
    // Clear system proxy explicitly to avoid leaving broken settings
    {
        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
        let _ = system_manager.clear_system_proxy().await;
    }
    crate::openvpn::OpenVpnManager::disconnect_silent();
    let _ = app.exit(0);
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    // Use PowerShell to check admin group membership to avoid Win32 FFI
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
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

    // Read desired routing mode upfront to decide whether to start local proxy or go straight to TUN
    let desired_mode = ConfigManager::new()
        .map_err(|e| e.to_string())?
        .load_configs().await
        .map_err(|e| e.to_string())?
        .settings
        .routing_mode;

    if matches!(desired_mode, RoutingMode::Tun) {
        // Do NOT start Rust proxy in TUN mode. Configure sing-box outbound directly to upstream.
        log::info!("[CONNECT] Routing mode is TUN — skipping local proxy, configuring sing-box outbound");
        // Export remote server for route exclusions (all OS)
        std::env::set_var("SS_REMOTE_HOST", config.server.clone());
        std::env::set_var("SS_REMOTE_PORT", config.port.to_string());
        // Set outbound for sing-box based on config (all OS for TUN)
        match config.proxy_type {
            crate::config::ProxyType::VLESS => {
                std::env::remove_var("SB_SS_SERVER");
                std::env::remove_var("SB_SS_PORT");
                std::env::remove_var("SB_SS_METHOD");
                std::env::remove_var("SB_SS_PASSWORD");
                std::env::set_var("SB_OUTBOUND_TYPE", "vless");
                std::env::remove_var("ACL_HTTP_PORT");
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
                std::env::remove_var("SB_VLESS_SERVER");
                std::env::remove_var("SB_VLESS_PORT");
                std::env::remove_var("SB_VLESS_UUID");
                std::env::remove_var("SB_VLESS_SECURITY");
                std::env::remove_var("SB_VLESS_SNI");
                std::env::remove_var("SB_VLESS_FP");
                std::env::remove_var("SB_VLESS_FLOW");
                std::env::remove_var("SB_VLESS_PBK");
                std::env::remove_var("SB_VLESS_SID");
                std::env::remove_var("SB_VLESS_SPX");
                std::env::set_var("SB_OUTBOUND_TYPE", "shadowsocks");
                std::env::set_var("ACL_HTTP_PORT", "9080");
                std::env::set_var("SB_SS_SERVER", &config.server);
                std::env::set_var("SB_SS_PORT", config.port.to_string());
                if let Some(method) = &config.method { std::env::set_var("SB_SS_METHOD", method); }
                if let Some(password) = &config.password { std::env::set_var("SB_SS_PASSWORD", password); }
            }
            _ => {
                // fallback to socks (rare)
                std::env::remove_var("SB_VLESS_SERVER");
                std::env::remove_var("SB_VLESS_PORT");
                std::env::remove_var("SB_VLESS_UUID");
                std::env::remove_var("SB_VLESS_SECURITY");
                std::env::remove_var("SB_VLESS_SNI");
                std::env::remove_var("SB_VLESS_FP");
                std::env::remove_var("SB_VLESS_FLOW");
                std::env::remove_var("SB_VLESS_PBK");
                std::env::remove_var("SB_VLESS_SID");
                std::env::remove_var("SB_VLESS_SPX");
                std::env::remove_var("SB_SS_SERVER");
                std::env::remove_var("SB_SS_PORT");
                std::env::remove_var("SB_SS_METHOD");
                std::env::remove_var("SB_SS_PASSWORD");
                std::env::set_var("SB_OUTBOUND_TYPE", "socks");
            }
        }
        // Clear system proxy before enabling TUN
        let _ = clear_system_proxy().await;
        // Enable TUN now (will spawn sing-box) - IP verification handled inside enable_tun_mode
        if let Err(e) = enable_tun_mode(window.clone()).await {
            log::error!("[CONNECT][TUN] Failed to enable TUN: {}", e);
            return Err(e);
        }
        let _ = window.emit("status", StatusEvent { status: "connected".into() });
        return Ok(());
    }

    // SystemProxy flow (default): start local proxy first
    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.connect(config.clone()).await
    };

    match result {
        Ok(_) => {
            log::info!("[CONNECT] VPN proxy started successfully");
            // Export remote server host/port for TUN route exclusions (all OS)
            {
                std::env::set_var("SS_REMOTE_HOST", config.server.clone());
                std::env::set_var("SS_REMOTE_PORT", config.port.to_string());
                // Export outbound params for sing-box TUN integration
                #[cfg(any(target_os = "windows", target_os = "macos"))]
                match config.proxy_type {
                    crate::config::ProxyType::VLESS => {
                        // Clear SS env to avoid stale values affecting TUN config
                        std::env::remove_var("SB_SS_SERVER");
                        std::env::remove_var("SB_SS_PORT");
                        std::env::remove_var("SB_SS_METHOD");
                        std::env::remove_var("SB_SS_PASSWORD");
                        std::env::set_var("SB_OUTBOUND_TYPE", "vless");
                        std::env::remove_var("ACL_HTTP_PORT"); // use default 8080 for sing-box http inbound
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
                        // Clear VLESS env to avoid stale values affecting TUN config
                        std::env::remove_var("SB_VLESS_SERVER");
                        std::env::remove_var("SB_VLESS_PORT");
                        std::env::remove_var("SB_VLESS_UUID");
                        std::env::remove_var("SB_VLESS_SECURITY");
                        std::env::remove_var("SB_VLESS_SNI");
                        std::env::remove_var("SB_VLESS_FP");
                        std::env::remove_var("SB_VLESS_FLOW");
                        std::env::remove_var("SB_VLESS_PBK");
                        std::env::remove_var("SB_VLESS_SID");
                        std::env::remove_var("SB_VLESS_SPX");
                        // For TUN use sing-box outbound=shadowsocks directly to upstream
                        std::env::set_var("SB_OUTBOUND_TYPE", "shadowsocks");
                        // Use a non-conflicting HTTP port for ACL proxy when SS is active
                        std::env::set_var("ACL_HTTP_PORT", "9080");
                        std::env::set_var("SB_SS_SERVER", &config.server);
                        std::env::set_var("SB_SS_PORT", config.port.to_string());
                        if let Some(method) = &config.method { std::env::set_var("SB_SS_METHOD", method); }
                        if let Some(password) = &config.password { std::env::set_var("SB_SS_PASSWORD", password); }
                    }
                    _ => {
                        // Clear both env groups; fall back to socks (local)
                        std::env::remove_var("SB_VLESS_SERVER");
                        std::env::remove_var("SB_VLESS_PORT");
                        std::env::remove_var("SB_VLESS_UUID");
                        std::env::remove_var("SB_VLESS_SECURITY");
                        std::env::remove_var("SB_VLESS_SNI");
                        std::env::remove_var("SB_VLESS_FP");
                        std::env::remove_var("SB_VLESS_FLOW");
                        std::env::remove_var("SB_VLESS_PBK");
                        std::env::remove_var("SB_VLESS_SID");
                        std::env::remove_var("SB_VLESS_SPX");
                        std::env::remove_var("SB_SS_SERVER");
                        std::env::remove_var("SB_SS_PORT");
                        std::env::remove_var("SB_SS_METHOD");
                        std::env::remove_var("SB_SS_PASSWORD");
                        std::env::set_var("SB_OUTBOUND_TYPE", "socks");
                    }
                }
            }
            // On Windows, proactively allow app in firewall (single prompt, cached by checking existing rules)
            #[cfg(target_os = "windows")]
            if let Err(e) = ensure_firewall_rules_allow() { log::warn!("[CONNECT][WIN] firewall allow failed: {}", e); }
            
            // Wait a bit so that the proxy has time to start
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Check IP to confirm that the proxy works
            match get_ip().await {
                Ok(ip_info) => {
                    log::info!("[CONNECT] IP verification successful: {} ({})", ip_info.ip, ip_info.country.as_ref().unwrap_or(&"Unknown".to_string()));
                    
                    // Small delay before sending the event
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    
                    // Send regular status event
                    println!("[STDOUT] Sending status event to frontend: status=connected");
                    
                    let status_result = window.emit("status", StatusEvent {
                        status: "connected".into(),
                    });
                    
                    match status_result {
                        Ok(_) => println!("[STDOUT] Successfully sent status event to frontend"),
                        Err(e) => println!("[STDOUT] Failed to send status event: {:?}", e),
                    }
                    
                    // Mark proxy as Connected only after successful verification
                    {
                        let manager = PROXY_MANAGER.lock().await;
                        manager.mark_connected().await;
                    }

                    // Send IP verification event
                    println!("[STDOUT] Sending ip_verified event to frontend: ip={}, country={:?}", 
                        ip_info.ip, ip_info.country);
                    
                    // Save baseline IP for later change detection when TUN is enabled
                    #[allow(unused_variables)]
                    let baseline_ip = ip_info.ip.clone();
                    let ip_result = window.emit("ip_verified", ip_info);
                    
                    match ip_result {
                        Ok(_) => println!("[STDOUT] Successfully sent ip_verified event to frontend"),
                        Err(e) => println!("[STDOUT] Failed to send ip_verified event: {:?}", e),
                    }
                    
                    // Apply routing mode from settings (SystemProxy by default)
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
                            if let Err(e) = enable_tun_mode(window.clone()).await {
                                let msg = e.to_string();
                                #[cfg(target_os = "macos")]
                                {
                                    if msg.to_lowercase().contains("permit") || msg.to_lowercase().contains("priv") || !is_root_macos() {
                                        log::warn!("[CONNECT][macOS] TUN requires admin privileges. Requesting elevation and relaunch.");
                                        // Best-effort: trigger elevation relaunch to TUN mode; frontend can exit this instance
                                        if let Err(e2) = relaunch_elevated_with_args_macos(&["--elevated-relaunch", "--set-routing=tun"]) {
                                            log::error!("[CONNECT][macOS] Elevation failed: {}", e2);
                                        }
                                        // Do not fallback silently; keep current network unchanged
                                        return Err("TUN requires admin privileges; relaunching elevated".into());
                                    }
                                }
                                // Non-macOS or non-permission error: fallback to SystemProxy
                                log::warn!("[CONNECT] Failed to enable TUN mode automatically: {}. Falling back to SystemProxy.", msg);
                                let _ = disable_tun_mode().await;
                                let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                                let _ = system_manager.set_system_proxy(&proxy_settings).await;
                                log::info!("[CONNECT] Fallback to SystemProxy applied");
                            } else {
                                // TUN enabled; on macOS validate external IP changed, otherwise fallback automatically
                                #[cfg(target_os = "macos")]
                                {
                                    let window_clone = window.clone();
                                    let baseline = baseline_ip.clone();
                                    tauri::async_runtime::spawn(async move {
                                        // Wait for routes to be ready (up to ~20s) by inspecting routing table, not just time
                                        let mut ready = false;
                                        for _ in 0..40 {
                                            if macos_tun_routes_ready() {
                                                ready = true;
                                                break;
                                            }
                                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        }
                                        if !ready {
                                            log::warn!("[ROUTING][macOS] TUN routes not detected in time. Keeping TUN active and skipping early fallback.");
                                            let _ = window_clone.emit("status", StatusEvent { status: "connected".into() });
                                            // Continue without forcing fallback; IP change check below may still succeed
                                        }
                                        // After routes are ready, verify IP change (give up to ~10s)
                                        for _ in 0..20 {
                                            match get_ip().await {
                                                Ok(info2) => {
                                                    if !baseline.is_empty() && info2.ip != baseline {
                                                        log::info!("[ROUTING][macOS] TUN routes ready and external IP changed to {}", info2.ip);
                                                        return;
                                                    }
                                                }
                                                Err(e) => log::warn!("[ROUTING][macOS] IP check after TUN failed: {}", e),
                                            }
                                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        }
                                        log::warn!("[ROUTING][macOS] TUN routes ready but IP unchanged. Applying fallback to SystemProxy.");
                                        let _ = disable_tun_mode().await;
                                        let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                                        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                                        let _ = system_manager.set_system_proxy(&proxy_settings).await;
                                        let _ = window_clone.emit("status", StatusEvent { status: "connected".into() });
                                    });
                                }
                            }
                        }
                        RoutingMode::SystemProxy => {
                            log::info!("[ROUTING] Applying routing mode: SystemProxy");
                            println!("[STDOUT] ROUTING: Applying mode SystemProxy");
                            // Ensure TUN is disabled if it was on
                            let _ = disable_tun_mode().await;
                            // Set system proxy to our local SOCKS5
                            let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                            let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                            if let Err(e) = system_manager.set_system_proxy(&proxy_settings).await {
                                log::warn!("[CONNECT] Failed to set system proxy automatically: {}", e);
                            }
                            // Note: macOS HTTP/HTTPS will follow ACL_HTTP_PORT (env) inside SystemProxyManager
                            if let Ok(p) = std::env::var("ACL_HTTP_PORT") {
                                log::info!("[ROUTING] SystemProxy HTTP port (ACL_HTTP_PORT) = {}", p);
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
                    
                    // Do not enable system proxy/TUN on IP verification failure to avoid breaking network
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
                        // Wait a bit so that the proxy has time to start
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        match get_ip().await {
                            Ok(ip_info) => {
                                let _ = window.emit("status", StatusEvent { status: "connected".into() });
                                {
                                    let manager = PROXY_MANAGER.lock().await;
                                    manager.mark_connected().await;
                                }
                                // Capture baseline IP before routing changes
                                #[allow(unused_variables)]
                                let baseline_ip = ip_info.ip.clone();
                                let _ = window.emit("ip_verified", ip_info);
                                let settings = ConfigManager::new().map_err(|e| e.to_string())?.load_configs().await.map_err(|e| e.to_string())?.settings;
                                match settings.routing_mode {
                                    RoutingMode::Tun => {
                                        log::info!("[ROUTING] Applying routing mode: TUN");
                                        println!("[STDOUT] ROUTING: Applying mode TUN");
                                        let _ = clear_system_proxy().await;
                                        if let Err(e) = enable_tun_mode(window.clone()).await {
                                            let msg = e.to_string();
                                            #[cfg(target_os = "macos")]
                                            {
                                                if msg.to_lowercase().contains("permit") || msg.to_lowercase().contains("priv") || !is_root_macos() {
                                                    log::warn!("[CONNECT][macOS] TUN requires admin privileges. Requesting elevation and relaunch.");
                                                    if let Err(e2) = relaunch_elevated_with_args_macos(&["--elevated-relaunch", "--set-routing=tun"]) {
                                                        log::error!("[CONNECT][macOS] Elevation failed: {}", e2);
                                                    }
                                                    return Err("TUN requires admin privileges; relaunching elevated".into());
                                                }
                                            }
                                            log::warn!("[CONNECT] Failed to enable TUN mode automatically: {}. Falling back to SystemProxy.", msg);
                                            let _ = disable_tun_mode().await;
                                            let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                                            let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                                            let _ = system_manager.set_system_proxy(&proxy_settings).await;
                                            log::info!("[CONNECT] Fallback to SystemProxy applied");
                                        } else {
                                            // TUN enabled; on macOS validate external IP changed, otherwise fallback automatically
                                            #[cfg(target_os = "macos")]
                                            {
                                                let window_clone = window.clone();
                                                let baseline = baseline_ip.clone();
                                                tauri::async_runtime::spawn(async move {
                                                    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                                        // Wait for routes to be ready (up to ~20s)
                                        let mut ready = false;
                                        for _ in 0..40 {
                                            if macos_tun_routes_ready() {
                                                ready = true;
                                                break;
                                            }
                                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        }
                                        if !ready {
                                            log::warn!("[ROUTING][macOS] TUN routes not detected in time. Keeping TUN active and skipping early fallback.");
                                            let _ = window_clone.emit("status", StatusEvent { status: "connected".into() });
                                            // Continue without forcing fallback; IP change check below may still succeed
                                        }
                                        // After routes are ready, verify IP change (give up to ~10s)
                                        for _ in 0..20 {
                                            match get_ip().await {
                                                Ok(info2) => {
                                                    if !baseline.is_empty() && info2.ip != baseline {
                                                        log::info!("[ROUTING][macOS] TUN routes ready and external IP changed to {}", info2.ip);
                                                        return;
                                                    }
                                                }
                                                Err(e) => log::warn!("[ROUTING][macOS] IP check after TUN failed: {}", e),
                                            }
                                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        }
                                        log::warn!("[ROUTING][macOS] TUN routes ready but IP unchanged. Applying fallback to SystemProxy.");
                                        let _ = disable_tun_mode().await;
                                        let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
                                        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                                        let _ = system_manager.set_system_proxy(&proxy_settings).await;
                                        let _ = window_clone.emit("status", StatusEvent { status: "connected".into() });
                                                });
                                            }
                                        }
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

    // First disable TUN and system proxy. Do this in a separate task so that in-flight traffic can complete gracefully
    let tun_task = tauri::async_runtime::spawn(async move {
        let _ = disable_tun_mode().await;
    });

    let result = {
        let manager = PROXY_MANAGER.lock().await;
        manager.disconnect().await
    };

    match result {
        Ok(_) => {
            // Явно очищаем системный прокси на всех платформах (особенно Windows), чтобы не оставить "битый" прокси
            {
                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                let _ = system_manager.clear_system_proxy().await;
            }

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
            
            // If connected, verify IP every 30 seconds
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
                        // If IP verification fails several times in a row, the connection may be down,
                        // but we do not change status automatically yet
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

    // Determine current status and routing mode to decide whether to use local SOCKS
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

    // If SystemProxy — check via local SOCKS, otherwise (Tun/other) — without proxy
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

    // List of public services to obtain IP. Try in order until one succeeds.
    // 1) ipinfo.io — ip + country
    // 2) ipwho.is — ip + country_code
    // 3) ip-api.com — query + countryCode
    // 4) api.ipify.org — IP only
    // 5) icanhazip.com — IP only (text/plain)
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

// Commands for working with configs
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
pub async fn set_routing_mode(window: tauri::Window, mode: String) -> Result<(), String> {
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
                if let Err(e) = enable_tun_mode(window.clone()).await { log::warn!("[ROUTING] Live-apply TUN failed: {}", e); }
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

// Commands for controlling system proxy
#[tauri::command]
pub async fn set_system_proxy() -> Result<(), String> {
    log::info!("[SYSTEM_PROXY] Enabling system proxy");
    
    // Get current proxy status
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };

    match status {
        ConnectionStatus::Connected => {
            // Check whether TUN mode is enabled
            let tun_mode = {
                let system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                system_manager.is_tun_mode()
            };

            if tun_mode {
                // If TUN mode is enabled, just enable it
                let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                system_manager.set_tun_mode(true).await
                    .map_err(|e| format!("Failed to enable TUN mode: {}", e))?;
            } else {
                // Set system proxy to our SOCKS5 proxy
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

// Commands for controlling TUN mode
#[tauri::command]
pub async fn enable_tun_mode(window: tauri::Window) -> Result<(), String> {
    log::info!("[TUN] Enabling TUN mode");
    println!("[STDOUT] TUN mode enable requested");
    
    // Get current proxy status
    let status = {
        let manager = PROXY_MANAGER.lock().await;
        manager.get_status().await
    };

    // Allow TUN without local proxy if a direct outbound for sing-box is configured
    let routing_mode = ConfigManager::new()
        .map_err(|e| e.to_string())?
        .load_configs().await
        .map_err(|e| e.to_string())?
        .settings
        .routing_mode;
    let allow_without_local_proxy = matches!(routing_mode, RoutingMode::Tun)
        && std::env::var("SB_OUTBOUND_TYPE").map(|s| s != "socks").unwrap_or(true);

    match status {
        ConnectionStatus::Connected | ConnectionStatus::Connecting if !allow_without_local_proxy => {
            println!("[STDOUT] VPN is connected, starting TUN interface");
            
            // Start TUN interface (via pkexec wrapper on Linux)
            let mut tun_manager = TUN_MANAGER.lock().await;
            match tun_manager.start().await {
                Ok(_) => {
                    println!("[STDOUT] TUN interface started successfully");

                    // In TUN mode on Windows we do not enable system proxy
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

                    // Check and send updated IP to frontend
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    match get_ip().await {
                        Ok(ip_info) => {
                            log::info!("[TUN] IP verification: {} ({})", ip_info.ip, ip_info.country.as_deref().unwrap_or("Unknown"));
                            let _ = window.emit("ip_verified", ip_info);
                        }
                        Err(e) => {
                            log::warn!("[TUN] IP verification failed: {}", e);
                        }
                    }

                    Ok(())
                }
                Err(e) => {
                    println!("[STDOUT] Failed to start TUN interface: {}", e);
                    
                    // Check whether the error is related to permissions
                    let error_msg = e.to_string();
                    if error_msg.contains("permissions") || error_msg.contains("sudo") || error_msg.contains("pkexec") {
                        Err("TUN Mode requires administrator privileges (pkexec). Please grant permissions when prompted.".to_string())
                    } else {
                        Err(format!("Failed to start TUN interface: {}", e))
                    }
                }
            }
        }
        _ => {
            if !allow_without_local_proxy {
                let error_msg = "VPN must be connected to enable TUN mode";
                println!("[STDOUT] {}", error_msg);
                return Err(error_msg.to_string());
            }
            // Direct outbound: start TUN without local proxy
            println!("[STDOUT] Starting TUN interface without local proxy (direct outbound)");
            let mut tun_manager = TUN_MANAGER.lock().await;
            match tun_manager.start().await {
                Ok(_) => {
                    #[cfg(not(target_os = "windows"))]
                    {
                        let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
                        system_manager.set_tun_mode(true).await
                            .map_err(|e| {
                                println!("[STDOUT] Failed to enable TUN mode: {}", e);
                                format!("Failed to enable TUN mode: {}", e)
                            })?;
                    }
                    println!("[STDOUT] TUN mode enabled successfully (direct outbound)");
                    log::info!("[TUN] TUN mode enabled successfully (direct outbound)");

                    // Check and send updated IP to frontend
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    match get_ip().await {
                        Ok(ip_info) => {
                            log::info!("[TUN] IP verification: {} ({})", ip_info.ip, ip_info.country.as_deref().unwrap_or("Unknown"));
                            let _ = window.emit("ip_verified", ip_info);
                        }
                        Err(e) => {
                            log::warn!("[TUN] IP verification failed: {}", e);
                        }
                    }

                    Ok(())
                }
                Err(e) => {
                    println!("[STDOUT] Failed to start TUN interface: {}", e);
                    let error_msg = e.to_string();
                    if error_msg.contains("permissions") || error_msg.contains("sudo") || error_msg.contains("pkexec") {
                        Err("TUN Mode requires administrator privileges (pkexec). Please grant permissions when prompted.".to_string())
                    } else {
                        Err(format!("Failed to start TUN interface: {}", e))
                    }
                }
            }
        }
    }
}

#[tauri::command]
pub async fn disable_tun_mode() -> Result<(), String> {
    log::info!("[TUN] Disabling TUN mode");
    println!("[STDOUT] TUN mode disable requested");
    
    // Disable TUN mode in the system proxy manager
    let mut system_manager = SYSTEM_PROXY_MANAGER.lock().await;
    system_manager.set_tun_mode(false).await
        .map_err(|e| {
            println!("[STDOUT] Failed to disable TUN mode: {}", e);
            format!("Failed to disable TUN mode: {}", e)
        })?;

    println!("[STDOUT] TUN mode disabled in system proxy manager");

    // Stop TUN interface
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

