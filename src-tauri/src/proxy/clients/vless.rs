use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use async_trait::async_trait;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
use std::os::windows::process::CommandExt;
use crate::singbox::runner::{find_singbox_path, spawn_singbox};

pub struct VlessClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    child: Option<tokio::process::Child>,
    // New: supervised child and control
    supervised_child: Arc<AsyncMutex<Option<tokio::process::Child>>>,
    supervisor_stop: Arc<AtomicBool>,
    supervisor_task: Option<JoinHandle<()>>,
}

impl VlessClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            status: ConnectionStatus::Disconnected,
            child: None,
            supervised_child: Arc::new(AsyncMutex::new(None)),
            supervisor_stop: Arc::new(AtomicBool::new(false)),
            supervisor_task: None,
        }
    }

    fn build_singbox_config_json(&self) -> serde_json::Value {
        use std::net::{IpAddr, ToSocketAddrs};

        let original_server = self.config.server.clone();
        // Prefer connecting by IP to avoid sing-box doing its own DNS resolution for the upstream
        // VLESS server (which may be blocked or misrouted once TUN is active). Preserve SNI so the
        // TLS layer still sees the original hostname.
        let mut server = original_server.clone();
        if server.parse::<IpAddr>().is_err() {
            if let Ok(iter) = (server.as_str(), self.config.port).to_socket_addrs() {
                if let Some(ip) = iter.filter_map(|sa| {
                    match sa.ip() {
                        IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
                        IpAddr::V6(v6) => Some(IpAddr::V6(v6)),
                    }
                }).next() {
                    log::info!("[VLESS] Resolved upstream host {} -> {}", server, ip);
                    server = ip.to_string();
                } else {
                    log::warn!("[VLESS] Could not resolve upstream host {}; using hostname as-is", server);
                }
            } else {
                log::warn!("[VLESS] DNS resolution failed for upstream host {}; using hostname as-is", server);
            }
        }
        let port = self.config.port;
        let uuid = self.config.uuid.clone().unwrap_or_default();
        let tls_enabled = self.config.tls.unwrap_or(false);
        // For SNI prefer explicit config.sni; otherwise keep the original hostname,
        // even if we dial by IP, to match typical VLESS/Reality setups.
        let mut sni = self.config.sni.clone().unwrap_or_default();
        let network = self.config.network.clone().unwrap_or_else(|| "tcp".to_string());
        let ws_path = self.config.ws_path.clone().unwrap_or_default();
        let ws_headers = self.config.ws_headers.clone().unwrap_or_default();
        let flow = self.config.flow.clone().unwrap_or_default();
        let fingerprint = self.config.fingerprint.clone().unwrap_or_default();
        let security = self.config.security.clone().unwrap_or_else(|| "none".to_string());
        let reality_public_key = self.config.reality_public_key.clone().unwrap_or_default();
        let reality_short_id = self.config.reality_short_id.clone().unwrap_or_default();

        log::info!(
            "[VLESS] Config summary: server={} port={} tls={} sni={} fp={} flow={} net={} ws_path={}",
            server, port, tls_enabled, sni, fingerprint, flow, network, ws_path
        );

        if sni.is_empty() {
            sni = original_server;
        }

        let mut outbound = serde_json::json!({
            "type": "vless",
            "server": server,
            "server_port": port,
            "uuid": uuid,
        });

        if !flow.is_empty() { outbound["flow"] = serde_json::Value::String(flow); }

        if tls_enabled {
            let mut tls = serde_json::json!({ "enabled": true });
            if !sni.is_empty() { tls["server_name"] = serde_json::Value::String(sni); }
            if let Some(skip) = self.config.skip_cert_verify { if skip { tls["insecure"] = serde_json::Value::Bool(true); } }
            if !fingerprint.is_empty() {
                tls["utls"] = serde_json::json!({ "enabled": true, "fingerprint": fingerprint });
            }
            if security == "reality" {
                let mut reality = serde_json::json!({ "enabled": true });
                if !reality_public_key.is_empty() { reality["public_key"] = serde_json::Value::String(reality_public_key); }
                if !reality_short_id.is_empty() { reality["short_id"] = serde_json::Value::String(reality_short_id); }
                tls["reality"] = reality;
            }
            outbound["tls"] = tls;
        }

        if network == "ws" {
            let mut transport = serde_json::json!({ "type": "ws" });
            if !ws_path.is_empty() { transport["path"] = serde_json::Value::String(ws_path); }
            if !ws_headers.is_empty() { transport["headers"] = serde_json::to_value(ws_headers).unwrap_or(serde_json::json!({})); }
            outbound["transport"] = transport;
        }

        // Provide both HTTP (for WinINET/system proxy) and SOCKS inbounds.
        // HTTP port is taken from ACL_HTTP_PORT if set and available; otherwise
        // we auto-select a free port starting from 2081, mirroring Shadowsocks ACL HTTP.
        //
        // Default sing-box log level: on Linux use "warn" to reduce noise, elsewhere "info".
        // Can always be overridden via SB_LOG_LEVEL.
        let default_log_level = if cfg!(target_os = "linux") { "warn" } else { "info" };
        let sb_log_level =
            std::env::var("SB_LOG_LEVEL").unwrap_or_else(|_| default_log_level.to_string());
        let http_port: u16 = crate::utils::ensure_acl_http_port_initialized();
        serde_json::json!({
            "log": { "level": sb_log_level, "timestamp": true },
            "inbounds": [
                { "type": "http",  "listen": "127.0.0.1", "listen_port": http_port, "sniff": true },
                { "type": "socks", "listen": "127.0.0.1", "listen_port": 1080, "sniff": true, "sniff_override_destination": true }
            ],
            "outbounds": [ outbound ]
        })
    }

    fn resolve_singbox_path() -> std::path::PathBuf {
        find_singbox_path().unwrap_or_else(|| std::path::PathBuf::from("sing-box"))
    }
}

impl Drop for VlessClient {
    fn drop(&mut self) {
        // signal supervisor to stop
        self.supervisor_stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.supervisor_task.take() { let _ = handle.abort(); }

        if let Some(mut child) = self.child.take() {
            #[cfg(target_os = "windows")]
            {
                if let Some(pid) = child.id() {
                    let _ = std::process::Command::new("taskkill")
                        .args(["/PID", &pid.to_string(), "/T", "/F"])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
            let _ = child.start_kill();
        }
        // Also try to kill supervised child if present
        if let Ok(mut guard) = self.supervised_child.try_lock() {
            if let Some(mut c) = guard.take() { let _ = c.start_kill(); }
        }
    }
}

#[async_trait]
impl ProxyClient for VlessClient {
    async fn connect(&mut self) -> VpnResult<()> {
        if matches!(self.status, ConnectionStatus::Connected | ConnectionStatus::Connecting) {
            return Err(VpnError::AlreadyConnected);
        }
        self.status = ConnectionStatus::Connecting;

        // Best-effort: ensure no stale sing-box instances remain from previous runs (Windows only)
        // This prevents port 1080 conflicts and ghost processes after abrupt exits.
        #[cfg(target_os = "windows")]
        {
            use tokio::process::Command as TokioCommand;
            let _ = TokioCommand::new("taskkill")
                .creation_flags(0x08000000)
                .args(["/IM", "sing-box.exe", "/F", "/T"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
            // small delay to let the OS release the socket
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        #[cfg(target_os = "windows")]
        {
            use tokio::net::TcpStream;
            use tokio::time::{timeout, Duration};
            let target = format!("{}:{}", self.config.server, self.config.port);
            let timeout_ms: u64 = std::env::var("WIN_PREFLIGHT_TIMEOUT_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(8000);
            let mut any_ok = false;
            if let Ok(addrs) = tokio::net::lookup_host(&target).await {
                for addr in addrs {
                    if let Ok(Ok(_)) = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await { any_ok = true; break; }
                }
            }
            if !any_ok { log::warn!("[WIN] Preflight to {} failed (timeout={})", target, timeout_ms); }
        }

        let cfg = self.build_singbox_config_json();
        let cfg_path = std::env::temp_dir().join("crabsock_vless_singbox.json");
        match tokio::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).await {
            Ok(_) => {}
            Err(e) => return Err(VpnError::ConnectionFailed(format!("Failed to write sing-box config: {}", e))),
        }

        let sb_path = Self::resolve_singbox_path();
        log::info!("[VLESS] Starting sing-box: {:?} -c {}", sb_path, cfg_path.display());

        // Initial spawn
        let child = spawn_singbox(&sb_path, &cfg_path)
            .map_err(|e| VpnError::ConnectionFailed(format!("Failed to start sing-box: {}", e)))?;
        if let Some(pid) = child.id() {
            log::info!("[VLESS] sing-box PID={}", pid);
        }
        // Track in both legacy and supervised holders
        self.child = Some(child);
        if self.child.is_some() {
            let mut guard = self.supervised_child.lock().await;
            // move handle into supervised slot
            let taken = self.child.take();
            *guard = taken;
        }

        // Wait until local SOCKS is ready to accept connections
        if let Err(e) = crate::net::socks::ensure_socks_ready("127.0.0.1", 1080).await {
            log::warn!("[VLESS] Local SOCKS not ready in time: {}", e);
        }

        // Start supervisor to auto-restart on unexpected exit
        let stop_flag = self.supervisor_stop.clone();
        stop_flag.store(false, Ordering::SeqCst);
        let supervised = self.supervised_child.clone();
        let sb_path_cloned = sb_path.clone();
        let cfg_path_cloned = cfg_path.clone();

        let handle = tokio::spawn(async move {
            let mut backoff_ms: u64 = 1000;
            loop {
                if stop_flag.load(Ordering::SeqCst) { break; }

                // Take current child (if any) and wait for it
                let need_spawn = {
                    let mut g = supervised.lock().await;
                    if let Some(mut ch) = g.take() {
                        // Wait for process to exit
                        match ch.wait().await {
                            Ok(status) => log::warn!("[VLESS] sing-box exited with status: {}", status),
                            Err(e) => log::warn!("[VLESS] sing-box wait error: {}", e),
                        }
                        // proceed to respawn unless stopping
                        !stop_flag.load(Ordering::SeqCst)
                    } else {
                        // nothing running -> need spawn
                        true
                    }
                };

                if !need_spawn { break; }
                if stop_flag.load(Ordering::SeqCst) { break; }

                // Exponential backoff between restarts
                tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);

                // Spawn new sing-box
                match spawn_singbox(&sb_path_cloned, &cfg_path_cloned) {
                    Ok(ch) => {
                        let mut g = supervised.lock().await;
                        *g = Some(ch);
                        // reset backoff after successful spawn
                        backoff_ms = 1000;
                        log::info!("[VLESS] sing-box restarted");
                    }
                    Err(e) => {
                        log::error!("[VLESS] sing-box restart failed: {}", e);
                    }
                }
            }
        });
        self.supervisor_task = Some(handle);

        self.status = ConnectionStatus::Connected;
        Ok(())
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        // Stop supervisor and kill process
        self.supervisor_stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.supervisor_task.take() { let _ = h.abort(); }

        // Windows: first try to kill any sing-box by image name unconditionally.
        // This covers races where the supervisor temporarily holds the child handle.
        #[cfg(target_os = "windows")]
        {
            use tokio::process::Command as TokioCommand;
            let _ = TokioCommand::new("taskkill")
                .creation_flags(0x08000000)
                .args(["/IM", "sing-box.exe", "/F", "/T"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }

        // Kill supervised child
        {
            let mut guard = self.supervised_child.lock().await;
            if let Some(mut child) = guard.take() {
                // On Windows: try killing by PID tree up-front to ensure descendants are gone
                #[cfg(target_os = "windows")]
                if let Some(pid) = child.id() {
                    use tokio::process::Command as TokioCommand;
                    let _ = TokioCommand::new("taskkill")
                        .creation_flags(0x08000000)
                        .args(["/PID", &pid.to_string(), "/T", "/F"])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                }

                // Generic kill and wait as a fallback
                let _ = child.kill().await;
                let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait()).await;
            }
        }

        // Windows: Verify process truly gone; loop on tasklist for a short time
        #[cfg(target_os = "windows")]
        {
            use tokio::process::Command as TokioCommand;
            let mut tries = 0usize;
            while tries < 15 {
                let out = TokioCommand::new("tasklist")
                    .creation_flags(0x08000000)
                    .args(["/FI", "IMAGENAME eq sing-box.exe"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .output()
                    .await;
                let mut still_present = false;
                if let Ok(o) = out {
                    if o.status.success() {
                        let s = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
                        if s.contains("sing-box.exe".to_ascii_lowercase().as_str()) { still_present = true; }
                    }
                }
                if !still_present { break; }
                // try again after forcing a kill by name
                let _ = TokioCommand::new("taskkill")
                    .creation_flags(0x08000000)
                    .args(["/IM", "sing-box.exe", "/F", "/T"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                tries += 1;
            }
        }

        // Wait until 127.0.0.1:1080 is free (avoid race before next connection)
        // Non-fatal if we can't confirm, but reduces chances of port-in-use issues.
        {
            use std::net::{TcpListener};
            let mut attempts = 0usize;
            while attempts < 10 {
                if TcpListener::bind("127.0.0.1:1080").is_ok() {
                    // immediately drop the listener to free the port
                    break;
                }
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    async fn get_status(&self) -> ConnectionStatus { self.status.clone() }
    async fn is_connected(&self) -> bool { matches!(self.status, ConnectionStatus::Connected) }
    fn set_status_connected(&mut self) { self.status = ConnectionStatus::Connected; }
    fn set_status_error(&mut self, msg: String) { self.status = ConnectionStatus::Error(msg); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, ProxyType};
    use serde_json::Value;

    fn cfg_ws_tls() -> ProxyConfig {
        let mut ws_headers = std::collections::HashMap::new();
        ws_headers.insert("Host".into(), "h.example".into());
        ProxyConfig {
            proxy_type: ProxyType::VLESS,
            name: "n".into(),
            server: "s.example".into(),
            port: 443,
            password: Some("uuid".into()),
            method: None,
            uuid: Some("uuid".into()),
            security: Some("tls".into()),
            network: Some("ws".into()),
            tls: Some(true),
            sni: Some("sni.example".into()),
            skip_cert_verify: Some(true),
            alpn: None,
            ws_path: Some("/ws".into()),
            ws_headers: Some(ws_headers),
            flow: None, fingerprint: None, reality_public_key: None,
            reality_short_id: None, reality_spx: None,
        }
    }

    #[test]
    fn build_config_tcp_no_transport() {
        let cfg = ProxyConfig { network: Some("tcp".into()), ..cfg_ws_tls() };
        let c = VlessClient::new(cfg);
        let j: Value = c.build_singbox_config_json();
        assert!(j["outbounds"][0]["transport"].is_null());
    }

    #[test]
    fn build_config_ws_and_tls_fields_present() {
        let c = VlessClient::new(cfg_ws_tls());
        let j: Value = c.build_singbox_config_json();
        // Default log level may differ by platform; just ensure it is a string.
        assert!(j["log"]["level"].is_string());
        // Expect both HTTP and SOCKS inbounds (order and ports are not enforced).
        let mut has_http = false;
        let mut has_socks = false;
        if let Some(arr) = j["inbounds"].as_array() {
            for ib in arr {
                let t = ib["type"].as_str().unwrap_or("");
                if t == "http" { has_http = true; }
                if t == "socks" { has_socks = true; }
            }
        }
        assert!(has_http && has_socks);
        assert_eq!(j["outbounds"][0]["type"], "vless");
        assert_eq!(j["outbounds"][0]["tls"]["enabled"], true);
        assert_eq!(j["outbounds"][0]["tls"]["server_name"], "sni.example");
        assert_eq!(j["outbounds"][0]["tls"]["insecure"], true);
        assert_eq!(j["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(j["outbounds"][0]["transport"]["path"], "/ws");
        assert_eq!(j["outbounds"][0]["transport"]["headers"]["Host"], "h.example");
    }
}



