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
        let server = self.config.server.clone();
        let port = self.config.port;
        let uuid = self.config.uuid.clone().unwrap_or_default();
        let tls_enabled = self.config.tls.unwrap_or(false);
        let sni = self.config.sni.clone().unwrap_or_default();
        let network = self.config.network.clone().unwrap_or_else(|| "tcp".to_string());
        let ws_path = self.config.ws_path.clone().unwrap_or_default();
        let ws_headers = self.config.ws_headers.clone().unwrap_or_default();
        let flow = self.config.flow.clone().unwrap_or_default();
        let fingerprint = self.config.fingerprint.clone().unwrap_or_default();
        let security = self.config.security.clone().unwrap_or_else(|| "none".to_string());
        let reality_public_key = self.config.reality_public_key.clone().unwrap_or_default();
        let reality_short_id = self.config.reality_short_id.clone().unwrap_or_default();

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

        // Provide both HTTP (for WinINET/system proxy) and SOCKS inbounds
        serde_json::json!({
            "log": { "level": "info" },
            "inbounds": [
                { "type": "http",  "listen": "127.0.0.1", "listen_port": 8080, "sniff": true },
                { "type": "socks", "listen": "127.0.0.1", "listen_port": 1080, "sniff": true, "sniff_override_destination": true }
            ],
            "outbounds": [ outbound ]
        })
    }

    fn resolve_singbox_path() -> std::path::PathBuf {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("sing-box.exe"));
                candidates.push(dir.join("resources").join("sing-box").join("sing-box.exe"));
                candidates.push(dir.join("resources").join("sing-box.exe"));
            }
        }
        candidates.push(std::path::PathBuf::from("./src-tauri/resources/sing-box/sing-box.exe"));
        candidates.into_iter().find(|p| p.exists()).unwrap_or_else(|| std::path::PathBuf::from("sing-box.exe"))
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
        let mut cmd = tokio::process::Command::new(&sb_path);
        cmd.arg("run").arg("-c").arg(&cfg_path);
        #[cfg(target_os = "windows")]
        { cmd.creation_flags(0x08000000); }
        cmd.kill_on_drop(true);
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        let child = cmd.spawn().map_err(|e| VpnError::ConnectionFailed(format!("Failed to start sing-box: {}", e)))?;
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
                        let _ = ch.wait().await;
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
                let mut cmd = tokio::process::Command::new(&sb_path_cloned);
                cmd.arg("run").arg("-c").arg(&cfg_path_cloned);
                #[cfg(target_os = "windows")]
                { cmd.creation_flags(0x08000000); }
                cmd.kill_on_drop(true);
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::null());
                match cmd.spawn() {
                    Ok(ch) => {
                        let mut g = supervised.lock().await;
                        *g = Some(ch);
                        // reset backoff after successful spawn
                        backoff_ms = 1000;
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

        // Kill supervised child
        {
            let mut guard = self.supervised_child.lock().await;
            if let Some(mut child) = guard.take() {
                let _ = child.kill().await;
                let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait()).await;
                #[cfg(target_os = "windows")]
                {
                    if let Some(pid) = child.id() {
                        use tokio::process::Command as TokioCommand;
                        let mut k = TokioCommand::new("taskkill");
                        #[cfg(target_os = "windows")]
                        { k.creation_flags(0x08000000); }
                        let _ = k
                            .args(["/PID", &pid.to_string(), "/T", "/F"]) 
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .await;
                    }
                }
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
        assert_eq!(j["log"]["level"], "info");
        // Expect both HTTP:8080 and SOCKS:1080 inbounds (order not enforced)
        let mut has_http = false;
        let mut has_socks = false;
        if let Some(arr) = j["inbounds"].as_array() {
            for ib in arr {
                let t = ib["type"].as_str().unwrap_or("");
                let p = ib["listen_port"].as_i64().unwrap_or_default();
                if t == "http" && p == 8080 { has_http = true; }
                if t == "socks" && p == 1080 { has_socks = true; }
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



