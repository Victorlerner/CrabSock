use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use async_trait::async_trait;
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
use std::os::windows::process::CommandExt;

pub struct VlessClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    child: Option<tokio::process::Child>,
}

impl VlessClient {
    pub fn new(config: ProxyConfig) -> Self { Self { config, status: ConnectionStatus::Disconnected, child: None } }

    fn build_singbox_config_json(&self) -> serde_json::Value {
        let server = self.config.server.clone();
        let port = self.config.port;
        let uuid = self.config.uuid.clone().unwrap_or_default();
        let tls_enabled = self.config.tls.unwrap_or(false);
        let sni = self.config.sni.clone().unwrap_or_default();
        let network = self.config.network.clone().unwrap_or_else(|| "tcp".to_string());
        let ws_path = self.config.ws_path.clone().unwrap_or_default();
        let ws_headers = self.config.ws_headers.clone().unwrap_or_default();

        let mut outbound = serde_json::json!({
            "type": "vless",
            "server": server,
            "server_port": port,
            "uuid": uuid,
        });

        if tls_enabled {
            let mut tls = serde_json::json!({ "enabled": true });
            if !sni.is_empty() { tls["server_name"] = serde_json::Value::String(sni); }
            if let Some(skip) = self.config.skip_cert_verify { if skip { tls["insecure"] = serde_json::Value::Bool(true); } }
            outbound["tls"] = tls;
        }

        if network == "ws" {
            let mut transport = serde_json::json!({ "type": "ws" });
            if !ws_path.is_empty() { transport["path"] = serde_json::Value::String(ws_path); }
            if !ws_headers.is_empty() { transport["headers"] = serde_json::to_value(ws_headers).unwrap_or(serde_json::json!({})); }
            outbound["transport"] = transport;
        }

        serde_json::json!({
            "log": { "level": "info" },
            "inbounds": [ { "type": "socks", "listen": "127.0.0.1", "listen_port": 1080, "sniff": true, "sniff_override_destination": true } ],
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
        if let Some(mut child) = self.child.take() {
            #[cfg(target_os = "windows")]
            {
                if let Some(pid) = child.id() {
                    let _ = std::process::Command::new("taskkill")
                        .creation_flags(0x08000000)
                        .args(["/PID", &pid.to_string(), "/T", "/F"]) 
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
            let _ = child.start_kill();
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

        let mut cmd = tokio::process::Command::new(sb_path);
        cmd.arg("run").arg("-c").arg(&cfg_path);
        #[cfg(target_os = "windows")]
        { cmd.creation_flags(0x08000000); }
        cmd.kill_on_drop(true);
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(child) => { self.child = Some(child); Ok(()) }
            Err(e) => Err(VpnError::ConnectionFailed(format!("Failed to start sing-box: {}", e)))
        }
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait()).await;
            #[cfg(target_os = "windows")]
            {
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
        assert_eq!(j["inbounds"][0]["type"], "socks");
        assert_eq!(j["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(j["inbounds"][0]["listen_port"], 1080);
        assert_eq!(j["outbounds"][0]["type"], "vless");
        assert_eq!(j["outbounds"][0]["tls"]["enabled"], true);
        assert_eq!(j["outbounds"][0]["tls"]["server_name"], "sni.example");
        assert_eq!(j["outbounds"][0]["tls"]["insecure"], true);
        assert_eq!(j["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(j["outbounds"][0]["transport"]["path"], "/ws");
        assert_eq!(j["outbounds"][0]["transport"]["headers"]["Host"], "h.example");
    }
}



