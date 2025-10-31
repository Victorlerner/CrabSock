use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
// shadowsocks types are imported where used to avoid unused warnings across targets
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[async_trait]
pub trait ProxyClient: Send + Sync {
    async fn connect(&mut self) -> VpnResult<()>;
    async fn disconnect(&mut self) -> VpnResult<()>;
    async fn get_status(&self) -> ConnectionStatus;
    async fn is_connected(&self) -> bool;
    // non-async setter for status, default no-op for implementations that don't track status
    fn set_status_connected(&mut self) {}
    fn set_status_error(&mut self, _msg: String) {}
}

pub struct ShadowsocksClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ShadowsocksClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            status: ConnectionStatus::Disconnected,
            task: None,
        }
    }

    async fn run_shadowsocks_proxy(
        server: String,
        port: u16,
        password: String,
        method: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Starting Shadowsocks client using shadowsocks-rust library");
        log::info!("Local proxy: 127.0.0.1:1080");
        log::info!("Remote server: {}:{}", server, port);
        log::info!("Encryption method: {}", method);
        log::info!("Password: [HIDDEN]");

        // Windows-specific: preflight TCP reachability to avoid confusing SS errors
        #[cfg(target_os = "windows")]
        {
            use tokio::net::TcpStream;
            use tokio::time::{timeout, Duration};
            let target = format!("{}:{}", server, port);
            let timeout_ms: u64 = std::env::var("WIN_PREFLIGHT_TIMEOUT_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(8000);
            let mut last_err: Option<String> = None;
            let mut resolved_any = false;
            match tokio::net::lookup_host(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_any = true;
                        log::info!("[WIN] Preflight trying {} ({} ms)", addr, timeout_ms);
                        match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
                            Ok(Ok(_s)) => {
                                log::info!("[WIN] Upstream {} is reachable (TCP preflight)", addr);
                                last_err = None;
                                break;
                            }
                            Ok(Err(e)) => { last_err = Some(format!("connect {} failed: {}", addr, e)); }
                            Err(_) => { last_err = Some(format!("connect {} timed out ({} ms)", addr, timeout_ms)); }
                        }
                    }
                }
                Err(e) => { last_err = Some(format!("DNS resolve failed for {}: {}", target, e)); }
            }
            if !resolved_any {
                log::warn!("[WIN] Preflight DNS resolved no addresses for {} — continuing to try anyway", target);
            }
            if let Some(err) = last_err {
                log::warn!("[WIN] Preflight failed: {} — continuing to start Shadowsocks", err);
            }
        }

        // Используем shadowsocks-rust библиотеку для правильной реализации протокола
        use crate::shadowsocks::{ShadowsocksClient as SsClient, ShadowsocksConfig};
        
        let config = ShadowsocksConfig {
            server,
            port,
            password,
            method,
        };

        let client = SsClient::new(config);
        client.start_local_proxy().await?;

        Ok(())
    }

}

#[async_trait]
impl ProxyClient for ShadowsocksClient {
    async fn connect(&mut self) -> VpnResult<()> {
        if matches!(self.status, ConnectionStatus::Connected | ConnectionStatus::Connecting) {
            return Err(VpnError::AlreadyConnected);
        }

        self.status = ConnectionStatus::Connecting;

        // Реальная реализация Shadowsocks клиента
        let server = self.config.server.clone();
        let port = self.config.port;
        let password = self.config.password.clone().unwrap_or_default();
        let method = self.config.method.clone().unwrap_or_else(|| "chacha20-ietf-poly1305".to_string());

        // Windows: do an upfront preflight to surface detailed errors to frontend immediately
        #[cfg(target_os = "windows")]
        {
            use tokio::net::TcpStream;
            use tokio::time::{timeout, Duration};
            let target = format!("{}:{}", server, port);
            let timeout_ms: u64 = std::env::var("WIN_PREFLIGHT_TIMEOUT_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(8000);
            let mut last_err: Option<String> = None;
            let mut resolved_any = false;
            match tokio::net::lookup_host(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_any = true;
                        match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
                            Ok(Ok(_)) => { last_err = None; break; }
                            Ok(Err(e)) => { last_err = Some(format!("connect {} failed: {}", addr, e)); }
                            Err(_) => { last_err = Some(format!("connect {} timed out ({} ms)", addr, timeout_ms)); }
                        }
                    }
                }
                Err(e) => { last_err = Some(format!("DNS resolve failed for {}: {}", target, e)); }
            }
            if !resolved_any { log::warn!("[WIN] Preflight DNS resolved no addresses for {} — continuing", target); }
            if let Some(err) = last_err { log::warn!("[WIN] Preflight failed: {} — continuing", err); }
        }

        let task = tokio::spawn(async move {
            log::info!("Starting SOCKS5 proxy on 127.0.0.1:1080");
            log::info!("Connecting to Shadowsocks server: {}:{}", server, port);
            log::info!("Method: {}, Password: [HIDDEN]", method);
            
            // Используем простую реализацию SOCKS5 прокси
            if let Err(e) = Self::run_shadowsocks_proxy(server, port, password, method).await {
                log::error!("Shadowsocks proxy error: {}", e);
            }
        });

        self.task = Some(task);
        // Do not mark Connected here; leave it as Connecting until validated by commands::connect_vpn IP check

        Ok(())
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    async fn get_status(&self) -> ConnectionStatus {
        self.status.clone()
    }

    async fn is_connected(&self) -> bool {
        matches!(self.status, ConnectionStatus::Connected)
    }

    fn set_status_connected(&mut self) {
        self.status = ConnectionStatus::Connected;
    }

    fn set_status_error(&mut self, msg: String) {
        self.status = ConnectionStatus::Error(msg);
    }
}

pub struct VmessClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    task: Option<tokio::task::JoinHandle<()>>,
}

pub struct VlessClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    child: Option<tokio::process::Child>,
}

impl VlessClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config, status: ConnectionStatus::Disconnected, child: None }
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
            "inbounds": [
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
        // workspace dev fallback
        candidates.push(std::path::PathBuf::from("./src-tauri/resources/sing-box/sing-box.exe"));
        candidates.into_iter().find(|p| p.exists()).unwrap_or_else(|| std::path::PathBuf::from("sing-box.exe"))
    }
}

impl Drop for VlessClient {
    fn drop(&mut self) {
        // Best-effort synchronous termination on drop to avoid orphaned processes on abrupt shutdown paths
        if let Some(mut child) = self.child.take() {
            #[cfg(target_os = "windows")]
            {
                // Try hard kill via taskkill to ensure file handles are released
                if let Some(pid) = child.id() {
                    let _ = std::process::Command::new("taskkill")
                        .args(["/PID", &pid.to_string(), "/T", "/F"]) // kill the process tree
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
            let _ = child.start_kill(); // non-blocking best-effort for non-Windows too
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

        // Preflight basic TCP reachability to the remote
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

        // Write sing-box config
        let cfg = self.build_singbox_config_json();
        let cfg_path = std::env::temp_dir().join("crabsock_vless_singbox.json");
        match tokio::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).await {
            Ok(_) => {}
            Err(e) => return Err(VpnError::ConnectionFailed(format!("Failed to write sing-box config: {}", e))),
        }

        let sb_path = Self::resolve_singbox_path();
        log::info!("[VLESS] Starting sing-box: {:?} -c {}", sb_path, cfg_path.display());

        #[cfg(target_os = "windows")]
        use std::os::windows::process::CommandExt;

        let mut cmd = tokio::process::Command::new(sb_path);
        cmd.arg("run").arg("-c").arg(&cfg_path);
        #[cfg(target_os = "windows")]
        { cmd.creation_flags(0x08000000); } // CREATE_NO_WINDOW
        cmd.kill_on_drop(true);
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                self.child = Some(child);
                // leave status as Connecting; caller will mark_connected() after IP verify
                Ok(())
            }
            Err(e) => Err(VpnError::ConnectionFailed(format!("Failed to start sing-box: {}", e)))
        }
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        if let Some(mut child) = self.child.take() {
            // First try graceful kill
            let _ = child.kill().await;
            // Then wait for the process to exit to release all handles
            let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait()).await;

            // If still alive on Windows, escalate with taskkill /T /F
            #[cfg(target_os = "windows")]
            {
                if let Some(pid) = child.id() {
                    // Double-check with a small wait; if the process is still around, force kill the tree
                    use tokio::process::Command as TokioCommand;
                    let _ = TokioCommand::new("taskkill")
                        .args(["/PID", &pid.to_string(), "/T", "/F"]) // kill process tree, force
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

impl VmessClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            status: ConnectionStatus::Disconnected,
            task: None,
        }
    }
}

pub struct Socks5Client {
    config: ProxyConfig,
    status: ConnectionStatus,
}

impl Socks5Client {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config, status: ConnectionStatus::Disconnected }
    }
}

#[async_trait]
impl ProxyClient for VmessClient {
    async fn connect(&mut self) -> VpnResult<()> {
        // TODO: Implement VMess client using sing-box or custom implementation
        Err(VpnError::ConnectionFailed("VMess not implemented yet".to_string()))
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    async fn get_status(&self) -> ConnectionStatus {
        self.status.clone()
    }

    async fn is_connected(&self) -> bool {
        matches!(self.status, ConnectionStatus::Connected)
    }

    fn set_status_connected(&mut self) {
        self.status = ConnectionStatus::Connected;
    }

    fn set_status_error(&mut self, msg: String) {
        self.status = ConnectionStatus::Error(msg);
    }
}

#[async_trait]
impl ProxyClient for Socks5Client {
    async fn connect(&mut self) -> VpnResult<()> {
        if matches!(self.status, ConnectionStatus::Connected | ConnectionStatus::Connecting) {
            return Err(VpnError::AlreadyConnected);
        }
        self.status = ConnectionStatus::Connecting;

        let server = self.config.server.clone();
        let port = self.config.port;
        let proxy_url = format!("socks5h://{}:{}", server, port);
        log::info!("[SOCKS5] Testing upstream SOCKS5 connectivity via {}", proxy_url);

        // Use reqwest to preflight connectivity
        let client = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(10))
            .tcp_keepalive(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(8))
            .timeout(std::time::Duration::from_secs(12))
            .no_proxy()
            .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| VpnError::ConnectionFailed(format!("Invalid SOCKS5 proxy URL: {}", e)))?)
            .build()
            .map_err(|e| VpnError::ConnectionFailed(format!("Failed to build HTTP client: {}", e)))?;

        let resp = client
            .get("https://ipinfo.io/json")
            .send()
            .await
            .map_err(|e| VpnError::ConnectionFailed(format!("SOCKS5 upstream check failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(VpnError::ConnectionFailed(format!("SOCKS5 upstream returned bad status: {}", resp.status())));
        }

        // If we get here, upstream works; mark connected
        self.status = ConnectionStatus::Connected;

        // Export env var for subsequent client calls and allow SystemProxyManager to pick it up if requested
        std::env::set_var("SOCKS_PROXY", &proxy_url);
        std::env::set_var("socks_proxy", &proxy_url);
        std::env::set_var("http_proxy", &proxy_url);
        std::env::set_var("https_proxy", &proxy_url);

        Ok(())
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    async fn get_status(&self) -> ConnectionStatus { self.status.clone() }
    async fn is_connected(&self) -> bool { matches!(self.status, ConnectionStatus::Connected) }
    fn set_status_connected(&mut self) { self.status = ConnectionStatus::Connected; }
    fn set_status_error(&mut self, msg: String) { self.status = ConnectionStatus::Error(msg); }
}

pub struct ProxyManager {
    client: Arc<Mutex<Option<Box<dyn ProxyClient>>>>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn connect(&self, config: ProxyConfig) -> VpnResult<()> {
        let mut client_guard = self.client.lock().await;
        
        if client_guard.is_some() {
            return Err(VpnError::AlreadyConnected);
        }

        let mut client: Box<dyn ProxyClient> = match config.proxy_type {
            crate::config::ProxyType::Shadowsocks => {
                Box::new(ShadowsocksClient::new(config))
            }
            crate::config::ProxyType::VMess => {
                Box::new(VmessClient::new(config))
            }
            crate::config::ProxyType::VLESS => {
                Box::new(VlessClient::new(config))
            }
            crate::config::ProxyType::SOCKS5 => {
                Box::new(Socks5Client::new(config))
            }
            _ => {
                return Err(VpnError::ConnectionFailed("Unsupported proxy type".to_string()));
            }
        };

        client.connect().await?;
        *client_guard = Some(client);
        
        Ok(())
    }

    pub async fn disconnect(&self) -> VpnResult<()> {
        let mut client_guard = self.client.lock().await;
        
        if let Some(mut client) = client_guard.take() {
            client.disconnect().await?;
        }
        
        Ok(())
    }

    pub async fn get_status(&self) -> ConnectionStatus {
        let client_guard = self.client.lock().await;
        
        if let Some(client) = client_guard.as_ref() {
            client.get_status().await
        } else {
            ConnectionStatus::Disconnected
        }
    }

    pub async fn is_connected(&self) -> bool {
        let client_guard = self.client.lock().await;
        
        if let Some(client) = client_guard.as_ref() {
            client.is_connected().await
        } else {
            false
        }
    }

    pub async fn mark_connected(&self) {
        let mut client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_mut() {
            client.set_status_connected();
        }
    }

    pub async fn mark_error(&self, message: String) {
        let mut client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_mut() {
            client.set_status_error(message);
        }
    }
}