use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use async_trait::async_trait;

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
            if !resolved_any { log::warn!("[WIN] Preflight DNS resolved no addresses for {} — continuing to try anyway", target); }
            if let Some(err) = last_err { log::warn!("[WIN] Preflight failed: {} — continuing to start Shadowsocks", err); }
        }

        use crate::shadowsocks::{ShadowsocksClient as SsClient, ShadowsocksConfig};
        let config = ShadowsocksConfig { server, port, password, method };
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

        let server = self.config.server.clone();
        let port = self.config.port;
        let password = self.config.password.clone().unwrap_or_default();
        let method = self.config.method.clone().unwrap_or_else(|| "chacha20-ietf-poly1305".to_string());

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
            if let Err(e) = Self::run_shadowsocks_proxy(server, port, password, method).await {
                log::error!("Shadowsocks proxy error: {}", e);
            }
        });

        self.task = Some(task);
        Ok(())
    }

    async fn disconnect(&mut self) -> VpnResult<()> {
        if let Some(task) = self.task.take() { task.abort(); }
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    async fn get_status(&self) -> ConnectionStatus { self.status.clone() }
    async fn is_connected(&self) -> bool { matches!(self.status, ConnectionStatus::Connected) }
    fn set_status_connected(&mut self) { self.status = ConnectionStatus::Connected; }
    fn set_status_error(&mut self, msg: String) { self.status = ConnectionStatus::Error(msg); }
}


