use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::shadowsocks::{ShadowsocksClient as SsClient, ShadowsocksConfig};
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
            let mut last_err: Option<String> = None;
            let mut resolved_any = false;
            match tokio::net::lookup_host(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_any = true;
                        log::info!("[WIN] Preflight trying {}", addr);
                        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                            Ok(Ok(_s)) => {
                                log::info!("[WIN] Upstream {} is reachable (TCP preflight)", addr);
                                last_err = None;
                                break;
                            }
                            Ok(Err(e)) => {
                                last_err = Some(format!("connect {} failed: {}", addr, e));
                            }
                            Err(_) => {
                                last_err = Some(format!("connect {} timed out", addr));
                            }
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(format!("DNS resolve failed for {}: {}", target, e));
                }
            }
            if !resolved_any {
                return Err(format!("Windows preflight: no addresses resolved for {}", target).into());
            }
            if let Some(err) = last_err {
                return Err(format!("Windows preflight failed: {}", err).into());
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
            let mut last_err: Option<String> = None;
            let mut resolved_any = false;
            match tokio::net::lookup_host(&target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_any = true;
                        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                            Ok(Ok(_)) => { last_err = None; break; }
                            Ok(Err(e)) => { last_err = Some(format!("connect {} failed: {}", addr, e)); }
                            Err(_) => { last_err = Some(format!("connect {} timed out", addr)); }
                        }
                    }
                }
                Err(e) => { last_err = Some(format!("DNS resolve failed for {}: {}", target, e)); }
            }
            if !resolved_any {
                return Err(VpnError::ConnectionFailed(format!("Windows preflight: no addresses resolved for {}", target)));
            }
            if let Some(err) = last_err {
                return Err(VpnError::ConnectionFailed(format!("Windows preflight failed: {}", err)));
            }
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