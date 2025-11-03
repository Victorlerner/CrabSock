use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use async_trait::async_trait;

pub struct Socks5Client {
    config: ProxyConfig,
    status: ConnectionStatus,
}

impl Socks5Client {
    pub fn new(config: ProxyConfig) -> Self { Self { config, status: ConnectionStatus::Disconnected } }
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

        self.status = ConnectionStatus::Connected;
        std::env::set_var("SOCKS_PROXY", &proxy_url);
        std::env::set_var("socks_proxy", &proxy_url);
        std::env::set_var("http_proxy", &proxy_url);
        std::env::set_var("https_proxy", &proxy_url);
        Ok(())
    }

    async fn disconnect(&mut self) -> VpnResult<()> { self.status = ConnectionStatus::Disconnected; Ok(()) }
    async fn get_status(&self) -> ConnectionStatus { self.status.clone() }
    async fn is_connected(&self) -> bool { matches!(self.status, ConnectionStatus::Connected) }
    fn set_status_connected(&mut self) { self.status = ConnectionStatus::Connected; }
    fn set_status_error(&mut self, msg: String) { self.status = ConnectionStatus::Error(msg); }
}


