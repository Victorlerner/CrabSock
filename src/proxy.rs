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
        log::info!("Starting Shadowsocks client using external process");
        log::info!("Local proxy: 127.0.0.1:1080");
        log::info!("Remote server: {}:{}", server, port);
        log::info!("Encryption method: {}", method);
        log::info!("Password: [HIDDEN]");

        // Skip system shadowsocks client for now, use our custom implementation
        log::info!("Using custom Shadowsocks implementation");
        
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
        self.status = ConnectionStatus::Connected;

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
}