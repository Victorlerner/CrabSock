use shadowsocks_service::{
    config::{Config, ConfigType, ServerInstanceConfig, LocalInstanceConfig, LocalConfig, ProtocolType},
    local::Server,
};
use shadowsocks::config::{ServerConfig, ServerAddr};
use std::str::FromStr;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub method: String,
}

pub struct ShadowsocksClient {
    config: ShadowsocksConfig,
}

impl ShadowsocksClient {
    pub fn new(config: ShadowsocksConfig) -> Self {
        Self { config }
    }

    pub async fn start_local_proxy(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Starting Shadowsocks local proxy using shadowsocks-rust library");
        
        // Create server configuration
        let server_addr = ServerAddr::from_str(&format!("{}:{}", self.config.server, self.config.port))
            .map_err(|e| format!("Failed to parse server address: {}", e))?;
        let method = self.config.method.parse()
            .map_err(|e| format!("Failed to parse cipher method: {}", e))?;
        
        let server_config = ServerConfig::new(server_addr, self.config.password.clone(), method)
            .map_err(|e| format!("Failed to create server config: {}", e))?;

        // Create local configuration
        let mut config = Config::new(ConfigType::Local);
        config.server.push(ServerInstanceConfig::with_server_config(server_config));
        
        // Add local configuration for SOCKS5
        let local_addr = ServerAddr::from_str("127.0.0.1:1080")
            .map_err(|e| format!("Failed to parse local address: {}", e))?;
        let mut local_config = LocalConfig::new(ProtocolType::Socks);
        local_config.addr = Some(local_addr);
        config.local.push(LocalInstanceConfig::with_local_config(local_config));

        // Also expose an HTTP proxy for browsers that don't honor system SOCKS
        let http_local_addr = ServerAddr::from_str("127.0.0.1:8080")
            .map_err(|e| format!("Failed to parse HTTP local address: {}", e))?;
        let mut http_local_config = LocalConfig::new(ProtocolType::Http);
        http_local_config.addr = Some(http_local_addr);
        config.local.push(LocalInstanceConfig::with_local_config(http_local_config));

        log::info!("SOCKS5 proxy listening on 127.0.0.1:1080");
        log::info!("HTTP proxy listening on 127.0.0.1:8080");

        // Create and run the local server with timeout
        let server = Server::new(config).await
            .map_err(|e| format!("Failed to create server: {}", e))?;
        
        // Запускаем сервер с таймаутом для предотвращения зависания
        let server_timeout = Duration::from_secs(300); // 5 минут
        
        timeout(server_timeout, server.run()).await
            .map_err(|e| {
                format!("Server timeout or error: {}", e)
            })?
            .map_err(|e| format!("Server error: {}", e))?;

        Ok(())
    }
}