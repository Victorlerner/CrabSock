use shadowsocks_service::{
    config::{Config, ConfigType, ServerInstanceConfig, LocalInstanceConfig, LocalConfig, ProtocolType},
    local::Server,
};
use shadowsocks::config::{ServerConfig, ServerAddr};
use std::str::FromStr;

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

        // Also start an ACL-aware HTTP CONNECT proxy on 127.0.0.1:<ACL_HTTP_PORT> that bypasses internal domains to DIRECT
        // and forwards the rest via SOCKS5 (127.0.0.1:1080). This ensures browsers always hit our ACL first.
        tokio::spawn(async move {
            let http_port: u16 = std::env::var("ACL_HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
            let bind = format!("127.0.0.1:{}", http_port);
            if let Err(e) = crate::acl_http_proxy::run_acl_http_proxy(&bind, ("127.0.0.1", 1080)).await {
                log::error!("ACL HTTP proxy error: {}", e);
            }
        });

        let http_port: u16 = std::env::var("ACL_HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
        log::info!("SOCKS5 proxy listening on 127.0.0.1:1080");
        log::info!("ACL HTTP proxy listening on 127.0.0.1:{}", http_port);

        // Create and run the local server (long-lived)
        let server = Server::new(config).await
            .map_err(|e| format!("Failed to create server: {}", e))?;

        server.run().await
            .map_err(|e| format!("Server error: {}", e))?;

        Ok(())
    }
}