use anyhow::Result;
use std::net::SocketAddr;
use log::info;
use crate::shadowsocks_socks5::ShadowsocksSocks5Proxy;

pub struct OptimizedShadowsocksClient {
    local_addr: SocketAddr,
    remote_server: String,
    remote_port: u16,
    password: String,
    method: String,
}

impl OptimizedShadowsocksClient {
    pub fn new(
        local_addr: SocketAddr,
        remote_server: String,
        remote_port: u16,
        password: String,
        method: String,
    ) -> Self {
        Self {
            local_addr,
            remote_server,
            remote_port,
            password,
            method,
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting optimized Shadowsocks client");
        info!("Local proxy: {}", self.local_addr);
        info!("Remote server: {}:{}", self.remote_server, self.remote_port);
        info!("Method: {}", self.method);

        // Используем правильную реализацию Shadowsocks SOCKS5 прокси
        let proxy = ShadowsocksSocks5Proxy::new(
            self.local_addr,
            self.remote_server.clone(),
            self.remote_port,
            self.password.clone(),
            self.method.clone(),
        );

        proxy.start().await
    }
}
