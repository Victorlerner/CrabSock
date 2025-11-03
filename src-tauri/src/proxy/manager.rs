use crate::config::ProxyConfig;
use crate::error::VpnResult;
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use crate::proxy::factory::build_client;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct ProxyManager {
    client: Arc<Mutex<Option<Box<dyn ProxyClient>>>>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self { client: Arc::new(Mutex::new(None)) }
    }

    pub async fn connect(&self, config: ProxyConfig) -> VpnResult<()> {
        let mut client_guard = self.client.lock().await;
        if client_guard.is_some() { return Err(crate::error::VpnError::AlreadyConnected); }
        let mut client = build_client(config)?;
        client.connect().await?;
        *client_guard = Some(client);
        Ok(())
    }

    pub async fn disconnect(&self) -> VpnResult<()> {
        let mut client_guard = self.client.lock().await;
        if let Some(mut client) = client_guard.take() { client.disconnect().await?; }
        Ok(())
    }

    pub async fn get_status(&self) -> ConnectionStatus {
        let client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_ref() { client.get_status().await } else { ConnectionStatus::Disconnected }
    }

    pub async fn is_connected(&self) -> bool {
        let client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_ref() { client.is_connected().await } else { false }
    }

    pub async fn mark_connected(&self) {
        let mut client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_mut() { client.set_status_connected(); }
    }

    pub async fn mark_error(&self, message: String) {
        let mut client_guard = self.client.lock().await;
        if let Some(client) = client_guard.as_mut() { client.set_status_error(message); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, ProxyType};

    fn vmess_cfg() -> ProxyConfig {
        ProxyConfig {
            proxy_type: ProxyType::VMess,
            name: "vm".into(),
            server: "invalid".into(),
            port: 443,
            password: None,
            method: None,
            uuid: Some("uuid".into()),
            security: Some("tls".into()),
            network: Some("tcp".into()),
            tls: Some(true),
            sni: None,
            skip_cert_verify: None,
            alpn: None,
            ws_path: None,
            ws_headers: None,
            flow: None,
            fingerprint: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_spx: None,
        }
    }

    #[tokio::test]
    async fn status_without_client_is_disconnected() {
        let m = ProxyManager::new();
        assert!(matches!(m.get_status().await, ConnectionStatus::Disconnected));
        assert!(!m.is_connected().await);
    }

    #[tokio::test]
    async fn connect_vmess_not_implemented_does_not_store_client() {
        let m = ProxyManager::new();
        let err = m.connect(vmess_cfg()).await.unwrap_err();
        assert!(matches!(m.get_status().await, ConnectionStatus::Disconnected));
        let s = format!("{}", err);
        assert!(s.contains("VMess not implemented yet"));
    }

    #[tokio::test]
    async fn disconnect_without_client_ok() {
        let m = ProxyManager::new();
        assert!(m.disconnect().await.is_ok());
    }
}


