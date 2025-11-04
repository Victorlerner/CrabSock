use crate::error::VpnResult;
use async_trait::async_trait;

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


