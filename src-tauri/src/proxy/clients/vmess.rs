use crate::config::ProxyConfig;
use crate::error::{VpnError, VpnResult};
use crate::proxy::types::{ConnectionStatus, ProxyClient};
use async_trait::async_trait;

pub struct VmessClient {
    config: ProxyConfig,
    status: ConnectionStatus,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl VmessClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config, status: ConnectionStatus::Disconnected, task: None }
    }
}

#[async_trait]
impl ProxyClient for VmessClient {
    async fn connect(&mut self) -> VpnResult<()> {
        Err(VpnError::ConnectionFailed("VMess not implemented yet".to_string()))
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


