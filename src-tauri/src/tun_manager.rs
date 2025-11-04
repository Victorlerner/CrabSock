use anyhow::Result;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "crabsock0".to_string(),
            address: Ipv4Addr::new(172, 19, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 240),
            mtu: 1500,
        }
    }
}

pub struct TunManager {
    backend: Box<dyn crate::tun::backend::TunBackend>,
}

impl TunManager {
    pub fn new() -> Self {
        let backend = crate::tun::backend_factory::TunBackendFactory::make();
        Self { backend }
    }
    pub async fn start(&mut self) -> Result<()> { self.backend.start().await }
    pub async fn stop(&mut self) -> Result<()> { self.backend.stop().await }
    pub fn is_running(&self) -> bool { self.backend.is_running() }
}