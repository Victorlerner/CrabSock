use anyhow::Result;
use std::path::PathBuf;

use crate::net::socks::{ensure_socks_ready, get_socks_endpoint};
use crate::singbox::config_builder::build_singbox_config;
use crate::singbox::runner::{find_singbox_path, spawn_singbox};
use crate::tun_manager::TunConfig;

pub struct WindowsSingBoxTun {
    pub(crate) singbox_child: Option<tokio::process::Child>,
    pub(crate) temp_config: Option<PathBuf>,
    pub(crate) config: TunConfig,
    pub(crate) is_running: bool,
}

impl WindowsSingBoxTun {
    pub fn new() -> Self { Self { singbox_child: None, temp_config: None, config: TunConfig::default(), is_running: false } }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Starting sing-box (TUN inbound -> local SOCKS5)");

        let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
        let (socks_host, socks_port) = get_socks_endpoint();
        if outbound_type == "socks" { ensure_socks_ready(&socks_host, socks_port).await?; }

        let singbox_path = find_singbox_path()
            .ok_or_else(|| anyhow::anyhow!("sing-box.exe not found in resources or alongside executable"))?;

        let cfg_path = build_singbox_config(&self.config, socks_host, socks_port)?;
        if std::env::var("LOG_SINGBOX_CONFIG").ok().as_deref() != Some("0") {
            if let Ok(cfg_text) = std::fs::read_to_string(&cfg_path) {
                log::info!("[SING-BOX][CONFIG] {}", cfg_text);
            }
        }
        self.temp_config = Some(cfg_path.clone());

        let child = spawn_singbox(&singbox_path, &cfg_path)?;
        self.singbox_child = Some(child);
        self.is_running = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Stopping sing-box");
        if let Some(mut child) = self.singbox_child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(cfg) = self.temp_config.take() {
            let _ = std::fs::remove_file(cfg);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool { self.is_running }
}

