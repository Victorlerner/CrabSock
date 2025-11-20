use anyhow::Result;
use std::path::PathBuf;

use crate::net::socks::{ensure_socks_ready, get_socks_endpoint};
use crate::singbox::config_builder::build_singbox_config;
use crate::singbox::runner::{find_singbox_path, spawn_singbox};
use crate::tun_manager::TunConfig;

pub struct LinuxSingBoxTun {
    pub(crate) singbox_child: Option<tokio::process::Child>,
    pub(crate) temp_config: Option<PathBuf>,
    pub(crate) config: TunConfig,
    pub(crate) is_running: bool,
}

impl LinuxSingBoxTun {
    pub fn new() -> Self { 
        Self { 
            singbox_child: None, 
            temp_config: None, 
            config: TunConfig::default(), 
            is_running: false,
        } 
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { return Ok(()); }
        log::info!("[TUN][LINUX] Starting sing-box (TUN inbound -> selected outbound)");

        let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
        let (socks_host, socks_port) = get_socks_endpoint();
        if outbound_type == "socks" { ensure_socks_ready(&socks_host, socks_port).await?; }

        let singbox_path = find_singbox_path()
            .ok_or_else(|| anyhow::anyhow!("sing-box not found in resources or alongside executable"))?;
        
        // On Linux sing-box is started via pkexec wrapper (similar to nekoray)
        // This allows auto_route to work WITHOUT multiple password prompts
        log::info!("[TUN][LINUX] sing-box will run via pkexec (one password prompt)");

        let cfg_path = build_singbox_config(&self.config, socks_host, socks_port)?;
        
        // Always log config for debugging (can be disabled via LOG_SINGBOX_CONFIG=0)
        if std::env::var("LOG_SINGBOX_CONFIG").ok().as_deref() != Some("0") {
            if let Ok(cfg_text) = std::fs::read_to_string(&cfg_path) {
                log::info!("[SING-BOX][CONFIG] Generated config:\n{}", cfg_text);
            }
        }
        
        log::info!("[TUN][LINUX] Sing-box config path: {}", cfg_path.display());
        log::info!("[TUN][LINUX] TUN interface: {}, address: {}/{}", 
                   self.config.name, self.config.address, self.config.netmask);
        
        self.temp_config = Some(cfg_path.clone());

        let child = spawn_singbox(&singbox_path, &cfg_path)?;
        
        self.singbox_child = Some(child);
        self.is_running = true;
        log::info!("[TUN][LINUX] sing-box started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { return Ok(()); }
        log::info!("[TUN][LINUX] Stopping sing-box...");
        
        // Take child only once
        let mut child = self.singbox_child.take();
        
        // IMPORTANT: sing-box is started via pkexec bash wrapper (running as root)
        // Normal kill will not work - need pkexec killall like in nekoray
        log::info!("[TUN][LINUX] Killing sing-box via pkexec killall...");
        
        // Kill ALL sing-box processes via killall (as nekoray unconditional stop)
        // SIGTERM for graceful shutdown
        let output = tokio::process::Command::new("pkexec")
            .args(["killall", "-TERM", "sing-box"])
            .output()
            .await;
        
        match output {
            Ok(out) if out.status.success() => {
                log::info!("[TUN][LINUX] pkexec killall succeeded");
            }
            Ok(out) => {
                log::warn!("[TUN][LINUX] pkexec killall returned {}: {}", 
                          out.status, String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => {
                log::error!("[TUN][LINUX] Failed to execute pkexec killall: {}", e);
            }
        }
        
        // Wait for pkexec/wrapper process to exit
        if let Some(ref mut c) = child {
            log::info!("[TUN][LINUX] Waiting for wrapper to exit...");
            match tokio::time::timeout(std::time::Duration::from_secs(5), c.wait()).await {
                Ok(Ok(status)) => {
                    log::info!("[TUN][LINUX] Wrapper exited with status: {}", status);
                }
                Ok(Err(e)) => {
                    log::error!("[TUN][LINUX] Error waiting for wrapper: {}", e);
                }
                Err(_) => {
                    log::warn!("[TUN][LINUX] Timeout waiting for wrapper, forcing kill");
                    let _ = c.kill().await;
                    let _ = c.wait().await;
                }
            }
        }
        
        // Remove temporary config
        if let Some(cfg) = self.temp_config.take() {
            let _ = std::fs::remove_file(cfg);
        }
        
        self.is_running = false;
        log::info!("[TUN][LINUX] sing-box stopped successfully");
        Ok(())
    }

    pub fn is_running(&self) -> bool { self.is_running }
}


