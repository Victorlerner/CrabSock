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
        
        // Prefer root helper (crabsock-root-helper) to stop sing-box; fallback to pkexec killall.
        let output = tokio::task::spawn_blocking(|| {
            use std::os::unix::fs::PermissionsExt;
            use std::os::unix::prelude::MetadataExt;
            use std::path::Path;
            use std::process::Stdio as PStdio;

            const ROOT_HELPER_VERSION: &str = "1";

            fn is_suid_root(p: &Path) -> bool {
                if let Ok(meta) = std::fs::metadata(p) {
                    let mode = meta.permissions().mode();
                    let uid = meta.uid();
                    (mode & 0o4000) != 0 && uid == 0
                } else {
                    false
                }
            }

            let mut candidates: Vec<std::path::PathBuf> = Vec::new();
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    candidates.push(dir.join("crabsock-root-helper"));
                }
            }
            candidates.push(std::path::PathBuf::from(
                "/usr/local/bin/crabsock-root-helper",
            ));

            let helper = {
                let mut chosen: Option<std::path::PathBuf> = None;
                for p in candidates {
                    if !(p.exists() && p.is_file() && is_suid_root(p.as_path())) {
                        continue;
                    }
                    let out = std::process::Command::new(&p)
                        .arg("version")
                        .stdin(PStdio::null())
                        .stdout(PStdio::piped())
                        .stderr(PStdio::null())
                        .output();
                    if let Ok(o) = out {
                        let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if v == ROOT_HELPER_VERSION {
                            chosen = Some(p);
                            break;
                        }
                    }
                }
                chosen
            };

            if let Some(h) = helper {
                log::info!(
                    "[TUN][LINUX] Stopping sing-box via root helper {} (singbox-kill)",
                    h.display()
                );
                std::process::Command::new(&h)
                    .arg("singbox-kill")
                    .stdin(PStdio::null())
                    .stdout(PStdio::piped())
                    .stderr(PStdio::piped())
                    .output()
            } else {
                log::info!(
                    "[TUN][LINUX] Root helper not available, falling back to pkexec killall"
                );
                std::process::Command::new("pkexec")
                    .args(["killall", "-TERM", "sing-box"])
                    .stdin(PStdio::null())
                    .stdout(PStdio::piped())
                    .stderr(PStdio::piped())
                    .output()
            }
        })
        .await
        .unwrap_or_else(|e| {
            log::error!("[TUN][LINUX] spawn_blocking failed for sing-box stop: {}", e);
            Err(std::io::Error::new(std::io::ErrorKind::Other, "join error"))
        });
        
        match output {
            Ok(out) if out.status.success() => {
                log::info!("[TUN][LINUX] sing-box stop command succeeded");
            }
            Ok(out) => {
                log::warn!(
                    "[TUN][LINUX] sing-box stop command returned {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Err(e) => {
                log::error!("[TUN][LINUX] Failed to execute sing-box stop command: {}", e);
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


