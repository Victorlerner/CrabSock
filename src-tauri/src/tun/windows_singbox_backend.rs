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
    #[cfg(target_os = "windows")]
    pub(crate) elevated_pid: Option<u32>,
}

impl WindowsSingBoxTun {
    pub fn new() -> Self { Self { singbox_child: None, temp_config: None, config: TunConfig::default(), is_running: false, #[cfg(target_os = "windows")] elevated_pid: None } }

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

        #[cfg(target_os = "windows")]
        {
            if !is_elevated_windows() {
                // Elevate only sing-box, not the whole app
                let pid = spawn_singbox_elevated(&singbox_path, &cfg_path)?;
                self.elevated_pid = pid;
            } else {
                let child = spawn_singbox(&singbox_path, &cfg_path)?;
                self.singbox_child = Some(child);
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let child = spawn_singbox(&singbox_path, &cfg_path)?;
            self.singbox_child = Some(child);
        }
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
        #[cfg(target_os = "windows")]
        if let Some(pid) = self.elevated_pid.take() {
            // Best effort kill the elevated process tree
            let mut k = std::process::Command::new("taskkill");
            k.args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(target_os = "windows")]
            { use std::os::windows::process::CommandExt; k.creation_flags(0x08000000); }
            let _ = k.status();
        }
        if let Some(cfg) = self.temp_config.take() {
            let _ = std::fs::remove_file(cfg);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool { self.is_running }
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    use std::process::Stdio;
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        ])
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(Stdio::null())
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            return s.contains("true");
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn spawn_singbox_elevated(singbox_path: &std::path::Path, cfg_path: &std::path::Path) -> anyhow::Result<Option<u32>> {
    use std::process::Stdio;
    // Build args like: run -c <cfg> --disable-color
    let args = vec![
        "run".to_string(),
        "-c".to_string(), cfg_path.to_string_lossy().to_string(),
        "--disable-color".to_string(),
    ];
    let joined = args
        .iter()
        .map(|s| s.replace("'", "''"))
        .collect::<Vec<_>>()
        .join(" ");
    // Use -PassThru to capture PID
    let ps = format!(
        "(Start-Process -FilePath \"{}\" -Verb RunAs -WindowStyle Hidden -ArgumentList '{}' -PassThru).Id",
        singbox_path.display(),
        joined
    );
    let mut psc = std::process::Command::new("powershell");
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; psc.creation_flags(0x08000000); }
    let out = psc
        .args(["-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command", &ps])
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Ok(pid) = s.parse::<u32>() {
            log::info!("[TUN][WIN] Elevated sing-box PID {}", pid);
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

