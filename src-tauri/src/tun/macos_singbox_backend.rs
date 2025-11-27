use anyhow::Result;
use std::path::PathBuf;
use crate::net::socks::{ensure_socks_ready, get_socks_endpoint};
use crate::singbox::config_builder::build_singbox_config;
use crate::singbox::runner::{find_singbox_path, spawn_singbox};
use crate::tun_manager::TunConfig;

pub struct MacosSingBoxTun {
    pub(crate) singbox_child: Option<tokio::process::Child>,
    pub(crate) temp_config: Option<PathBuf>,
    pub(crate) config: TunConfig,
    pub(crate) is_running: bool,
    // Elevated mode tracking (when sing-box is started via osascript sudo)
    pub(crate) elevated_pid: Option<i32>,
    pub(crate) elevated_pid_file: Option<PathBuf>,
    pub(crate) elevated_log_file: Option<PathBuf>,
}

impl MacosSingBoxTun {
    pub fn new() -> Self { Self { singbox_child: None, temp_config: None, config: TunConfig::default(), is_running: false, elevated_pid: None, elevated_pid_file: None, elevated_log_file: None } }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { return Ok(()); }
        log::info!("[TUN][MAC] Starting sing-box (TUN inbound)");

        let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
        let (socks_host, socks_port) = get_socks_endpoint();
        log::info!("[TUN][MAC] Outbound type: {}", outbound_type);
        log::info!("[TUN][MAC] Local SOCKS endpoint: {}:{}", socks_host, socks_port);
        if outbound_type == "socks" {
            if let Err(e) = ensure_socks_ready(&socks_host, socks_port).await {
                log::warn!("[TUN][MAC] Local SOCKS not ready: {}", e);
            }
        }

        let singbox_path = find_singbox_path()
            .ok_or_else(|| anyhow::anyhow!("sing-box (darwin) not found in resources or alongside executable"))?;
        log::info!("[TUN][MAC] sing-box binary path: {:?}", singbox_path);

        let cfg_path = build_singbox_config(&self.config, socks_host, socks_port)?;
        if std::env::var("LOG_SINGBOX_CONFIG").ok().as_deref() != Some("0") {
            if let Ok(cfg_text) = std::fs::read_to_string(&cfg_path) {
                log::info!("[SING-BOX][CONFIG] {}", cfg_text);
            }
        }
        log::info!("[TUN][MAC] sing-box config path: {}", cfg_path.display());
        self.temp_config = Some(cfg_path.clone());

        match spawn_singbox(&singbox_path, &cfg_path) {
            Ok(mut child) => {
                // Briefly wait to detect immediate failure (e.g., permission denied for utun)
                for _ in 0..10 {
                    if let Ok(Some(status)) = child.try_wait() {
                        // sing-box exited immediately; likely no permission to create utun
                        log::warn!("[TUN][MAC] sing-box exited early with status: {}", status);
                        // Attempt elevated spawn as a fallback (without relaunching the whole app)
                        if self.spawn_singbox_elevated(&singbox_path, &cfg_path)? {
                            self.is_running = true;
                            Self::log_interfaces_and_routes();
                            return Ok(());
                        } else {
                            return Err(anyhow::anyhow!("sing-box TUN failed to start (permission?)"));
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                self.singbox_child = Some(child);
                self.is_running = true;
                Self::log_interfaces_and_routes();
                Ok(())
            }
            Err(e) => {
                log::warn!("[TUN][MAC] Failed to spawn sing-box normally: {}", e);
                if self.spawn_singbox_elevated(&singbox_path, &cfg_path)? {
                    self.is_running = true;
                    Self::log_interfaces_and_routes();
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(format!("sing-box spawn failed and elevation fallback failed: {}", e)))
                }
            }
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { return Ok(()); }
        log::info!("[TUN][MAC] Stopping sing-box");
        if let Some(mut child) = self.singbox_child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(pid) = self.elevated_pid.take() {
            // Kill elevated process via admin privileges
            let cmd = format!("/bin/sh -c 'kill -TERM {pid} || true; sleep 0.3; kill -KILL {pid} || true'");
            let osa = format!("do shell script {} with administrator privileges", as_osascript_string(&cmd));
            let _ = std::process::Command::new("osascript").args(["-e", &osa]).output();
        }
        if let Some(pidf) = self.elevated_pid_file.take() {
            let _ = std::fs::remove_file(pidf);
        }
        if let Some(logf) = self.elevated_log_file.take() {
            // keep log by default for debugging; comment next line to preserve
            let _ = std::fs::remove_file(logf);
        }
        if let Some(cfg) = self.temp_config.take() {
            let _ = std::fs::remove_file(cfg);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool { self.is_running }

    fn spawn_singbox_elevated(&mut self, singbox_path: &PathBuf, cfg_path: &PathBuf) -> Result<bool> {
        log::info!("[TUN][MAC] Attempting elevated sing-box start via osascript (admin)");
        let tmp = std::env::temp_dir();
        let pid_file = tmp.join(format!("crabsock-singbox-{}.pid", std::process::id()));
        let log_file = tmp.join(format!("crabsock-singbox-{}.log", std::process::id()));
        // Build nohup command to run in background and write PID
        let cmd = format!(
            "nohup {} run -c {} --disable-color > {} 2>&1 & echo $! > {}",
            sh_single_quote(&singbox_path.to_string_lossy()),
            sh_single_quote(&cfg_path.to_string_lossy()),
            sh_single_quote(&log_file.to_string_lossy()),
            sh_single_quote(&pid_file.to_string_lossy())
        );
        let shell = format!("/bin/sh -c {}", sh_single_quote(&cmd));
        let osa = format!("do shell script {} with administrator privileges", as_osascript_string(&shell));
        let out = std::process::Command::new("osascript").args(["-e", &osa]).output();
        match out {
            Ok(res) => {
                if !res.status.success() {
                    let se = String::from_utf8_lossy(&res.stderr);
                    log::error!("[TUN][MAC] osascript elevation failed: {}", se.trim());
                    return Ok(false);
                }
                // Read PID
                let mut tries = 0;
                loop {
                    tries += 1;
                    if tries > 20 { break; }
                    if let Ok(text) = std::fs::read_to_string(&pid_file) {
                        if let Ok(pid) = text.trim().parse::<i32>() {
                            self.elevated_pid = Some(pid);
                            self.elevated_pid_file = Some(pid_file.clone());
                            self.elevated_log_file = Some(log_file.clone());
                            log::info!("[TUN][MAC] Elevated sing-box started, PID={}", pid);
                            return Ok(true);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                log::warn!("[TUN][MAC] PID file not created by elevated sing-box");
                Ok(false)
            }
            Err(e) => {
                log::error!("[TUN][MAC] Failed to invoke osascript: {}", e);
                Ok(false)
            }
        }
    }
}

fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn as_osascript_string(s: &str) -> String {
    // AppleScript string literal uses double quotes; need to escape backslashes and double quotes
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

impl MacosSingBoxTun {
    fn log_cmd_output(cmd: &mut std::process::Command, tag: &str) {
        match cmd.output() {
            Ok(out) => {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let head = text.lines().take(80).collect::<Vec<_>>().join("\n");
                    log::info!("[TUN][MAC] {}:\n{}", tag, head);
                } else {
                    let se = String::from_utf8_lossy(&out.stderr);
                    log::warn!("[TUN][MAC] {} failed: {}", tag, se.trim());
                }
            }
            Err(e) => log::warn!("[TUN][MAC] {} exec error: {}", tag, e),
        }
    }
    fn log_interfaces_and_routes() {
        // Best-effort snapshots for debugging TUN routing
        let mut ifc = std::process::Command::new("ifconfig");
        Self::log_cmd_output(&mut ifc, "ifconfig");
        let mut ns = std::process::Command::new("netstat");
        ns.args(["-rn", "-f", "inet"]);
        Self::log_cmd_output(&mut ns, "netstat -rn -f inet");
        let mut sc = std::process::Command::new("scutil");
        sc.arg("--nwi");
        Self::log_cmd_output(&mut sc, "scutil --nwi");
    }
}




