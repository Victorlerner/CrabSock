use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

pub fn find_singbox_path() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let exe_dir = dir.to_path_buf();
            let mut candidates = vec![
                exe_dir.join("sing-box.exe"),
                exe_dir.join("bin").join("sing-box.exe"),
                exe_dir.join("resources").join("sing-box.exe"),
                exe_dir.join("resources").join("sing-box").join("sing-box.exe"),
            ];
            if let Some(target_dir) = exe_dir.parent() {
                if let Some(crate_dir) = target_dir.parent() {
                    candidates.push(crate_dir.join("resources").join("sing-box").join("sing-box.exe"));
                }
            }
            for c in candidates { if c.exists() { return Some(c); } }
        }
    }
    None
}

#[cfg(target_os = "windows")]
pub fn spawn_singbox(singbox_path: &Path, cfg_path: &Path) -> Result<tokio::process::Child> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut child = Command::new(singbox_path)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["run", "-c", cfg_path.to_string_lossy().as_ref(), "--disable-color"]) 
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box: {}", e)))?;

    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut r = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = r.next_line().await {
                if !line.trim().is_empty() { log::info!("[SING-BOX][STDOUT] {}", line); }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut r = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = r.next_line().await {
                if !line.trim().is_empty() { log::warn!("[SING-BOX][STDERR] {}", line); }
            }
        });
    }

    Ok(child)
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_singbox(_singbox_path: &Path, _cfg_path: &Path) -> Result<tokio::process::Child> {
    Err(anyhow::anyhow!("spawn_singbox is only supported on Windows"))
}

