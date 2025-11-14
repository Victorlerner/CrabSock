use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

pub fn find_singbox_path() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let exe_dir = dir.to_path_buf();
            #[allow(unused_mut)]
            let mut chosen: Option<PathBuf> = None;
            #[cfg(target_os = "windows")]
            {
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
                for c in candidates {
                    log::debug!("[SING-BOX][PATH] Checking candidate: {:?}", c);
                    if c.exists() {
                        log::info!("[SING-BOX][PATH] Using sing-box binary at {:?}", c);
                        return Some(c);
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                // In a .app bundle, executable is at Contents/MacOS/<app>, resources at Contents/Resources
                let bundle_res = exe_dir.parent().map(|p| p.join("Resources"));
                let mut candidates: Vec<PathBuf> = Vec::new();
                if let Some(res) = &bundle_res {
                    // Direct placement
                    candidates.push(res.join("sing-box"));
                    // Nested under our packaged resources dir layout
                    candidates.push(res.join("resources").join("sing-box").join("darwin").join("sing-box"));
                }
                // Dev layouts
                candidates.push(exe_dir.join("sing-box"));
                candidates.push(exe_dir.join("resources").join("sing-box").join("darwin").join("sing-box"));
                if let Some(target_dir) = exe_dir.parent() {
                    if let Some(crate_dir) = target_dir.parent() {
                        candidates.push(crate_dir.join("resources").join("sing-box").join("darwin").join("sing-box"));
                        candidates.push(crate_dir.join("src-tauri").join("resources").join("sing-box").join("darwin").join("sing-box"));
                    }
                }
                for c in candidates {
                    log::debug!("[SING-BOX][PATH] Checking candidate: {:?}", c);
                    if c.exists() {
                        log::info!("[SING-BOX][PATH] Using sing-box binary at {:?}", c);
                        return Some(c);
                    }
                }
            }
            #[cfg(target_os = "linux")]
            {
                // Common locations when packaged or during dev runs
                let mut candidates: Vec<PathBuf> = Vec::new();
                // alongside executable
                candidates.push(exe_dir.join("sing-box"));
                // resources under current dir
                candidates.push(exe_dir.join("resources").join("sing-box").join("linux").join("sing-box"));
                candidates.push(exe_dir.join("resources").join("sing-box").join("sing-box"));
                // parent crate resources (dev)
                if let Some(target_dir) = exe_dir.parent() {
                    if let Some(crate_dir) = target_dir.parent() {
                        candidates.push(crate_dir.join("resources").join("sing-box").join("linux").join("sing-box"));
                        candidates.push(crate_dir.join("src-tauri").join("resources").join("sing-box").join("linux").join("sing-box"));
                        candidates.push(crate_dir.join("src-tauri").join("resources").join("sing-box").join("sing-box"));
                    }
                }
                for c in candidates {
                    log::debug!("[SING-BOX][PATH] Checking candidate: {:?}", c);
                    if c.exists() {
                        log::info!("[SING-BOX][PATH] Using sing-box binary at {:?}", c);
                        return Some(c);
                    }
                }
            }
        }
    }
    log::warn!("[SING-BOX][PATH] sing-box binary not found in known locations");
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

#[cfg(target_os = "macos")]
pub fn spawn_singbox(singbox_path: &Path, cfg_path: &Path) -> Result<tokio::process::Child> {
    // Try to ensure executable bit (best-effort)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&singbox_path) {
            let mut perm = meta.permissions();
            let mode = perm.mode();
            let target = mode | 0o111;
            if target != mode {
                perm.set_mode(target);
                let _ = std::fs::set_permissions(&singbox_path, perm);
            }
        }
    }
    let mut child = Command::new(singbox_path)
        .args(["run", "-c", cfg_path.to_string_lossy().as_ref(), "--disable-color"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box: {}", e)))?;
    log::info!("[SING-BOX][SPAWN][macOS] Executed: {:?} run -c {}", singbox_path, cfg_path.display());

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

#[cfg(target_os = "linux")]
pub fn spawn_singbox(singbox_path: &Path, cfg_path: &Path) -> Result<tokio::process::Child> {
    // Ensure exec bit on packaged binary (best-effort)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&singbox_path) {
            let mut perm = meta.permissions();
            let mode = perm.mode();
            let target = mode | 0o111;
            if target != mode {
                perm.set_mode(target);
                let _ = std::fs::set_permissions(&singbox_path, perm);
            }
        }
    }
    let mut child = Command::new(singbox_path)
        .args(["run", "-c", cfg_path.to_string_lossy().as_ref(), "--disable-color"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box: {}", e)))?;
    log::info!("[SING-BOX][SPAWN][Linux] Executed: {:?} run -c {}", singbox_path, cfg_path.display());

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

