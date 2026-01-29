use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

pub fn find_singbox_path() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        log::info!("[SING-BOX][PATH] current_exe: {:?}", exe);
        if let Some(dir) = exe.parent() {
            let exe_dir = dir.to_path_buf();
            log::info!("[SING-BOX][PATH] exe_dir: {:?}", exe_dir);
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
                    log::info!("[SING-BOX][PATH] Checking candidate: {:?}", c);
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
                    log::info!("[SING-BOX][PATH] Checking candidate: {:?}", c);
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
                // System-wide install (e.g. Debian/Ubuntu .deb layout)
                // Example from production: /usr/lib/CrabSock/resources/sing-box/linux/sing-box
                candidates.push(PathBuf::from("/usr/lib/CrabSock/resources/sing-box/linux/sing-box"));
                // parent crate resources (dev)
                if let Some(target_dir) = exe_dir.parent() {
                    if let Some(crate_dir) = target_dir.parent() {
                        candidates.push(crate_dir.join("resources").join("sing-box").join("linux").join("sing-box"));
                        candidates.push(crate_dir.join("src-tauri").join("resources").join("sing-box").join("linux").join("sing-box"));
                        candidates.push(crate_dir.join("src-tauri").join("resources").join("sing-box").join("sing-box"));
                    }
                }
                for c in candidates {
                    log::info!("[SING-BOX][PATH] Checking candidate: {:?}", c);
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
    use std::os::unix::fs::PermissionsExt;

    const ROOT_HELPER_VERSION: &str = "1";

    // Ensure sing-box is executable
    if let Ok(meta) = std::fs::metadata(&singbox_path) {
        let mut perm = meta.permissions();
        let mode = perm.mode();
        let target = mode | 0o111;
        if target != mode {
            perm.set_mode(target);
            let _ = std::fs::set_permissions(&singbox_path, perm);
        }
    }

    // Try to use crabsock-root-helper (root helper) first.
    fn find_root_helper() -> Option<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::prelude::MetadataExt;
        use std::path::Path;

        fn is_suid_root(p: &Path) -> bool {
            if let Ok(meta) = std::fs::metadata(p) {
                let mode = meta.permissions().mode();
                let uid = meta.uid();
                (mode & 0o4000) != 0 && uid == 0
            } else {
                false
            }
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("crabsock-root-helper"));
            }
        }
        candidates.push(PathBuf::from("/usr/local/bin/crabsock-root-helper"));

        for p in candidates {
            if !(p.exists() && p.is_file() && is_suid_root(p.as_path())) {
                continue;
            }
            // Helper version check
            let out = std::process::Command::new(&p)
                .arg("version")
                .stdin(Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output();
            if let Ok(o) = out {
                let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if v == ROOT_HELPER_VERSION {
                    return Some(p);
                }
            }
        }
        None
    }

    // Try to auto-install helper via pkexec if not present.
    fn ensure_root_helper_installed() -> Option<PathBuf> {
        if let Some(h) = find_root_helper() {
            return Some(h);
        }

        let install_result: Result<(), String> = (|| {
            let cur = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe_dir = cur
                .parent()
                .ok_or_else(|| "Failed to resolve exe dir".to_string())?;
            let helper_src = exe_dir.join("crabsock-root-helper");
            if !helper_src.exists() {
                return Err(format!(
                    "Helper binary not found next to executable: {}",
                    helper_src.display()
                ));
            }

            // Locate install-openvpn-helper.sh in resources
            let mut script_candidates: Vec<PathBuf> = Vec::new();
            script_candidates.push(exe_dir.join("resources").join("install-openvpn-helper.sh"));
            if let Some(parent) = exe_dir.parent() {
                if let Some(grandparent) = parent.parent() {
                    script_candidates.push(
                        grandparent.join("resources").join("install-openvpn-helper.sh"),
                    );
                    script_candidates.push(
                        grandparent
                            .join("src-tauri")
                            .join("resources")
                            .join("install-openvpn-helper.sh"),
                    );
                }
            }
            // System-wide install (e.g. Debian/Ubuntu .deb layout)
            script_candidates.push(
                PathBuf::from("/usr/lib/CrabSock/resources/install-openvpn-helper.sh"),
            );
            let script = script_candidates
                .into_iter()
                .find(|p| p.exists() && p.is_file())
                .ok_or_else(|| "install-openvpn-helper.sh not found in resources".to_string())?;

            log::info!(
                "[ROOT-HELPER] Installing helper via pkexec: script={} src={}",
                script.display(),
                helper_src.display()
            );

            let status = std::process::Command::new("pkexec")
                .arg("bash")
                .arg(&script)
                .arg(&helper_src)
                .stdin(Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .status()
                .map_err(|e| format!("Failed to execute pkexec: {}", e))?;

            if !status.success() {
                return Err(format!(
                    "pkexec install-openvpn-helper.sh exited with status {:?}",
                    status.code()
                ));
            }

            Ok(())
        })();

        match install_result {
            Ok(()) => find_root_helper(),
            Err(e) => {
                log::warn!(
                    "[ROOT-HELPER] Failed to auto-install helper (pkexec): {}; falling back to pkexec wrapper",
                    e
                );
                None
            }
        }
    }

    if let Some(helper) = ensure_root_helper_installed() {
        log::info!(
            "[SING-BOX][SPAWN][Linux] Starting via root helper {}",
            helper.display()
        );
        let mut child = Command::new(&helper)
            .arg("singbox-run")
            .arg(singbox_path.to_string_lossy().as_ref())
            .arg(cfg_path.to_string_lossy().as_ref())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box via helper: {}", e)))?;

        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let mut r = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = r.next_line().await {
                    if !line.trim().is_empty() {
                        log::info!("[SING-BOX][STDOUT] {}", line);
                    }
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let mut r = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = r.next_line().await {
                    if !line.trim().is_empty() {
                        log::warn!("[SING-BOX][STDERR] {}", line);
                    }
                }
            });
        }
        Ok(child)
    } else {
        // Fallback: old pkexec wrapper if helper is not available
        log::info!(
            "[SING-BOX][SPAWN][Linux] Falling back to pkexec wrapper (helper unavailable)"
        );

        // Locate wrapper script
        let wrapper_path = if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let mut candidates: Vec<PathBuf> = Vec::new();
                candidates.push(exe_dir.join("resources").join("singbox-wrapper.sh"));
                if let Some(parent) = exe_dir.parent() {
                    if let Some(grandparent) = parent.parent() {
                        candidates.push(
                            grandparent.join("resources").join("singbox-wrapper.sh"),
                        );
                        candidates.push(
                            grandparent
                                .join("src-tauri")
                                .join("resources")
                                .join("singbox-wrapper.sh"),
                        );
                    }
                }
                // System-wide install (e.g. Debian/Ubuntu .deb layout)
                candidates.push(
                    PathBuf::from("/usr/lib/CrabSock/resources/singbox-wrapper.sh"),
                );
                candidates.into_iter().find(|p| p.exists())
            } else {
                None
            }
        } else {
            None
        };

        let wrapper =
            wrapper_path.ok_or_else(|| anyhow::anyhow!("singbox-wrapper.sh not found"))?;

        // Ensure wrapper is executable
        if let Ok(meta) = std::fs::metadata(&wrapper) {
            let mut perm = meta.permissions();
            perm.set_mode(0o755);
            let _ = std::fs::set_permissions(&wrapper, perm);
        }

        log::info!(
            "[SING-BOX][SPAWN][Linux] Starting via pkexec wrapper (one password prompt for all operations)"
        );

        // Start via pkexec bash wrapper (ONE password prompt!)
        let mut child = Command::new("pkexec")
            .args([
                "bash",
                wrapper.to_string_lossy().as_ref(),
                singbox_path.to_string_lossy().as_ref(),
                cfg_path.to_string_lossy().as_ref(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box via pkexec: {}", e)))?;

        log::info!(
            "[SING-BOX][SPAWN][Linux] pkexec bash {} {} {}",
            wrapper.display(),
            singbox_path.display(),
            cfg_path.display()
        );

        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let mut r = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = r.next_line().await {
                    if !line.trim().is_empty() {
                        log::info!("[SING-BOX][STDOUT] {}", line);
                    }
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let mut r = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = r.next_line().await {
                    if !line.trim().is_empty() {
                        log::warn!("[SING-BOX][STDERR] {}", line);
                    }
                }
            });
        }
        Ok(child)
    }
}

