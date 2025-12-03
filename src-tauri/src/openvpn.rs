use once_cell::sync::Lazy;
use serde::Serialize;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::collections::VecDeque;
use tauri::AppHandle;
use tauri::Manager;
use tauri::Emitter;

#[derive(Debug, Clone, Serialize)]
pub struct OpenVpnConfigInfo {
    pub name: String,
    pub path: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenVpnStatusEvent {
    pub status: String,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct OpenVpnManager {
    process: Option<Child>,
    active_config_name: Option<String>,
    management_port: Option<u16>,
    management_password_path: Option<PathBuf>,
    connected: bool,
    temp_cfg_path: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    used_helper: bool,
    #[cfg(target_os = "macos")]
    pid_file_path: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    log_file_path: Option<PathBuf>,
}

static GLOBAL_MGR: Lazy<Arc<Mutex<OpenVpnManager>>> = Lazy::new(|| Arc::new(Mutex::new(OpenVpnManager::default())));

// In-memory ring buffer for recent OpenVPN logs (for replay after frontend reload/start)
const LOG_BUFFER_CAP: usize = 500;
static LOG_BUFFER: Lazy<Mutex<VecDeque<String>>> = Lazy::new(|| Mutex::new(VecDeque::with_capacity(LOG_BUFFER_CAP)));

fn buffer_log(line: &str) {
    let mut q = LOG_BUFFER.lock().unwrap();
    if q.len() >= LOG_BUFFER_CAP { let _ = q.pop_front(); }
    q.push_back(line.to_string());
}

// Track last known status for frontend to query on (re)start
static LAST_STATUS: Lazy<Mutex<OpenVpnStatusEvent>> = Lazy::new(|| Mutex::new(OpenVpnStatusEvent { status: "disconnected".into(), detail: None }));

pub fn get_recent_logs(limit: usize) -> Vec<String> {
    let q = LOG_BUFFER.lock().unwrap();
    let n = limit.min(q.len());
    // return in original order
    q.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect()
}

pub fn current_status_event() -> OpenVpnStatusEvent {
    LAST_STATUS.lock().unwrap().clone()
}

impl OpenVpnManager {
    pub fn global() -> Arc<Mutex<OpenVpnManager>> {
        GLOBAL_MGR.clone()
    }

    fn configs_dir(_app: &AppHandle) -> Result<PathBuf, String> {
        let base = dirs::config_dir().ok_or_else(|| "Failed to resolve config dir".to_string())?.join("CrabSock");
        let dir = base.join("openvpn").join("configs");
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create configs dir: {}", e))?;
        Ok(dir)
    }

    fn temp_dir(_app: &AppHandle) -> Result<PathBuf, String> {
        let base = dirs::cache_dir().or_else(|| dirs::config_dir()).ok_or_else(|| "Failed to resolve cache/config dir".to_string())?.join("CrabSock");
        let dir = base.join("openvpn").join("tmp");
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;
        Ok(dir)
    }

    fn find_openvpn_path(_app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
        #[cfg(target_os = "windows")]
        {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let exe_dir = dir.to_path_buf();
                    let candidates = [
                        // alongside executable
                        exe_dir.join("openvpn.exe"),
                        // packaged resources
                        exe_dir.join("resources").join("openvpn_win").join("openvpn_amd64").join("openvpn.exe"),
                        exe_dir.join("resources").join("openvpn_win").join("openvpn_arm64").join("openvpn.exe"),
                        // alternative layout (observed in your error): next to exe without "resources" dir
                        exe_dir.join("openvpn_win").join("openvpn_amd64").join("openvpn.exe"),
                        exe_dir.join("openvpn_win").join("openvpn_arm64").join("openvpn.exe"),
                        // dev fallbacks from project root
                        std::path::PathBuf::from("./src-tauri/resources/openvpn_win/openvpn_amd64/openvpn.exe"),
                        std::path::PathBuf::from("./src-tauri/resources/openvpn_win/openvpn_arm64/openvpn.exe"),
                    ];
                    for p in candidates {
                        if p.exists() {
                            let work = p.parent().unwrap_or(&exe_dir).to_path_buf();
                            return Ok((p, work));
                        }
                    }
                }
            }
            Err("openvpn.exe not found near executable or in resources".into())
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let exe_dir = dir.to_path_buf();
                    // Prefer OpenVPN 2.x (supports management, data-ciphers), with arch-specific binary first
                    // NOTE: On macOS, Tauri bundles resources into Contents/Resources, while the binary is in Contents/MacOS.
                    // So check ../Resources/openvpn_macos/... first.
                    let bundle_resources_dir = exe_dir.parent().map(|p| p.join("Resources"));
                    #[cfg(target_arch = "aarch64")]
                    let candidates = {
                        let mut v = Vec::new();
                        if let Some(res) = &bundle_resources_dir {
                            // Standard Tauri layout when individual files/dirs are listed under bundle.resources
                            v.push(res.join("openvpn_macos").join("openvpn_arm64"));
                            v.push(res.join("openvpn_macos").join("openvpn"));
                            v.push(res.join("openvpn_macos").join("openvpn10"));
                            // When the entire "resources" directory is bundled, paths become Resources/resources/...
                            v.push(res.join("resources").join("openvpn_macos").join("openvpn_arm64"));
                            v.push(res.join("resources").join("openvpn_macos").join("openvpn"));
                            v.push(res.join("resources").join("openvpn_macos").join("openvpn10"));
                        }
                        // Legacy layout: alongside exec (dev or custom bundle)
                        v.push(exe_dir.join("resources").join("openvpn_macos").join("openvpn_arm64"));
                        v.push(exe_dir.join("resources").join("openvpn_macos").join("openvpn"));
                        v.push(exe_dir.join("resources").join("openvpn_macos").join("openvpn10"));
                        // Dev fallbacks from project root
                        v.push(std::path::PathBuf::from("./src-tauri/resources/openvpn_macos/openvpn_arm64"));
                        v.push(std::path::PathBuf::from("./src-tauri/resources/openvpn_macos/openvpn"));
                        v.push(std::path::PathBuf::from("./src-tauri/resources/openvpn_macos/openvpn10"));
                        v
                    };
                    #[cfg(not(target_arch = "aarch64"))]
                    let candidates = {
                        let mut v = Vec::new();
                        if let Some(res) = &bundle_resources_dir {
                            // Standard Tauri layout
                            v.push(res.join("openvpn_macos").join("openvpn"));
                            v.push(res.join("openvpn_macos").join("openvpn10"));
                            // Bundled "resources" directory layout
                            v.push(res.join("resources").join("openvpn_macos").join("openvpn"));
                            v.push(res.join("resources").join("openvpn_macos").join("openvpn10"));
                        }
                        v.push(exe_dir.join("resources").join("openvpn_macos").join("openvpn"));
                        v.push(exe_dir.join("resources").join("openvpn_macos").join("openvpn10"));
                        v.push(std::path::PathBuf::from("./src-tauri/resources/openvpn_macos/openvpn"));
                        v.push(std::path::PathBuf::from("./src-tauri/resources/openvpn_macos/openvpn10"));
                        v
                    };
                    for p in candidates {
                        if p.exists() {
                            let work = p.parent().unwrap_or(&exe_dir).to_path_buf();
                            return Ok((p, work));
                        }
                    }
                }
            }
            Err("openvpn (macOS) not found in resources".into())
        }
        #[cfg(target_os = "linux")]
        {
            // Rely on PATH
            Ok((PathBuf::from("openvpn"), PathBuf::from(".")))
        }
    }

    pub fn list_configs(app: &AppHandle) -> Result<Vec<OpenVpnConfigInfo>, String> {
        let dir = Self::configs_dir(app)?;
        let mut items = Vec::new();
        if let Ok(rd) = fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()).unwrap_or("") == "ovpn" {
                    if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
                        let (display_name, remote) = parse_ovpn_metadata(&p).unwrap_or_else(|| (name.to_string(), None));
                        items.push(OpenVpnConfigInfo { name: name.to_string(), path: p.to_string_lossy().to_string(), display_name, remote });
                    }
                }
            }
        }
        Ok(items)
    }

    pub fn add_config(app: &AppHandle, name: &str, content: &str) -> Result<(), String> {
        let sanitized = name.trim().trim_matches(|c: char| c == '/' || c == '\\');
        if sanitized.is_empty() {
            return Err("Empty config name".to_string());
        }
        let dir = Self::configs_dir(app)?;
        let mut path = dir.join(sanitized);
        if path.extension().is_none() {
            path.set_extension("ovpn");
        }
        fs::write(&path, content).map_err(|e| format!("Failed to write config: {}", e))?;
        Ok(())
    }

    pub fn remove_config(app: &AppHandle, name: &str) -> Result<(), String> {
        let dir = Self::configs_dir(app)?;
        let mut path = dir.join(name);
        if path.extension().is_none() {
            path.set_extension("ovpn");
        }
        if path.exists() {
            fs::remove_file(&path).map_err(|e| format!("Failed to remove config: {}", e))?;
        }
        Ok(())
    }

    fn pick_free_port() -> Result<u16, String> {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("Failed to bind ephemeral port: {}", e))
            .and_then(|l| l.local_addr().map_err(|e| e.to_string()).map(|a| a.port()))
    }

    pub fn connect(app: &AppHandle, name: &str) -> Result<(), String> {
        // Ensure previous instance is stopped BEFORE starting a new one to avoid killing the fresh process
        {
            let global = OpenVpnManager::global();
            let mut g = global.lock().unwrap();
            g.disconnect_internal();
        }
        let (exe, work_dir) = Self::find_openvpn_path(app)?;
        log::debug!("[OPENVPN] Binary: {}", exe.display());
        if !work_dir.as_os_str().is_empty() { log::debug!("[OPENVPN] Workdir: {}", work_dir.display()); }
        // Also emit to frontend log for visibility
        let msg = format!("[OPENVPN] Using binary: {}", exe.display());
        let _ = app.emit("openvpn-log", msg.clone());
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }

        // Try to detect version for diagnostics (capture both stdout/stderr)
        let version_out = std::process::Command::new(&exe)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .ok()
            .map(|o| {
                let mut s = String::new();
                if !o.stdout.is_empty() { s.push_str(&String::from_utf8_lossy(&o.stdout)); }
                if !o.stderr.is_empty() { s.push_str(&String::from_utf8_lossy(&o.stderr)); }
                s
            })
            .unwrap_or_default();
        let version_line = version_out.lines().next().unwrap_or("unknown version").to_string();
        let msg_v = format!("[OPENVPN] Detected version: {}", version_line);
        let _ = app.emit("openvpn-log", msg_v.clone());
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg_v.clone()); }
        // Detect management support. Prefer heuristic via --help content.
        let help_out = std::process::Command::new(&exe)
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .ok()
            .map(|o| {
                let mut s = String::new();
                if !o.stdout.is_empty() { s.push_str(&String::from_utf8_lossy(&o.stdout)); }
                if !o.stderr.is_empty() { s.push_str(&String::from_utf8_lossy(&o.stderr)); }
                s.to_ascii_lowercase()
            })
            .unwrap_or_default();
        let exe_name = exe.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_ascii_lowercase();
        let looks_like_v3 = exe_name.contains("openvpn10") || version_line.to_ascii_lowercase().contains("openvpn 3");
        let mentions_management = help_out.contains("management");
        #[allow(unused_mut)]
        let mut supports_management = !looks_like_v3 && mentions_management;
        // On macOS management caused parsing errors even when help said it's supported; disable for reliability.
        #[cfg(target_os = "macos")]
        {
            supports_management = false;
        }
        let msg_supp = format!("[OPENVPN] Management support: {} (v3-like: {}, help has 'management': {})", supports_management, looks_like_v3, mentions_management);
        let _ = app.emit("openvpn-log", msg_supp.clone());
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg_supp.clone()); }
        if !supports_management {
            let msg = "[OPENVPN] Skipping management injection for this binary";
            let _ = app.emit("openvpn-log", msg);
            for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg); }
        }

        let configs = Self::configs_dir(app)?;
        let mut cfg = configs.join(name);
        if cfg.extension().is_none() { cfg.set_extension("ovpn"); }
        if !cfg.exists() { return Err(format!("Config not found: {}", cfg.display())); }
        log::debug!("[OPENVPN] Base config: {}", cfg.display());

        // Prepare temp config with management line
        let tmp_dir = Self::temp_dir(app)?;
        let tmp_cfg = tmp_dir.join(format!("{}-run.ovpn", name));
        let management_password_path = tmp_dir.join(format!("{}-mgmt.txt", name));

        let pass = format!("{}", uuid_like());
        fs::write(&management_password_path, &pass)
            .map_err(|e| format!("Failed to write management password: {}", e))?;
        log::debug!("[OPENVPN] Management file: {}", management_password_path.display());

        let original = fs::read_to_string(&cfg).map_err(|e| format!("Failed to read config: {}", e))?;
        let port = Self::pick_free_port()?;
        // Escape backslashes on Windows for OpenVPN config
        #[allow(unused_mut)]
        let mut mgmt_path_str = management_password_path.to_string_lossy().to_string();
        #[cfg(target_os = "windows")]
        {
            mgmt_path_str = mgmt_path_str.replace("\\", "\\\\");
        }
        let mgmt_line = format!("\nmanagement 127.0.0.1 {} {}\n", port, mgmt_path_str);
        if supports_management {
            let msg_mgmt = format!("[OPENVPN] Injecting management: 127.0.0.1 {} <pass_file>", port);
            let _ = app.emit("openvpn-log", msg_mgmt.clone());
            for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg_mgmt.clone()); }
        }

        // Build composed config; only handle bare auth-user-pass (no path)
        let mut composed_lines: Vec<String> = Vec::new();
        let mut needs_auth_file = false;
        for line in original.lines() {
            let t = line.trim();
            let ll = t.to_ascii_lowercase();
            if ll.starts_with("auth-user-pass") {
                let parts: Vec<&str> = t.split_whitespace().collect();
                if parts.len() == 1 {
                    needs_auth_file = true;
                    continue;
                } else {
                    // keep user-specified path exactly as-is
                    composed_lines.push(line.to_string());
                    continue;
                }
            }
            composed_lines.push(line.to_string());
        }
        if needs_auth_file {
            let mut auth_path = cfg.clone();
            auth_path.set_extension("auth");
            if auth_path.exists() {
                #[allow(unused_mut)]
                let mut auth_str = auth_path.to_string_lossy().to_string();
                #[cfg(target_os = "windows")]
                { auth_str = auth_str.replace("\\", "\\\\"); }
                composed_lines.push(format!("auth-user-pass {}", auth_str));
            } else {
                let msg = format!("[OPENVPN] 'auth-user-pass' present but no .auth file next to config: {}", auth_path.display());
                log::warn!("{}", msg);
                // Also emit to UI logs for clarity
                let _ = app.emit("openvpn-log", msg.clone());
                for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                return Err("OpenVPN config requires credentials (auth-user-pass) but no .auth file was found next to the .ovpn. Create a .auth file with two lines: username and password.".to_string());
            }
        }
        composed_lines.push(String::new());
        if supports_management {
            composed_lines.push(mgmt_line);
        }
        let composed = composed_lines.join("\n");
        fs::write(&tmp_cfg, composed).map_err(|e| format!("Failed to write temp config: {}", e))?;
        log::debug!("[OPENVPN] Temp config: {} (management port {})", tmp_cfg.display(), port);
        let msg_cfg = format!("[OPENVPN] Temp config written: {} (mgmt port {})", tmp_cfg.display(), port);
        let _ = app.emit("openvpn-log", msg_cfg.clone());
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg_cfg.clone()); }

        // Build args similar to Pritunl: --config <cfg> --verb 2
        let mut args = vec!["--config".to_string(), tmp_cfg.to_string_lossy().to_string(), "--verb".to_string(), "2".to_string()];
        #[cfg(target_os = "windows")]
        {
            args.push("--script-security".to_string());
            args.push("1".to_string());
        }
        log::debug!("[OPENVPN] Args: {:?}", args);
        let msg_args = format!("[OPENVPN] Launch args: {:?}", args);
        let _ = app.emit("openvpn-log", msg_args.clone());
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg_args.clone()); }
        #[cfg(target_os = "linux")]
        {
            if !has_apparmor() {
                let (up, down) = write_linux_dns_scripts(app, name)?;
                args.push("--script-security".to_string());
                args.push("2".to_string());
                args.push("--up".to_string());
                args.push(up.to_string_lossy().to_string());
                args.push("--down".to_string());
                args.push(down.to_string_lossy().to_string());
            }
        }

        // Use stdout for logs; avoid redirecting to file so frontend receives live logs
        let args_with_log = args.clone();

        // On Linux we try to use the setuid helper crabsock-root-helper,
        // which executes the system openvpn with the same arguments.
        // If the helper is not installed, we try to install it via pkexec and the bundled installer script.
        #[cfg(target_os = "linux")]
        let (spawn_exe, used_helper_flag) = {
            const ROOT_HELPER_VERSION: &str = "1";

            fn find_existing_helper() -> Option<PathBuf> {
                use std::path::Path;
                #[cfg(unix)]
                fn is_suid_root(p: &Path) -> bool {
                    use std::os::unix::fs::PermissionsExt;
                    use std::os::unix::prelude::MetadataExt;
                    if let Ok(meta) = std::fs::metadata(p) {
                        let mode = meta.permissions().mode();
                        let uid = meta.uid();
                        // setuid bit and owned by root
                        (mode & 0o4000) != 0 && uid == 0
                    } else {
                        false
                    }
                }
                #[cfg(not(unix))]
                fn is_suid_root(_p: &Path) -> bool { false }

                let mut candidates: Vec<PathBuf> = Vec::new();
                // 1) next to the application binary (primary path in dev/packaged mode)
                if let Ok(cur) = std::env::current_exe() {
                    if let Some(dir) = cur.parent() {
                        candidates.push(dir.join("crabsock-root-helper"));
                    }
                }
                // 2) system fallback, if installer already placed helper into /usr/local/bin
                candidates.push(PathBuf::from("/usr/local/bin/crabsock-root-helper"));

                for p in candidates {
                    if !(p.exists() && p.is_file() && is_suid_root(&p)) {
                        continue;
                    }
                    // Check helper version; if it does not match, treat as not installed.
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

            if let Some(helper) = find_existing_helper() {
                let msg = format!(
                    "[OPENVPN] Using helper binary: {} (will execute system openvpn)",
                    helper.display()
                );
                let _ = app.emit("openvpn-log", msg.clone());
                for (_, win) in app.webview_windows() {
                    let _ = win.emit("openvpn-log", msg.clone());
                }
                (helper, true)
            } else {
                // Try to auto-install the helper via pkexec.
                let install_result: Result<(), String> = (|| {
                    let cur = std::env::current_exe().map_err(|e| e.to_string())?;
                    let exe_dir = cur.parent().ok_or_else(|| "Failed to resolve exe dir".to_string())?;
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
                            script_candidates.push(grandparent.join("resources").join("install-openvpn-helper.sh"));
                            script_candidates.push(
                                grandparent
                                    .join("src-tauri")
                                    .join("resources")
                                    .join("install-openvpn-helper.sh"),
                            );
                        }
                    }
                    let script = script_candidates
                        .into_iter()
                        .find(|p| p.exists() && p.is_file())
                        .ok_or_else(|| "install-openvpn-helper.sh not found in resources".to_string())?;

                    let msg = format!(
                        "[OPENVPN] Installing helper via pkexec: script={} src={}",
                        script.display(),
                        helper_src.display()
                    );
                    let _ = app.emit("openvpn-log", msg.clone());
                    for (_, win) in app.webview_windows() {
                        let _ = win.emit("openvpn-log", msg.clone());
                    }

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
                        return Err(format!("pkexec install-openvpn-helper.sh exited with status {:?}", status.code()));
                    }

                    Ok(())
                })();

                match install_result {
                    Ok(()) => {
                        if let Some(helper) = find_existing_helper() {
                            let msg = format!(
                                "[OPENVPN] Helper installed and will be used: {}",
                                helper.display()
                            );
                            let _ = app.emit("openvpn-log", msg.clone());
                            for (_, win) in app.webview_windows() {
                                let _ = win.emit("openvpn-log", msg.clone());
                            }
                            (helper, true)
                        } else {
                            let msg = "[OPENVPN] Helper installation reported success but helper not found; falling back to direct openvpn";
                            let _ = app.emit("openvpn-log", msg);
                            for (_, win) in app.webview_windows() {
                                let _ = win.emit("openvpn-log", msg);
                            }
                            (exe.clone(), false)
                        }
                    }
                    Err(e) => {
                        let msg = format!(
                            "[OPENVPN] Failed to auto-install helper (pkexec): {}; falling back to direct openvpn",
                            e
                        );
                        let _ = app.emit("openvpn-log", msg.clone());
                        for (_, win) in app.webview_windows() {
                            let _ = win.emit("openvpn-log", msg.clone());
                        }
                        (exe.clone(), false)
                    }
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let (spawn_exe, used_helper_flag) = (exe.clone(), false);

        // Spawn process (Windows: require app to be elevated; do not self-elevate OpenVPN)
        #[cfg(target_os = "windows")]
        let mut child: Option<Child> = {
            if !is_elevated_windows_local() {
                return Err("OpenVPN requires Administrator privileges. Please restart the app as Administrator.".into());
            }
            let mut cmd = Command::new(&exe);
            cmd.args(&args_with_log)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // Hide console window for run
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            if !work_dir.as_os_str().is_empty() { cmd.current_dir(&work_dir); }
            let ch = cmd.spawn().map_err(|e| format!("Failed to start OpenVPN: {}", e))?;
            log::debug!("[OPENVPN] PID: {}", ch.id());
            Some(ch)
        };
        #[cfg(not(target_os = "windows"))]
        let mut child: Option<Child> = {
            // Best-effort: ensure the bundled binary is executable and not quarantined (macOS)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&spawn_exe) {
                    let mut perm = meta.permissions();
                    let mode = perm.mode();
                    // ensure owner/group/world execute bits
                    let target = mode | 0o111;
                    if target != mode {
                        perm.set_mode(target);
                        let _ = std::fs::set_permissions(&spawn_exe, perm);
                        let msg = format!("[OPENVPN] Set executable bit on {}", spawn_exe.display());
                        let _ = app.emit("openvpn-log", msg.clone());
                        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                // Remove quarantine attribute if present; ignore errors
                let _ = std::process::Command::new("xattr")
                    .args(["-d", "com.apple.quarantine", &exe.to_string_lossy()])
                    .stdin(Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let msg = format!("[OPENVPN] Attempted to remove quarantine attribute from {}", exe.display());
                let _ = app.emit("openvpn-log", msg.clone());
                for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
            }

            // On macOS, run elevated; otherwise regular spawn
            #[cfg(target_os = "macos")]
            {
                let is_root = std::process::Command::new("id").arg("-u").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false);
                let tmp_dir = Self::temp_dir(app)?;
                let pid_file = tmp_dir.join(format!("{}-openvpn.pid", name));
                let log_file = tmp_dir.join(format!("{}-openvpn.log", name));
                let elevated_args = args_with_log.clone();
                let script_path = tmp_dir.join(format!("{}-openvpn-elev.sh", name));
                // Build daemon args so OpenVPN forks itself and writes pid/log
                let mut daemon_args = elevated_args.clone();
                daemon_args.push("--writepid".to_string());
                daemon_args.push(pid_file.to_string_lossy().to_string());
                daemon_args.push("--log".to_string());
                daemon_args.push(log_file.to_string_lossy().to_string());
                daemon_args.push("--daemon".to_string());
                if !is_root {
                let exe_q = exe.to_string_lossy().replace('"', "\\\"");
                let args_joined = daemon_args
                    .iter()
                    .map(|a| format!("\"{}\"", a.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut script = String::new();
                script.push_str("#!/bin/sh\nset -e\n");
                script.push_str("export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin\n");
                if !work_dir.as_os_str().is_empty() {
                    script.push_str(&format!("cd \"{}\"\n", work_dir.to_string_lossy().replace('"', "\\\"")));
                }
                // Run OpenVPN with --daemon; it will fork, write pid/log, and return
                script.push_str(&format!("exec \"{}\" {}\n", exe_q, args_joined));
                std::fs::write(&script_path, script).map_err(|e| format!("Failed to write elevate script: {}", e))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&script_path) {
                        let mut p = meta.permissions();
                        p.set_mode(0o755);
                        let _ = std::fs::set_permissions(&script_path, p);
                    }
                }

                // Build AppleScript to run the shell script with admin privileges
                let osa_script = format!(
                    "do shell script \"/bin/sh '{}'\" with administrator privileges",
                    script_path.to_string_lossy().replace('"', "\\\"")
                );
                let out = std::process::Command::new("osascript")
                    .args(["-e", &osa_script])
                    .stdin(Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        let msg = format!("[OPENVPN] Started elevated via osascript; tailing {}", log_file.display());
                        let _ = app.emit("openvpn-log", msg.clone());
                        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                        let app_handle3 = app.clone();
                        let log_for_tail = log_file.clone();
                        std::thread::spawn(move || { tail_log_file(&log_for_tail, &app_handle3); });
                        {
                            if let Ok(mut guard) = OpenVpnManager::global().lock() {
                                guard.pid_file_path = Some(pid_file.clone());
                                guard.log_file_path = Some(log_file.clone());
                            }
                        }
                        None
                    }
                    Ok(o) => {
                        let so = String::from_utf8_lossy(&o.stdout);
                        let se = String::from_utf8_lossy(&o.stderr);
                        let msg = format!("[OPENVPN][ELEVATE][osascript] status={:?} stdout='{}' stderr='{}'", o.status.code(), so.trim(), se.trim());
                        let _ = app.emit("openvpn-log", msg.clone());
                        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                        return Err(format!("Failed to elevate OpenVPN (status {:?})", o.status.code()));
                    }
                    Err(e) => { return Err(format!("Failed to invoke osascript: {}", e)); }
                }
            } else {
                let mut cmd = Command::new(&exe);
                // Run directly as root using daemon args
                let mut daemon_args = args_with_log.clone();
                daemon_args.push("--writepid".to_string());
                daemon_args.push(pid_file.to_string_lossy().to_string());
                daemon_args.push("--log".to_string());
                daemon_args.push(log_file.to_string_lossy().to_string());
                daemon_args.push("--daemon".to_string());
                cmd.args(&daemon_args)
                    .stdin(Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                if !work_dir.as_os_str().is_empty() { cmd.current_dir(&work_dir); }
                let st = cmd.status().map_err(|e| format!("Failed to start OpenVPN: {}", e))?;
                if !st.success() { return Err(format!("OpenVPN exited immediately with status {:?}", st.code())); }
                let app_handle3 = app.clone();
                let log_for_tail = log_file.clone();
                std::thread::spawn(move || { tail_log_file(&log_for_tail, &app_handle3); });
                {
                    if let Ok(mut guard) = OpenVpnManager::global().lock() {
                        guard.pid_file_path = Some(pid_file.clone());
                        guard.log_file_path = Some(log_file.clone());
                    }
                }
                None
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let mut cmd = Command::new(&spawn_exe);
            cmd.args(&args_with_log)
                .stdin(Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if !work_dir.as_os_str().is_empty() { cmd.current_dir(&work_dir); }
            let ch = match cmd.spawn() {
                Ok(ch) => ch,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = std::fs::metadata(&spawn_exe) {
                                let mut perm = meta.permissions();
                                perm.set_mode(0o755);
                                let _ = std::fs::set_permissions(&spawn_exe, perm);
                                let msg = format!("[OPENVPN] Permission denied; applied chmod 755 to {}", spawn_exe.display());
                                let _ = app.emit("openvpn-log", msg.clone());
                                for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                            }
                        }
                        let retry = Command::new(&spawn_exe)
                            .args(&args_with_log)
                            .stdin(Stdio::null())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .current_dir(&work_dir)
                            .spawn();
                        match retry {
                            Ok(ch2) => ch2,
                            Err(e2) => {
                                let msg = format!("[OPENVPN] Retry spawn failed: {}", e2);
                                let _ = app.emit("openvpn-log", msg.clone());
                                for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                                return Err(format!("Failed to start OpenVPN: {}", e2));
                            }
                        }
                    } else {
                        let msg = format!("[OPENVPN] Spawn failed: {}", e);
                        let _ = app.emit("openvpn-log", msg.clone());
                        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
                        return Err(format!("Failed to start OpenVPN: {}", e));
                    }
                }
            };
            log::debug!("[OPENVPN] PID: {}", ch.id());
            Some(ch)
        }

        };

        // Setup log readers only if we have a direct child process (non-macOS flow)
        if let Some(c) = child.as_mut() {
            let stdout = c.stdout.take();
            let stderr = c.stderr.take();
            let app_handle = app.clone();
            thread::spawn(move || {
                if let Some(out) = stdout { read_and_emit_logs(out, &app_handle); }
            });
            let app_handle2 = app.clone();
            thread::spawn(move || {
                if let Some(err) = stderr { read_and_emit_logs(err, &app_handle2); }
            });
        }

        // Persist state
        {
            let global = OpenVpnManager::global();
            let mut g = global.lock().unwrap();
            g.process = child;
            g.active_config_name = Some(name.to_string());
            g.management_port = if supports_management { Some(port) } else { None };
            g.management_password_path = if supports_management { Some(management_password_path.clone()) } else { None };
            g.connected = false;
            g.temp_cfg_path = Some(tmp_cfg.clone());
            #[cfg(target_os = "linux")]
            {
                g.used_helper = used_helper_flag;
            }
        }

        // Emit initial status, then watch for connected line in logs
        let evt = OpenVpnStatusEvent { status: "connecting".into(), detail: None };
        if let Ok(mut s) = LAST_STATUS.lock() { *s = evt.clone(); }
        // emit to all windows
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-status", evt.clone()); }
        // also try app-scope emit if available
        let _ = app.emit("openvpn-status", evt);
        log::debug!("[OPENVPN] Status -> connecting");

        // Background watcher to infer connected by scanning temp log file via events
        // Simplified: poll for a while and flip status if process is alive for >3s and no error
        let app_handle3 = app.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            let mut alive = false;
            {
                let global_in = OpenVpnManager::global();
                let mut guard = global_in.lock().unwrap();
                if let Some(child) = guard.process.as_mut() {
                    alive = child.try_wait().ok().flatten().is_none();
                }
            }
            if alive {
                let evt = OpenVpnStatusEvent { status: "connected".into(), detail: None };
                if let Ok(mut s) = LAST_STATUS.lock() { *s = evt.clone(); }
                for (_, win) in app_handle3.webview_windows() { let _ = win.emit("openvpn-status", evt.clone()); }
                let _ = app_handle3.emit("openvpn-status", evt);
                log::debug!("[OPENVPN] Status -> connected (alive)");
                let global2 = OpenVpnManager::global();
                let mut g = global2.lock().unwrap();
                g.connected = true;
            }
        });

        Ok(())
    }

    pub fn disconnect(app: &AppHandle) -> Result<(), String> {
        let global = OpenVpnManager::global();
        let mut g = global.lock().unwrap();
        let had = g.process.is_some();
        g.disconnect_internal();
        drop(g);
        if had {
            let evt = OpenVpnStatusEvent { status: "disconnected".into(), detail: None };
            if let Ok(mut s) = LAST_STATUS.lock() { *s = evt.clone(); }
            for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-status", evt.clone()); }
            let _ = app.emit("openvpn-status", evt);
            log::debug!("[OPENVPN] Status -> disconnected");
            // Also emit generic status for UI
            for (_, win) in app.webview_windows() { let _ = win.emit("status", serde_json::json!({ "status": "disconnected" })); }
            let _ = app.emit("status", serde_json::json!({ "status": "disconnected" }));
        }
        Ok(())
    }

    fn disconnect_internal(&mut self) {
        if let Some(child) = self.process.as_mut() {
            // Try graceful via management, else kill
            if let (Some(port), Some(pass_path)) = (self.management_port, self.management_password_path.as_ref()) {
                let _ = send_management_signal(port, pass_path, "signal SIGTERM");
                thread::sleep(Duration::from_millis(300));
            }
            #[cfg(target_os = "linux")]
            {
                // If we used the setuid helper, rely on management SIGTERM only,
                // to avoid leaving the root-owned openvpn process orphaned after killing the helper process.
                if !self.used_helper {
                    let _ = child.kill();
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = child.kill();
            }
        }
        #[cfg(target_os = "macos")]
        {
            // If elevated (no child), try kill by pid file
            if self.process.is_none() {
                if let Some(pid_path) = self.pid_file_path.as_ref() {
                    if let Ok(pid_str) = std::fs::read_to_string(pid_path) {
                        if let Ok(pid) = pid_str.trim().parse::<i32>() {
                            // Try unprivileged SIGTERM first (may fail if process is root)
                            let term_status = std::process::Command::new("kill").arg("-TERM").arg(pid.to_string())
                                .stdin(Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status()
                                .ok();
                            let mut need_elevated_kill = true;
                            if let Some(st) = term_status {
                                // Success only if exit status is 0
                                need_elevated_kill = !st.success();
                            }
                            if need_elevated_kill {
                                // Attempt elevated kill via AppleScript to handle root-owned OpenVPN
                                let osa = format!(
                                    "do shell script \"kill -TERM {pid}; sleep 0.2; kill -KILL {pid} 2>/dev/null || true\" with administrator privileges",
                                );
                                let _ = std::process::Command::new("osascript")
                                    .args(["-e", &osa])
                                    .stdin(Stdio::null())
                                    .stdout(std::process::Stdio::null())
                                    .stderr(std::process::Stdio::null())
                                    .status();
                            }
                            // Best-effort: remove stale pid file
                            let _ = std::fs::remove_file(pid_path);
                        }
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            // If elevated (no child) or still hanging, force kill by matching our temp config in command line
            if self.process.is_none() {
                if let Some(p) = self.temp_cfg_path.as_ref() {
                    if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                        let filter = fname.replace('"', "\"");
                        let ps = format!(
                            "Get-CimInstance Win32_Process | Where-Object {{ $_.Name -eq 'openvpn.exe' -and $_.CommandLine -match '{}'}} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}",
                            filter
                        );
                        let mut cmd = std::process::Command::new("powershell");
                        use std::process::Stdio as OsStdio;
                        use std::os::windows::process::CommandExt;
                        cmd.creation_flags(0x08000000)
                            .args(["-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command", &ps])
                            .stdin(OsStdio::null())
                            .stdout(OsStdio::null())
                            .stderr(OsStdio::null());
                        let _ = cmd.status();
                    }
                }
            }
        }
        self.process = None;
        self.active_config_name = None;
        self.management_port = None;
        self.management_password_path = None;
        self.connected = false;
        self.temp_cfg_path = None;
        #[cfg(target_os = "linux")]
        {
            self.used_helper = false;
        }
        #[cfg(target_os = "macos")]
        {
            self.pid_file_path = None;
            self.log_file_path = None;
        }
    }

    pub fn status() -> (bool, bool) {
        let global = OpenVpnManager::global();
        let g = global.lock().unwrap();
        let running = g.process.as_ref().map(|c| c.id()).is_some();
        (running, g.connected)
    }

    // Stop without emitting UI events (for shutdown paths)
    pub fn disconnect_silent() {
        let global = OpenVpnManager::global();
        let mut g = global.lock().unwrap();
        g.disconnect_internal();
    }
}

fn read_and_emit_logs<R: std::io::Read + Send + 'static>(reader: R, app: &AppHandle) {
    let buf = BufReader::new(reader);
    for line in buf.lines().flatten() {
        buffer_log(&line);
        log::debug!("[OPENVPN][OUT] {}", line);
        for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", line.clone()); }
        let _ = app.emit("openvpn-log", line.clone());
        if line.contains("Initialization Sequence Completed") {
            let evt = OpenVpnStatusEvent { status: "connected".into(), detail: None };
            if let Ok(mut s) = LAST_STATUS.lock() { *s = evt.clone(); }
            for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-status", evt.clone()); }
            let _ = app.emit("openvpn-status", evt);
            log::debug!("[OPENVPN] Status -> connected (init complete)");
            if let Ok(mut g) = OpenVpnManager::global().lock() { g.connected = true; }
            // Also emit generic status event for UI consumers
            for (_, win) in app.webview_windows() { let _ = win.emit("status", serde_json::json!({ "status": "connected" })); }
            let _ = app.emit("status", serde_json::json!({ "status": "connected" }));
        }
    }
}

fn tail_log_file(path: &Path, app: &AppHandle) {
    use std::io::{Read, Seek, SeekFrom};
    let mut offset: u64 = 0;
    let max_iters = 60 * 60; // ~1h @1s
    for _ in 0..max_iters {
        std::thread::sleep(Duration::from_secs(1));
        let meta = match std::fs::metadata(path) { Ok(m) => m, Err(_) => continue };
        let len = meta.len();
        if len <= offset { continue; }
        let mut f = match std::fs::OpenOptions::new().read(true).open(path) { Ok(x) => x, Err(_) => continue };
        if f.seek(SeekFrom::Start(offset)).is_err() { continue; }
        let mut buf = String::new();
        if Read::read_to_string(&mut f, &mut buf).is_err() { continue; }
        offset = len;
        for line in buf.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            buffer_log(line);
            log::debug!("[OPENVPN][LOG] {}", line);
            let msg = line.to_string();
            for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-log", msg.clone()); }
            let _ = app.emit("openvpn-log", msg);
            if line.contains("Initialization Sequence Completed") {
                let evt = OpenVpnStatusEvent { status: "connected".into(), detail: None };
                if let Ok(mut s) = LAST_STATUS.lock() { *s = evt.clone(); }
                for (_, win) in app.webview_windows() { let _ = win.emit("openvpn-status", evt.clone()); }
                let _ = app.emit("openvpn-status", evt);
                if let Ok(mut g) = OpenVpnManager::global().lock() { g.connected = true; }
                // Also emit generic status event for UI consumers
                for (_, win) in app.webview_windows() { let _ = win.emit("status", serde_json::json!({ "status": "connected" })); }
                let _ = app.emit("status", serde_json::json!({ "status": "connected" }));
            }
        }
    }
}

fn send_management_signal(port: u16, pass_path: &Path, cmd: &str) -> Result<(), String> {
    use std::net::TcpStream;
    let pass = fs::read_to_string(pass_path).map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let _ = stream.write_all(format!("{}\n", pass.trim()).as_bytes());
    thread::sleep(Duration::from_millis(200));
    let _ = stream.write_all(format!("{}\n", cmd).as_bytes());
    Ok(())
}

fn uuid_like() -> String {
    // Simple unique-ish token for management password
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

#[cfg(target_os = "linux")]
fn has_apparmor() -> bool {
    match std::fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
        Ok(s) => s.trim().to_ascii_uppercase().starts_with('Y'),
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn write_linux_dns_scripts(app: &AppHandle, name: &str) -> Result<(PathBuf, PathBuf), String> {
    let dir = OpenVpnManager::temp_dir(app)?;
    let up = dir.join(format!("{}-up.sh", name));
    let down = dir.join(format!("{}-down.sh", name));

    let up_script = r#"#!/bin/sh
set -eu
IFACE="${dev:-tun0}"

DNS_LIST=""
DOMAIN_NAME=""

# Extract foreign_option_* that contain DHCP options
env | grep -E '^foreign_option_' | sort -t_ -k3 -n | cut -d= -f2- | while IFS= read -r opt; do
  case "$opt" in
    *"dhcp-option DNS "*)
      DNS_LIST="$DNS_LIST $(echo "$opt" | awk '{print $3}')"
      ;;
    *"dhcp-option DOMAIN "*)
      DOMAIN_NAME="$(echo "$opt" | awk '{print $3}')"
      ;;
  esac
done

if command -v resolvectl >/dev/null 2>&1; then
  for s in $DNS_LIST; do resolvectl dns "$IFACE" "$s" || true; done
  if [ -n "$DOMAIN_NAME" ]; then resolvectl domain "$IFACE" "$DOMAIN_NAME" || true; fi
  resolvectl flush-caches || true
elif command -v systemd-resolve >/dev/null 2>&1; then
  for s in $DNS_LIST; do systemd-resolve --interface="$IFACE" --set-dns="$s" || true; done
  if [ -n "$DOMAIN_NAME" ]; then systemd-resolve --interface="$IFACE" --set-domain="$DOMAIN_NAME" || true; fi
else
  # Fallback to editing resolv.conf (best effort)
  if [ -w /etc/resolv.conf ]; then
    cp -f /etc/resolv.conf /etc/resolv.conf.crabsock.bak 2>/dev/null || true
    : > /etc/resolv.conf
    for s in $DNS_LIST; do echo "nameserver $s" >> /etc/resolv.conf; done
    if [ -n "$DOMAIN_NAME" ]; then echo "search $DOMAIN_NAME" >> /etc/resolv.conf; fi
  fi
fi
"#;

    let down_script = r#"#!/bin/sh
set -eu
IFACE="${dev:-tun0}"

if command -v resolvectl >/dev/null 2>&1; then
  resolvectl revert "$IFACE" || true
  resolvectl flush-caches || true
elif command -v systemd-resolve >/dev/null 2>&1; then
  # systemd-resolve has no direct revert; try clearing
  systemd-resolve --interface="$IFACE" --set-dns='' || true
else
  if [ -f /etc/resolv.conf.crabsock.bak ] && [ -w /etc/resolv.conf ]; then
    mv -f /etc/resolv.conf.crabsock.bak /etc/resolv.conf 2>/dev/null || true
  fi
fi
"#;

    std::fs::write(&up, up_script).map_err(|e| format!("Failed to write up script: {}", e))?;
    std::fs::write(&down, down_script).map_err(|e| format!("Failed to write down script: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&up).map_err(|e| e.to_string())?.permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&up, p).map_err(|e| e.to_string())?;
        let mut p2 = std::fs::metadata(&down).map_err(|e| e.to_string())?.permissions();
        p2.set_mode(0o755);
        std::fs::set_permissions(&down, p2).map_err(|e| e.to_string())?;
    }

    Ok((up, down))
}

#[cfg(target_os = "windows")]
fn is_elevated_windows_local() -> bool {
    let mut cmd = std::process::Command::new("powershell");
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    let out = cmd
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

fn parse_ovpn_metadata(path: &Path) -> Option<(String, Option<String>)> {
    let content = fs::read_to_string(path).ok()?;
    let mut uv_name: Option<String> = None;
    let mut remote: Option<String> = None;
    for line in content.lines() {
        let l = line.trim();
        let ll = l.to_ascii_lowercase();
        if uv_name.is_none() && ll.starts_with("setenv uv_name ") {
            // exact slice after the directive (len("setenv uv_name ") == 15)
            let v = &l[15..];
            if !v.is_empty() { uv_name = Some(v.trim().to_string()); }
        }
        if remote.is_none() {
            if ll.starts_with('#') || ll.starts_with(';') { continue; }
            if ll.starts_with("remote ") {
                // remote HOST [PORT] [PROTO]
                let mut it = l.split_whitespace();
                let _ = it.next(); // "remote"
                if let Some(host) = it.next() {
                    let port_opt = it.next();
                    let value = if let Some(port) = port_opt {
                        if port.chars().all(|c| c.is_ascii_digit()) {
                            format!("{}:{}", host, port)
                        } else {
                            host.to_string()
                        }
                    } else { host.to_string() };
                    remote = Some(value);
                }
            }
        }
        if uv_name.is_some() && remote.is_some() { break; }
    }
    let name = uv_name.or_else(|| remote.clone()).or_else(|| path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))?;
    Some((name, remote))
}
