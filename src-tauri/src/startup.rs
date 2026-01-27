use crab_sock::config_manager::ConfigManager;
use tauri::Manager;

/// Parsed command-line options relevant for startup/elevation flows.
pub struct StartupArgs {
    pub auto_ovpn: Option<String>,
    pub auto_proxy: Option<String>,
    pub elevated_relaunch: bool,
    pub routing_override: Option<String>,
}

/// Parse CLI overrides (e.g. from elevation relaunch) and persist routing changes if requested.
pub fn parse_startup_args() -> StartupArgs {
    let mut auto_ovpn: Option<String> = None;
    let mut auto_proxy: Option<String> = None;
    let mut elevated_relaunch: bool = false;
    let mut routing_override: Option<String> = None;

    let args: Vec<String> = std::env::args().collect();

    if let Some(arg) = args.iter().find(|a| a.starts_with("--set-routing=")) {
        let val = arg.trim_start_matches("--set-routing=").to_lowercase();
        routing_override = Some(val.clone());
        tauri::async_runtime::block_on(async {
            if let Ok(manager) = ConfigManager::new() {
                if let Ok(mut file) = manager.load_configs().await {
                    file.settings.routing_mode = if val == "tun" {
                        crab_sock::config_manager::RoutingMode::Tun
                    } else {
                        crab_sock::config_manager::RoutingMode::SystemProxy
                    };
                    let _ = manager.save_configs(&file).await;
                    log::info!("[MAIN] Routing mode overridden by CLI: {}", val);
                }
            }
        });
    }

    if let Some(arg) = args.iter().find(|a| a.starts_with("--openvpn-connect=")) {
        let val = arg
            .trim_start_matches("--openvpn-connect=")
            .trim_matches('"')
            .to_string();
        auto_ovpn = Some(val);
    }

    if let Some(arg) = args.iter().find(|a| a.starts_with("--proxy-connect=")) {
        let val = arg
            .trim_start_matches("--proxy-connect=")
            .trim_matches('"')
            .to_string();
        auto_proxy = Some(val);
    }

    if args.iter().any(|a| a == "--elevated-relaunch") {
        elevated_relaunch = true;
    }

    StartupArgs {
        auto_ovpn,
        auto_proxy,
        elevated_relaunch,
        routing_override,
    }
}

#[cfg(target_os = "windows")]
fn is_elevated_process() -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let out = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
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
fn other_crabsock_instance_running() -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let current_pid = std::process::id();
    let ps = format!(
        "Get-Process -Name 'crab-sock' -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -ne {} }} | Select-Object -First 1 | ForEach-Object {{ 'found' }}",
        current_pid
    );
    let out = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            return s.contains("found");
        }
    }
    false
}

/// Best-effort: bring existing CrabSock window to foreground on Windows.
#[cfg(target_os = "windows")]
fn focus_existing_main_window() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
    };

    let title = "CrabSock";
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let hwnd: HWND =
            FindWindowW(None, PCWSTR(wide.as_ptr())).unwrap_or(HWND(std::ptr::null_mut()));
        if !hwnd.0.is_null() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

/// Decide whether this Windows process should exit immediately to avoid duplicates.
#[cfg(target_os = "windows")]
pub fn should_exit_early(elevated_relaunch: bool) -> bool {
    if elevated_relaunch {
        return false;
    }

    if other_crabsock_instance_running() {
        log::info!("[MAIN][WIN] Another CrabSock instance is already running; focusing it and exiting this one.");
        focus_existing_main_window();
        return true;
    }

    false
}

/// Non-Windows platforms never need this early-exit duplicate guard.
#[cfg(not(target_os = "windows"))]
pub fn should_exit_early(_elevated_relaunch: bool) -> bool {
    false
}

/// Bring the main window to the foreground (used from tray and single-instance plugin).
pub fn activate_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        #[cfg(target_os = "macos")]
        {
            let _ = win.set_focus();
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = win.set_always_on_top(true);
            let _ = win.set_focus();
            let _ = win.set_always_on_top(false);
        }
        #[cfg(target_os = "linux")]
        {
            // On some WMs focus-stealing prevention may block focus; ask for attention as a hint
            let _ = win.request_user_attention(Some(tauri::UserAttentionType::Informational));
        }
    }
}

/// Build the base Tauri builder, attaching the single-instance plugin when appropriate.
pub fn build_tauri_builder(elevated_relaunch: bool) -> tauri::Builder<tauri::Wry> {
    let base = tauri::Builder::default().plugin(tauri_plugin_updater::Builder::new().build());

    if elevated_relaunch {
        base
    } else {
        base.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // Focus already running instance instead of spawning a new one
            activate_main_window(&app.app_handle());
        }))
    }
}


