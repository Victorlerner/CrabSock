//! crabsock-root-helper
//!
//! Small setuid-root helper that performs privileged VPN operations:
//! - runs system `openvpn` with given arguments;
//! - runs embedded/system `sing-box` with given config;
//! - stops sing-box processes.
//!
//! Modes:
//! - default / `openvpn`: arguments are passed directly to `openvpn`, require `--config <abs_path>`;
//! - `singbox-run <bin_path> <config_path>`: runs `sing-box run -c <config_path> --disable-color`;
//! - `singbox-kill`: sends SIGTERM (and optionally SIGKILL) to all sing-box processes.
//!
//! Helper is expected to be installed as setuid-root and owned by root.

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const HELPER_VERSION: &str = "1";

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("crabsock-root-helper: expected mode and arguments, e.g.:");
        eprintln!("  crabsock-root-helper --config /abs/path/to.ovpn --verb 2");
        eprintln!("  crabsock-root-helper singbox-run /path/to/sing-box /abs/config.json");
        eprintln!("  crabsock-root-helper singbox-kill");
        return ExitCode::from(1);
    }

    #[cfg(unix)]
    {
        use libc::geteuid;
        unsafe {
            if geteuid() != 0 {
                eprintln!(
                    "crabsock-root-helper: warning: running without root privileges (geteuid != 0)"
                );
            }
        }
    }

    let mode = args.get(0).map(|s| s.as_str()).unwrap_or_default();

    match mode {
        "version" | "--version" | "-V" => {
            // Print helper version to stdout and exit.
            println!("{HELPER_VERSION}");
            ExitCode::SUCCESS
        }
        "singbox-run" => {
            // crabsock-root-helper singbox-run <bin_path> <config_path>
            if args.len() < 3 {
                eprintln!(
                    "crabsock-root-helper: singbox-run requires <bin_path> <config_path>"
                );
                return ExitCode::from(1);
            }
            let bin_path = args[1].clone();
            let cfg_path = args[2].clone();
            let bin = Path::new(&bin_path);
            let cfg = Path::new(&cfg_path);
            if !bin.is_absolute() || !cfg.is_absolute() {
                eprintln!(
                    "crabsock-root-helper: singbox-run requires absolute paths, got: bin={} cfg={}",
                    bin_path, cfg_path
                );
                return ExitCode::from(1);
            }
            if bin_path.contains("..") || cfg_path.contains("..") {
                eprintln!(
                    "crabsock-root-helper: paths must not contain '..': bin={}, cfg={}",
                    bin_path, cfg_path
                );
                return ExitCode::from(1);
            }
            if !bin.exists() {
                eprintln!(
                    "crabsock-root-helper: sing-box binary does not exist: {}",
                    bin_path
                );
                return ExitCode::from(1);
            }
            if !cfg.exists() {
                eprintln!(
                    "crabsock-root-helper: config file does not exist: {}",
                    cfg_path
                );
                return ExitCode::from(1);
            }

            // IMPORTANT: do not execute the sing-box binary directly from app resources.
            // During `tauri build` those resource files may be overwritten; if a process is
            // executing the same file, Linux can fail with `Text file busy (os error 26)`.
            // Fix: copy to a unique temp path and execute from there.
            let bin_meta = match fs::symlink_metadata(bin) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!(
                        "crabsock-root-helper: failed to stat sing-box binary: {}: {}",
                        bin_path, e
                    );
                    return ExitCode::from(1);
                }
            };
            if bin_meta.file_type().is_symlink() {
                eprintln!(
                    "crabsock-root-helper: refusing to execute symlink as sing-box binary: {}",
                    bin_path
                );
                return ExitCode::from(1);
            }

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let tmp_bin_path = format!("/tmp/crabsock-sing-box-{}-{}", std::process::id(), nonce);
            let tmp_bin = Path::new(&tmp_bin_path);

            // Secure-ish copy: create_new to avoid clobbering, then stream bytes.
            let mut src = match fs::File::open(bin) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "crabsock-root-helper: failed to open sing-box binary for copy: {}: {}",
                        bin_path, e
                    );
                    return ExitCode::from(1);
                }
            };
            let mut dst = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp_bin)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "crabsock-root-helper: failed to create temp sing-box binary: {}: {}",
                        tmp_bin_path, e
                    );
                    return ExitCode::from(1);
                }
            };
            if let Err(e) = std::io::copy(&mut src, &mut dst) {
                eprintln!(
                    "crabsock-root-helper: failed to copy sing-box to temp path: {} -> {}: {}",
                    bin_path, tmp_bin_path, e
                );
                let _ = fs::remove_file(tmp_bin);
                return ExitCode::from(1);
            }
            let _ = dst.flush();

            // Make it executable (ignore failure; if it fails, exec will fail and report).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(tmp_bin, fs::Permissions::from_mode(0o755));
            }

            let status = match Command::new(&tmp_bin_path)
                .args(["run", "-c", &cfg_path, "--disable-color"])
                .spawn()
                .and_then(|mut child| child.wait())
            {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("crabsock-root-helper: failed to start sing-box: {}", e);
                    let _ = fs::remove_file(tmp_bin);
                    return ExitCode::from(1);
                }
            };

            // Best-effort cleanup
            let _ = fs::remove_file(tmp_bin);

            if let Some(code) = status.code() {
                ExitCode::from(code as u8)
            } else if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        "singbox-kill" => {
            // crabsock-root-helper singbox-kill
            // Try graceful SIGTERM first, then SIGKILL as fallback.
            let term_status = Command::new("killall")
                .args(["-TERM", "sing-box"])
                .spawn()
                .and_then(|mut c| c.wait());
            if let Err(e) = term_status {
                eprintln!(
                    "crabsock-root-helper: failed to send SIGTERM to sing-box via killall: {}",
                    e
                );
            }

            // Best-effort: short sleep then SIGKILL
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = Command::new("killall")
                .args(["-KILL", "sing-box"])
                .spawn()
                .and_then(|mut c| c.wait());

            ExitCode::SUCCESS
        }
        // Default / legacy mode: treat arguments as direct openvpn args
        _ => {
            // If mode is something like "openvpn", skip it and treat the rest as args
            let openvpn_args: Vec<String> = if mode == "openvpn" {
                args.drain(0..1);
                args
            } else {
                args
            };

            if openvpn_args.is_empty() {
                eprintln!("crabsock-root-helper: expected openvpn arguments, e.g.:");
                eprintln!("  crabsock-root-helper --config /abs/path/to.ovpn --verb 2");
                return ExitCode::from(1);
            }

            // Find --config and validate its value
            let mut config_path: Option<String> = None;
            let mut i = 0;
            while i < openvpn_args.len() {
                if openvpn_args[i] == "--config" {
                    if i + 1 >= openvpn_args.len() {
                        eprintln!(
                            "crabsock-root-helper: --config flag requires a value"
                        );
                        return ExitCode::from(1);
                    }
                    let p = openvpn_args[i + 1].clone();
                    config_path = Some(p);
                    break;
                }
                i += 1;
            }

            let config_path = match config_path {
                Some(p) => p,
                None => {
                    eprintln!("crabsock-root-helper: --config <path> is required");
                    return ExitCode::from(1);
                }
            };

            let cfg = Path::new(&config_path);
            if !cfg.is_absolute() {
                eprintln!(
                    "crabsock-root-helper: config path must be absolute, got: {}",
                    config_path
                );
                return ExitCode::from(1);
            }
            if config_path.contains("..") {
                eprintln!(
                    "crabsock-root-helper: config path must not contain '..': {}",
                    config_path
                );
                return ExitCode::from(1);
            }

            let status = match Command::new("openvpn")
                .args(&openvpn_args)
                .spawn()
                .and_then(|mut child| child.wait())
            {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("crabsock-root-helper: failed to start openvpn: {}", e);
                    return ExitCode::from(1);
                }
            };

            if let Some(code) = status.code() {
                ExitCode::from(code as u8)
            } else if status.success() {
                ExitCode::SUCCESS
            } else {
                // Exited due to signal, no exit code available — map to 1
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crabsock-root-helper is only intended to run on Linux");
    ExitCode::from(1)
}






