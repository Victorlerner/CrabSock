//! crabsock-openvpn-helper
//!
//! Small setuid-root helper that launches the system `openvpn`
//! with the provided arguments. Requirements:
//! - first argument after program name must contain flags for openvpn;
//! - `--config <path>` must be present;
//! - `path` must be absolute and must not contain `..`.
//!
//! The helper:
//! - validates the config path;
//! - runs `openvpn` with the same arguments;
//! - waits for completion and returns the same exit code.

use std::env;
use std::path::Path;
use std::process::{Command, ExitCode};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("crabsock-openvpn-helper: expected openvpn arguments, e.g.:");
        eprintln!("  crabsock-openvpn-helper --config /abs/path/to.ovpn --verb 2");
        return ExitCode::from(1);
    }

    // Find --config and validate its value
    let mut config_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" {
            if i + 1 >= args.len() {
                eprintln!("crabsock-openvpn-helper: --config flag requires a value");
                return ExitCode::from(1);
            }
            let p = args[i + 1].clone();
            config_path = Some(p);
            break;
        }
        i += 1;
    }

    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("crabsock-openvpn-helper: --config <path> is required");
            return ExitCode::from(1);
        }
    };

    let cfg = Path::new(&config_path);
    if !cfg.is_absolute() {
        eprintln!(
            "crabsock-openvpn-helper: config path must be absolute, got: {}",
            config_path
        );
        return ExitCode::from(1);
    }
    if config_path.contains("..") {
        eprintln!(
            "crabsock-openvpn-helper: config path must not contain '..': {}",
            config_path
        );
        return ExitCode::from(1);
    }

    // In production this binary is expected to be setuid root and owned by root.
    // Here we only do a sanity check: if not root, print a warning (but still try).
    #[cfg(unix)]
    {
        use libc::geteuid;
        unsafe {
            if geteuid() != 0 {
                eprintln!(
                    "crabsock-openvpn-helper: warning: running without root privileges (geteuid != 0)"
                );
            }
        }
    }

    let status = match Command::new("openvpn")
        .args(&args)
        .spawn()
        .and_then(|mut child| child.wait())
    {
        Ok(status) => status,
        Err(e) => {
            eprintln!("crabsock-openvpn-helper: failed to start openvpn: {}", e);
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

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crabsock-openvpn-helper is only intended to run on Linux");
    ExitCode::from(1)
}


