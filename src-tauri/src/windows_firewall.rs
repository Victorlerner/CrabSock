use anyhow::Result;
use std::process::{Command, Stdio};

#[cfg(target_os = "windows")]
fn current_exe() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| String::new())
}

#[cfg(target_os = "windows")]
fn run_elevated_ps_script(script: &str) -> Result<()> {
    // Elevate one PowerShell process and run the combined script (single UAC prompt)
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-Command",
            &format!(
                "Start-Process -FilePath powershell -ArgumentList '-NoProfile -WindowStyle Hidden -Command {}' -Verb RunAs -WindowStyle Hidden",
                script.replace("'", "''")
            ),
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("elevated PowerShell failed"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn ensure_firewall_rules_allow() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static FIREWALL_INIT: AtomicBool = AtomicBool::new(false);

    if FIREWALL_INIT.load(Ordering::Relaxed) {
        return Ok(());
    }

    let exe = current_exe();
    if exe.is_empty() { return Err(anyhow::anyhow!("cannot get current exe path")); }

    // If rules already exist, do nothing (avoid prompting repeatedly)
    if firewall_rules_exist()? {
        FIREWALL_INIT.store(true, Ordering::Relaxed);
        return Ok(());
    }

    // Build a single elevated script that adds both rules in one UAC prompt
    let script = format!(
        "netsh advfirewall firewall add rule name=CrabSock_Out dir=out action=allow program=\"{}\" enable=yes profile=any; netsh advfirewall firewall add rule name=CrabSock_In_1080 dir=in action=allow protocol=TCP localport=1080 program=\"{}\" enable=yes profile=any",
        exe, exe
    );
    let _ = run_elevated_ps_script(&script);
    FIREWALL_INIT.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_firewall_rules_allow() -> Result<()> { Ok(()) }
#[cfg(target_os = "windows")]
fn firewall_rules_exist() -> Result<bool> {
    // Check both rules; if both present, return true
    let has_out = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=CrabSock_Out"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let has_in = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=CrabSock_In_1080"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    Ok(has_out && has_in)
}


