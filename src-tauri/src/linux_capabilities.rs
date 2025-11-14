use std::process::Command;

pub fn current_executable_path() -> Option<String> {
    std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string())
}

pub fn has_cap_net_admin() -> bool {
    let Some(path) = current_executable_path() else { return false; };
    match Command::new("getcap").arg(&path).output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.contains("cap_net_admin")
        }
        _ => false,
    }
}

pub fn has_cap_net_admin_on(path: &str) -> bool {
    match Command::new("getcap").arg(path).output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.contains("cap_net_admin")
        }
        _ => false,
    }
}

pub fn set_cap_net_admin_via_pkexec() -> Result<(), String> {
    let Some(path) = current_executable_path() else { return Err("failed to get current exe".into()); };
    let which = Command::new("which").arg("pkexec").output().map_err(|e| e.to_string())?;
    if !which.status.success() { return Err("pkexec not found".into()); }
    let out = Command::new("pkexec").args(["setcap", "cap_net_admin=ep", &path]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}

pub fn set_cap_net_admin_via_sudo() -> Result<(), String> {
    let Some(path) = current_executable_path() else { return Err("failed to get current exe".into()); };
    let out = Command::new("sudo").args(["setcap", "cap_net_admin=ep", &path]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}

pub fn set_cap_net_admin_on_path_via_pkexec(target_path: &str) -> Result<(), String> {
    let which = Command::new("which").arg("pkexec").output().map_err(|e| e.to_string())?;
    if !which.status.success() { return Err("pkexec not found".into()); }
    let out = Command::new("pkexec").args(["setcap", "cap_net_admin=ep", target_path]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}

pub fn set_cap_net_admin_on_path_via_sudo(target_path: &str) -> Result<(), String> {
    let out = Command::new("sudo").args(["setcap", "cap_net_admin=ep", target_path]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}


