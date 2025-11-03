#[cfg(target_os = "windows")]
pub fn configure_ip_windows(alias: &str, ip: std::net::Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let ps = format!(
        r#"
        $alias = '{alias}';
        $idx = $null;
        for ($i=0; $i -lt 40; $i++) {{
          $a = Get-NetAdapter -InterfaceAlias $alias -ErrorAction SilentlyContinue;
          if ($a) {{ $idx = $a.ifIndex; break; }}
          Start-Sleep -Milliseconds 250;
        }}
        if ($idx -eq $null) {{ throw 'adapter not found'; }}
        Set-NetIPInterface -InterfaceIndex $idx -AutomaticMetric Disabled -NlMtuBytes 1400 -InterfaceMetric 5 -ErrorAction SilentlyContinue | Out-Null;
        if (!(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {{
          New-NetIPAddress -IPAddress {ip} -PrefixLength {prefix} -InterfaceIndex $idx -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
        }}
        "#,
        alias = alias,
        ip = ip,
        prefix = prefix
    );
    let output = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-WindowStyle", "Hidden", "-Command", &ps])
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(anyhow::anyhow!(format!(
            "configure_ip_windows failed: status={:?}, stdout={}, stderr={}",
            o.status.code(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ))),
        Err(e) => Err(anyhow::anyhow!(format!("configure_ip_windows spawn error: {}", e))),
    }
}

