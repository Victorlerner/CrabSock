#[cfg(target_os = "windows")]
pub fn clear_split_default_routes(alias: &str) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let ps = format!(
        r#"
        $alias = '{alias}';
        $a = Get-NetAdapter -InterfaceAlias $alias -ErrorAction SilentlyContinue;
        try {{
        if ($a) {{
          $idx = $a.ifIndex;
            $r1 = Get-NetRoute -DestinationPrefix 0.0.0.0/1 -InterfaceIndex $idx -ErrorAction SilentlyContinue;
            if ($r1) {{ $r1 | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}
            $r2 = Get-NetRoute -DestinationPrefix 128.0.0.0/1 -InterfaceIndex $idx -ErrorAction SilentlyContinue;
            if ($r2) {{ $r2 | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}
          }}
        }} catch {{ }} finally {{ exit 0 }}
        "#,
        alias = alias
    );
    let _ = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-WindowStyle", "Hidden", "-Command", &ps])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

