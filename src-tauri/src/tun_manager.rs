use anyhow::Result;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use {
    futures_util::TryStreamExt,
    ipnetwork::Ipv4Network,
    rtnetlink::new_connection,
    std::net::IpAddr,
    tun_tap::{Iface, Mode},
};

#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::linux_capabilities::has_cap_net_admin;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "crabsock0".to_string(),
            address: Ipv4Addr::new(172, 19, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 240),
            mtu: 1500,
        }
    }
}

#[cfg(target_os = "linux")]
pub struct TunManager {
    iface: Option<Iface>,
    config: TunConfig,
    is_running: bool,
}

#[cfg(target_os = "linux")]
impl TunManager {
    pub fn new() -> Self {
        Self { iface: None, config: TunConfig::default(), is_running: false }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { log::warn!("[TUN] Already running"); return Ok(()); }
        log::info!("[TUN] Starting TUN interface: {}", self.config.name);
        println!("[STDOUT] TUN: Attempting to create TUN interface: {}", self.config.name);
        if !has_cap_net_admin() {
            println!("[STDOUT] TUN: No permissions to create TUN interface");
            return Err(anyhow::anyhow!("Insufficient permissions to create TUN interface"));
        }
        self.cleanup_existing_interface().await?;
        let iface = Iface::new(&self.config.name, Mode::Tun).map_err(|e| {
            println!("[STDOUT] TUN: Failed to create TUN interface: {}", e);
            anyhow::anyhow!("Failed to create TUN interface: {}", e)
        })?;
        println!("[STDOUT] TUN: TUN interface created successfully");
        self.iface = Some(iface);
        self.configure_tun_interface().await?;
        self.is_running = true;
        log::info!("[TUN] TUN interface started successfully (monitoring mode)");
        println!("[STDOUT] TUN: TUN interface started successfully (monitoring mode)");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { log::warn!("[TUN] Not running"); return Ok(()); }
        log::info!("[TUN] Stopping TUN interface");
        self.clear_routes().await?;
        if let Some(iface) = self.iface.take() { drop(iface); }
        self.is_running = false;
        log::info!("[TUN] TUN interface stopped");
        Ok(())
    }

    async fn cleanup_existing_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        if !has_cap_net_admin() { log::debug!("[TUN] No cap_net_admin, skip cleanup"); return Ok(()); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => {
                    let index = msg.header.index;
                    let _ = handle.link().del(index).execute().await;
                    log::info!("[TUN] Removed existing interface: {}", interface_name);
                }
                _ => break,
            }
        }
        Ok(())
    }

    async fn configure_tun_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        let address = self.config.address;
        log::info!("[TUN] Configuring interface {} with IP {}/{}", interface_name, address, self.get_cidr_prefix());
        if !has_cap_net_admin() { return Err(anyhow::anyhow!("Insufficient permissions to configure TUN (cap_net_admin missing)")); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        let mut maybe_index: Option<u32> = None;
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => { maybe_index = Some(msg.header.index); break; }
                _ => break,
            }
        }
        let index = maybe_index.ok_or_else(|| anyhow::anyhow!("Interface not found after creation"))?;
        handle.link().set(index).up().execute().await?;
        let cidr = Ipv4Network::new(address, self.get_cidr_prefix()).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        handle.address().add(index, IpAddr::V4(cidr.ip()), cidr.prefix()).execute().await?;
        Ok(())
    }

    async fn clear_routes(&self) -> Result<()> {
        let interface_name = &self.config.name;
        log::info!("[TUN] Clearing routes");
        if !has_cap_net_admin() { log::debug!("[TUN] No cap_net_admin, skip clear routes"); return Ok(()); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => {
                    let index = msg.header.index;
                    let _ = handle.link().del(index).execute().await;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn get_cidr_prefix(&self) -> u8 {
        let mask = u32::from(self.config.netmask);
        mask.count_ones() as u8
    }

    pub fn is_running(&self) -> bool { self.is_running }
}

#[cfg(target_os = "windows")]
pub struct TunManager {
    singbox_child: Option<tokio::process::Child>,
    temp_config: Option<PathBuf>,
    config: TunConfig,
    is_running: bool,
}

#[cfg(target_os = "windows")]
impl TunManager {
    pub fn new() -> Self { Self { singbox_child: None, temp_config: None, config: TunConfig::default(), is_running: false } }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Starting sing-box (TUN inbound -> local SOCKS5)");

        // Determine outbound type from environment (default socks)
        let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
        let (socks_host, socks_port) = get_socks_endpoint();
        if outbound_type == "socks" { ensure_socks_ready(&socks_host, socks_port).await?; }

        // Ensure wintun.dll is on PATH (sing-box loads it)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let exe_dir = dir.to_path_buf();
                let arch = std::env::consts::ARCH;
                let win_folder = match arch { "x86_64" => "amd64", "aarch64" => "arm64", "x86" => "x86", "arm" => "arm", _ => "amd64" };
                let candidates = [
                    exe_dir.join("wintun.dll"),
                    exe_dir.join("bin").join("wintun.dll"),
                    exe_dir.join("resources").join("wintun.dll"),
                    exe_dir.join("resources").join("bin").join("wintun.dll"),
                    exe_dir.join("resources").join("wintun").join("bin").join(win_folder).join("wintun.dll"),
                ];
                if let Some(src) = candidates.iter().find(|p| p.exists()).cloned() {
                    let target = exe_dir.join("wintun.dll");
                    if src != target && !target.exists() { let _ = std::fs::copy(&src, &target); }
                }
                use std::ffi::OsString;
                let mut new_path = OsString::new();
                new_path.push(exe_dir.as_os_str());
                if let Some(old) = std::env::var_os("PATH") { new_path.push(";"); new_path.push(old); }
                std::env::set_var("PATH", new_path);
            }
        }

        // Resolve sing-box path
        let singbox_path = find_singbox_path().ok_or_else(|| anyhow::anyhow!("sing-box.exe not found in resources or alongside executable"))?;

        // Build sing-box configuration
        let cfg_path = build_singbox_config(&self.config, socks_host, socks_port)?;
        if std::env::var("LOG_SINGBOX_CONFIG").ok().as_deref() != Some("0") {
            if let Ok(cfg_text) = std::fs::read_to_string(&cfg_path) {
                log::info!("[SING-BOX][CONFIG] {}", cfg_text);
            }
        }
        self.temp_config = Some(cfg_path.clone());

        // Spawn sing-box
        use tokio::process::Command;
        use std::process::Stdio;
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        // TODO: Remove ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS when sing-box 1.12.0 is released
        let mut child = Command::new(&singbox_path)
            .creation_flags(CREATE_NO_WINDOW)
            .args(["run", "-c", cfg_path.to_string_lossy().as_ref(), "--disable-color"]) 
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!(format!("Failed to start sing-box: {}", e)))?;

        // Pipe sing-box logs to our logger
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

        self.singbox_child = Some(child);
        self.is_running = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Stopping sing-box");
        if let Some(mut child) = self.singbox_child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(cfg) = self.temp_config.take() {
            let _ = std::fs::remove_file(cfg);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool { self.is_running }

    fn get_cidr_prefix(&self) -> u8 {
        let mask = u32::from(self.config.netmask);
        mask.count_ones() as u8
    }

    fn configure_routes_windows(&self) -> Result<()> {
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let alias = &self.config.name;
        // Prepare optional exclusion for remote SS server IP(s) (from env SS_REMOTE_HOST, SS_REMOTE_PORT)
        let remote_ip_rule = {
            use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
            let mut lines = String::new();
            if let Ok(host) = std::env::var("SS_REMOTE_HOST") {
                // If it's already an IPv4 literal, add it directly
                if let Ok(IpAddr::V4(v4)) = host.parse::<IpAddr>() {
                    lines.push_str(&format!(
                        "              New-NetRoute -DestinationPrefix {}/32 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;\n",
                        v4
                    ));
                } else {
                    // Resolve all IPv4 A records
                    let port: u16 = std::env::var("SS_REMOTE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
                    if let Ok(iter) = (host.as_str(), port).to_socket_addrs() {
                        let mut seen: std::collections::BTreeSet<Ipv4Addr> = std::collections::BTreeSet::new();
                        for sa in iter {
                            if let IpAddr::V4(v4) = sa.ip() {
                                if seen.insert(v4) {
                                    lines.push_str(&format!(
                                        "              New-NetRoute -DestinationPrefix {}/32 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;\n",
                                        v4
                                    ));
                                }
                                if seen.len() >= 8 { break; }
                            }
                        }
                    }
                }
            }
            lines
        };
        // Wait until adapter appears and fetch InterfaceIndex, then add split routes
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

            # Detect primary interface (default route owner) not equal to TUN
            $mainIndex = $null;
            $def = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric,InterfaceMetric | Select-Object -First 1;
            if ($def -and $def.InterfaceIndex -ne $idx) {{ $mainIndex = $def.InterfaceIndex }}
            if ($mainIndex -eq $null) {{
              $cand = Get-NetAdapter -Physical | Where-Object {{ $_.Status -eq 'Up' -and $_.ifIndex -ne $idx }} | Select-Object -First 1;
              if ($cand) {{ $mainIndex = $cand.ifIndex }}
            }}

            Write-Output ("IDX=" + $idx);
            if ($mainIndex -ne $null) {{ Write-Output ("MAIN=" + $mainIndex); }}

            # Ensure local loopback and private ranges stay off the TUN
            if ($mainIndex -ne $null) {{
              New-NetRoute -DestinationPrefix 127.0.0.0/8 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 10.0.0.0/8 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 172.16.0.0/12 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 192.168.0.0/16 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 169.254.0.0/16 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 224.0.0.0/4 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 255.255.255.255/32 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
{remote_ip_rule}              Write-Output "EXCLUDES_APPLIED=1";
            }}

            # Prefer the TUN by metric and set MTU 1400 for stability
            Set-NetIPInterface -InterfaceIndex $idx -AutomaticMetric Disabled -NlMtuBytes 1400 -InterfaceMetric 5 -ErrorAction SilentlyContinue | Out-Null;
            # On-link split default routes (avoid specifying a gateway for L3 TUN)
            New-NetRoute -DestinationPrefix 0.0.0.0/1 -InterfaceAlias $alias -AddressFamily IPv4 -RouteMetric 5 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
            New-NetRoute -DestinationPrefix 128.0.0.0/1 -InterfaceAlias $alias -AddressFamily IPv4 -RouteMetric 5 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
            # Fallback with legacy route.exe in case New-NetRoute silently fails
            try {{ route.exe add 0.0.0.0 mask 128.0.0.0 0.0.0.0 if $idx metric 5 }} catch {{}}
            try {{ route.exe add 128.0.0.0 mask 128.0.0.0 0.0.0.0 if $idx metric 5 }} catch {{}}
            "#,
            alias=alias,
            remote_ip_rule=remote_ip_rule
        );
        let output = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-WindowStyle", "Hidden", "-Command", &ps])
            .stdin(Stdio::null())
            .output();
        match output {
            Ok(o) => {
                if !o.status.success() {
                    log::error!(
                        "[TUN][WIN] configure_routes_windows failed: status={:?}, stdout={}, stderr={}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    return Err(anyhow::anyhow!("configure_routes_windows failed"));
                }
                let so = String::from_utf8_lossy(&o.stdout);
                if !so.trim().is_empty() { log::info!("[TUN][WIN] routes stdout: {}", so.trim()); }
                Ok(())
            }
            Err(e) => {
                log::error!("[TUN][WIN] configure_routes_windows spawn error: {}", e);
                Err(anyhow::anyhow!("configure_routes_windows spawn error"))
            }
        }
    }

    fn clear_routes_windows(&self) -> Result<()> {
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let alias = &self.config.name;
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
            alias=alias
        );
        let status = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-WindowStyle", "Hidden", "-Command", &ps])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status { Ok(_s) => Ok(()), _ => Ok(()) }
    }

    fn configure_ip_windows(&self) -> Result<()> {
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let alias = &self.config.name;
        let ip = self.config.address;
        let prefix = self.get_cidr_prefix();
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
            # Ensure MTU/metric on TUN early
            Set-NetIPInterface -InterfaceIndex $idx -AutomaticMetric Disabled -NlMtuBytes 1400 -InterfaceMetric 5 -ErrorAction SilentlyContinue | Out-Null;
            if (!(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {{
              New-NetIPAddress -IPAddress {ip} -PrefixLength {prefix} -InterfaceIndex $idx -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
            }}
            "#,
            alias=alias, ip=ip, prefix=prefix
        );
        let output = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-WindowStyle", "Hidden", "-Command", &ps])
            .stdin(Stdio::null())
            .output();
        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => {
                log::error!(
                    "[TUN][WIN] configure_ip_windows failed: status={:?}, stdout={}, stderr={}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                Err(anyhow::anyhow!("ip assign failed"))
            }
            Err(e) => {
                log::error!("[TUN][WIN] configure_ip_windows spawn error: {}", e);
                Err(anyhow::anyhow!("ip assign spawn failed"))
            }
        }
    }

    fn spawn_native_tun2socks_loop(&mut self) { /* replaced by start() bridge tasks */ }
}

#[cfg(target_os = "windows")]
async fn handle_tcp_stream_via_socks(
    lwip_stream: std::pin::Pin<Box<netstack_lwip::TcpStream>>,
    remote: std::net::SocketAddr,
    socks_host: String,
    socks_port: u16,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Only IPv4 for now
    if !remote.ip().is_ipv4() { return; }

    match TcpStream::connect((socks_host.as_str(), socks_port)).await {
        Ok(mut socks) => {
            let _ = socks.set_nodelay(true);
            // SOCKS5 greeting: no auth
            if socks.write_all(&[0x05, 0x01, 0x00]).await.is_err() { return; }
            let mut resp = [0u8; 2];
            if socks.read_exact(&mut resp).await.is_err() || resp != [0x05, 0x00] { return; }

            // CONNECT request
            let ip = match remote.ip() { std::net::IpAddr::V4(v4) => v4.octets(), _ => return };
            let port = remote.port();
            let req = [
                &[0x05, 0x01, 0x00, 0x01][..], // ver, cmd=connect, rsv, atyp=ipv4
                &ip,
                &port.to_be_bytes(),
            ].concat();
            if socks.write_all(&req).await.is_err() { return; }
            // reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            let mut head = [0u8; 4];
            if socks.read_exact(&mut head).await.is_err() || head[1] != 0x00 { return; }
            let addr_len = match head[3] { 0x01 => 4, 0x03 => { let mut l=[0u8;1]; if socks.read_exact(&mut l).await.is_err(){return;} l[0] as usize }, 0x04 => 16, _ => 0 };
            if addr_len == 0 { return; }
            let mut skip = vec![0u8; addr_len + 2];
            if socks.read_exact(&mut skip).await.is_err() { return; }

            // Pump both directions using a pin-safe adapter for lwip stream
            let mut lhs = PinnedLwipStream { inner: lwip_stream };
            let mut rhs = socks;
            let _ = tokio::io::copy_bidirectional(&mut lhs, &mut rhs).await;
            let _ = rhs.shutdown().await;
        }
        Err(_) => { /* cannot reach local socks */ }
    }
}

#[cfg(target_os = "windows")]
async fn ensure_socks_ready(host: &str, port: u16) -> anyhow::Result<()> {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    let addr = (host, port);
    for _ in 0..20 {
        if let Ok(Ok(_)) = timeout(Duration::from_millis(250), TcpStream::connect(addr)).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    Err(anyhow::anyhow!(format!("Local SOCKS endpoint {}:{} not reachable", host, port)))
}

#[cfg(target_os = "windows")]
struct PinnedLwipStream {
    inner: std::pin::Pin<Box<netstack_lwip::TcpStream>>,
}

#[cfg(target_os = "windows")]
impl tokio::io::AsyncRead for PinnedLwipStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(self.as_mut().inner.as_mut(), cx, buf)
    }
}

#[cfg(target_os = "windows")]
impl tokio::io::AsyncWrite for PinnedLwipStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self.as_mut().inner.as_mut(), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(self.as_mut().inner.as_mut(), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(self.as_mut().inner.as_mut(), cx)
    }
}

#[cfg(target_os = "windows")]
fn get_socks_endpoint() -> (String, u16) {
    // Prefer env SOCKS_PROXY like socks5h://127.0.0.1:1080
    if let Ok(proxy) = std::env::var("SOCKS_PROXY") {
        let p = proxy.trim();
        let without_scheme = p.strip_prefix("socks5h://").or_else(|| p.strip_prefix("socks5://")).unwrap_or(p);
        // strip auth if any
        let hostport = without_scheme.split('@').last().unwrap_or(without_scheme);
        // strip path
        let hostport = hostport.split('/').next().unwrap_or(hostport);
        let mut parts = hostport.rsplitn(2, ':');
        if let (Some(port_s), Some(host)) = (parts.next(), parts.next()) {
            if let Ok(port) = port_s.parse::<u16>() { return (host.to_string(), port); }
        }
        if !hostport.is_empty() { return (hostport.to_string(), 1080); }
    }
    ("127.0.0.1".to_string(), 1080)
}

#[cfg(target_os = "windows")]
fn find_singbox_path() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let exe_dir = dir.to_path_buf();
            let mut candidates = vec![
                exe_dir.join("sing-box.exe"),
                exe_dir.join("bin").join("sing-box.exe"),
                exe_dir.join("resources").join("sing-box.exe"),
                exe_dir.join("resources").join("sing-box").join("sing-box.exe"),
            ];
            // Dev-path: target/<profile>/ -> crate_dir/resources/sing-box/sing-box.exe
            if let Some(target_dir) = exe_dir.parent() { // .../target
                if let Some(crate_dir) = target_dir.parent() { // .../src-tauri
                    candidates.push(crate_dir.join("resources").join("sing-box").join("sing-box.exe"));
                }
            }
            for c in candidates { if c.exists() { return Some(c); } }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn build_singbox_config(cfg: &TunConfig, socks_host: String, socks_port: u16) -> Result<PathBuf> {
    use serde_json::json;
    // Collect remote server IP exclusions from SS_REMOTE_HOST
    let mut direct_cidrs: Vec<String> = vec![
        "127.0.0.0/8".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "169.254.0.0/16".to_string(),
        "224.0.0.0/4".to_string(),
        "255.255.255.255/32".to_string(),
    ];
    if let Ok(host) = std::env::var("SS_REMOTE_HOST") {
        use std::net::{IpAddr, ToSocketAddrs};
        let port: u16 = std::env::var("SS_REMOTE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let IpAddr::V4(v4) = ip { direct_cidrs.push(format!("{}/32", v4)); }
        } else if let Ok(iter) = (host.as_str(), port).to_socket_addrs() {
            use std::collections::BTreeSet;
            let mut seen = BTreeSet::new();
            for sa in iter {
                if let IpAddr::V4(v4) = sa.ip() {
                    if seen.insert(v4) { direct_cidrs.push(format!("{}/32", v4)); }
                    if seen.len() >= 8 { break; }
                }
            }
        }
    }

    let inet4 = format!("{}/{}", cfg.address, {
        let mask = u32::from(cfg.netmask);
        mask.count_ones() as u8
    });

    // Outbounds depend on SB_OUTBOUND_TYPE
    let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
    // Build outbounds and DNS config
    let outbounds = if outbound_type == "vless" {
        let server = std::env::var("SB_VLESS_SERVER").unwrap_or_else(|_| "".into());
        let port: u16 = std::env::var("SB_VLESS_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
        let uuid = std::env::var("SB_VLESS_UUID").unwrap_or_else(|_| "".into());
        let security = std::env::var("SB_VLESS_SECURITY").unwrap_or_else(|_| "reality".into());
        let sni = std::env::var("SB_VLESS_SNI").unwrap_or_else(|_| "".into());
        let fp = std::env::var("SB_VLESS_FP").unwrap_or_else(|_| "chrome".into());
        let flow = std::env::var("SB_VLESS_FLOW").unwrap_or_else(|_| "".into());
        let pbk = std::env::var("SB_VLESS_PBK").unwrap_or_else(|_| "".into());
        let sid = std::env::var("SB_VLESS_SID").unwrap_or_else(|_| "".into());

        json!([
            {
                "type": "vless",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "flow": flow,
                "packet_encoding": "",
                "domain_resolver": "dns-direct",
                "tls": {
                    "enabled": true,
                    "server_name": sni,
                    "utls": { "enabled": true, "fingerprint": fp },
                    "reality": {
                        "enabled": security == "reality",
                        "public_key": pbk,
                        "short_id": sid
                    }
                }
            },
            { "type": "direct", "tag": "direct" }
        ])
    } else {
        json!([
            {
                "type": "socks",
                "tag": "proxy",
                "server": socks_host,
                "server_port": socks_port,
                "version": "5",
                "udp_over_tcp": true
            },
            { "type": "direct", "tag": "direct" }
        ])
    };

    // Build DNS config to avoid bootstrap/ERR_NAME_NOT_RESOLVED
    let mut dns_rules: Vec<serde_json::Value> = Vec::new();
    if let Ok(host) = std::env::var("SB_VLESS_SERVER") {
        // Only add rule if looks like a domain (not IPv4)
        if host.chars().any(|c| c.is_alphabetic()) {
            dns_rules.push(json!({ "domain": [host], "server": "dns-direct" }));
        }
    }
    dns_rules.push(json!({ "query_type": [32, 33], "server": "dns-block" }));
    dns_rules.push(json!({ "domain_suffix": [".lan"], "server": "dns-block" }));
 // Повыше: поставь "level": "debug" или "trace".
// Потише: "warn" или "error".
    // Build inbounds: TUN always; optional mixed inbound gated by env to avoid bind conflicts
    let mut inbounds: Vec<serde_json::Value> = vec![json!({
        "type": "tun",
        "interface_name": cfg.name,
        "address": [ inet4 ],
        "mtu": 1400,
        "auto_route": true,
        "strict_route": true,
        "endpoint_independent_nat": true,
        "sniff": true,
        "sniff_override_destination": false,
        "stack": "gvisor"
    })];
    if std::env::var("SINGBOX_ENABLE_MIXED").ok().as_deref() == Some("1") {
        let mixed_port: u16 = std::env::var("SINGBOX_MIXED_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(1081);
        inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
            "sniff": true,
            "sniff_override_destination": false
        }));
    }

    let doc = json!({
        "log": { "level": "warn" },
        "inbounds": inbounds,
        "dns": {
            "independent_cache": true,
            "rules": dns_rules,
            "servers": [
                { "address": "https://doh.pub/dns-query",    "address_resolver": "dns-local", "detour": "direct", "tag": "dns-direct" },
                { "address": "rcode://success",               "tag": "dns-block" },
                { "address": "local",                         "detour": "direct", "tag": "dns-local" }
            ]
        },
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-direct",
            "final": "proxy",
            "rules": [
                { "protocol": "dns", "action": "hijack-dns" },
                { "ip_cidr": direct_cidrs, "action": "direct" },
                { "network": "udp", "port": [135,137,138,139,5353], "action": "reject" },
                { "ip_cidr": ["224.0.0.0/3","ff00::/8"], "action": "reject" },
                { "source_ip_cidr": ["224.0.0.0/3","ff00::/8"], "action": "reject" }
            ]
        }
    });

    let temp = std::env::temp_dir().join(format!("crabsock-singbox-{}.json", std::process::id()));
    std::fs::write(&temp, doc.to_string())
        .map_err(|e| anyhow::anyhow!(format!("write sing-box config failed: {}", e)))?;
    Ok(temp)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub struct TunManager { is_running: bool }

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl TunManager {
    pub fn new() -> Self { Self { is_running: false } }
    pub async fn start(&mut self) -> Result<()> { self.is_running = true; Ok(()) }
    pub async fn stop(&mut self) -> Result<()> { self.is_running = false; Ok(()) }
    pub fn is_running(&self) -> bool { self.is_running }
}