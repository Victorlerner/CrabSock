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
use futures_util::{SinkExt, StreamExt};

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
    dev: Option<tun::AsyncDevice>,
    bridge_tasks: Vec<tokio::task::JoinHandle<()>>,
    config: TunConfig,
    is_running: bool,
}

#[cfg(target_os = "windows")]
impl TunManager {
    pub fn new() -> Self { Self { dev: None, bridge_tasks: Vec::new(), config: TunConfig::default(), is_running: false } }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Starting Wintun + tun2socks (TCP via SOCKS5)");

        // Ensure signed wintun.dll is discoverable by the loader
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let exe_dir = dir.to_path_buf();
                let arch = std::env::consts::ARCH;
                let win_folder = match arch {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    "x86" => "x86",
                    "arm" => "arm",
                    _ => "amd64",
                };
                let candidates = [
                    exe_dir.join("wintun.dll"),
                    exe_dir.join("bin").join("wintun.dll"),
                    exe_dir.join("resources").join("wintun.dll"),
                    exe_dir.join("resources").join("bin").join("wintun.dll"),
                    exe_dir.join("resources").join("wintun").join("bin").join(win_folder).join("wintun.dll"),
                ];
                let present = candidates.iter().find(|p| p.exists()).cloned();
                if let Some(src) = present {
                    let target = exe_dir.join("wintun.dll");
                    if src != target && !target.exists() {
                        let _ = std::fs::copy(&src, &target);
                    }
                }
                // Prepend exe dir to PATH so LoadLibrary can resolve wintun.dll
                use std::ffi::OsString;
                let mut new_path = OsString::new();
                new_path.push(exe_dir.as_os_str());
                if let Some(old) = std::env::var_os("PATH") { new_path.push(";"); new_path.push(old); }
                std::env::set_var("PATH", new_path);
            }
        }

        // Create (or open) a Wintun device
        // Force MTU to 1400 to avoid fragmentation issues on common paths
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(&self.config.name).mtu(1400).up();
        let dev = tun::create_as_async(&cfg)
            .map_err(|e| anyhow::anyhow!("Failed to create Wintun: {}", e))?;

        // Configure IP and split routes through PowerShell (fail fast on errors)
        self.configure_ip_windows()?;
        self.clear_routes_windows()?;
        self.configure_routes_windows()?;

        // Build a lwIP netstack and bridge it to the TUN device
        // Use larger buffers to reduce backpressure and drops under load
        let (stack, mut tcp_listener, udp_socket) = netstack_lwip::NetStack::with_buffer_size(65536, 8192)?;

        let framed = dev.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        // Stack -> TUN
        self.bridge_tasks.push(tokio::spawn(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => { if let Err(e) = tun_sink.send(pkt).await { log::error!("[TUN][WIN] send to TUN failed: {}", e); break; } }
                    Err(e) => { log::error!("[TUN][WIN] netstack stream error: {}", e); break; }
                }
            }
        }));

        // TUN -> Stack
        self.bridge_tasks.push(tokio::spawn(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => { if let Err(e) = stack_sink.send(pkt).await { log::error!("[TUN][WIN] send to stack failed: {}", e); break; } }
                    Err(e) => { log::error!("[TUN][WIN] TUN read error: {}", e); break; }
                }
            }
        }));

        // TCP sockets from netstack -> local SOCKS5 (queue instead of dropping when saturated)
        let max_concurrency: usize = std::env::var("TUN_TCP_CONCURRENCY").ok().and_then(|s| s.parse().ok()).unwrap_or(16384);
        let tcp_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency));
        let (socks_host, socks_port) = get_socks_endpoint();
        log::info!("[TUN][WIN] Using SOCKS endpoint {}:{}", socks_host, socks_port);
        // Ensure local SOCKS (Shadowsocks) is up before proceeding
        ensure_socks_ready(&socks_host, socks_port).await?;
        self.bridge_tasks.push(tokio::spawn({
            let tcp_sem = tcp_sem.clone();
            let socks_host = socks_host.clone();
            async move {
                while let Some((stream, _local, remote)) = tcp_listener.next().await {
                    let sem = tcp_sem.clone();
                    let host = socks_host.clone();
                    // Drop connection immediately if saturated to avoid lwIP backlog ("tcp full")
                    if let Ok(permit) = sem.try_acquire_owned() {
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_tcp_stream_via_socks(stream, remote, host, socks_port).await;
                        });
                    } else {
                        log::warn!("[TUN][WIN] dropping TCP stream due to saturation: {}", remote);
                        // stream dropped here
                    }
                }
            }
        }));

        // UDP handling: implement DNS via TCP-over-SOCKS; drop others (QUIC will fallback to TCP)
        self.bridge_tasks.push(tokio::spawn(async move {
            let (ls, mut lr) = udp_socket.split();
            let ls = std::sync::Arc::new(ls);
            let socks_host = socks_host.clone();
            let socks_port = socks_port;
            loop {
                match lr.recv_from().await {
                    Ok((data, src_addr, dst_addr)) => {
                        if dst_addr.port() == 53 {
                            let ls_cloned = ls.clone();
                            let host = socks_host.clone();
                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                use tokio::net::TcpStream;
                                // Connect SOCKS
                                if let Ok(mut socks) = TcpStream::connect((host.as_str(), socks_port)).await {
                                    if socks.write_all(&[0x05, 0x01, 0x00]).await.is_ok() {
                                        let mut resp = [0u8;2];
                                        if socks.read_exact(&mut resp).await.is_ok() && resp == [0x05, 0x00] {
                                            // CONNECT to original dns server via TCP
                                            if let std::net::IpAddr::V4(v4) = dst_addr.ip() {
                                                let mut req = Vec::with_capacity(4+4+2);
                                                req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
                                                req.extend_from_slice(&v4.octets());
                                                req.extend_from_slice(&dst_addr.port().to_be_bytes());
                                                if socks.write_all(&req).await.is_ok() {
                                                    let mut head = [0u8;4];
                                                    if socks.read_exact(&mut head).await.is_ok() && head[1]==0x00 {
                                                        let addr_len = match head[3] { 0x01 => 4, 0x03 => { let mut l=[0u8;1]; if socks.read_exact(&mut l).await.is_err(){return;} l[0] as usize }, 0x04 => 16, _ => 0 };
                                                        if addr_len != 0 {
                                                            let mut skip = vec![0u8; addr_len + 2];
                                                            if socks.read_exact(&mut skip).await.is_ok() {
                                                                // DNS over TCP
                                                                let len = (data.len() as u16).to_be_bytes();
                                                                if socks.write_all(&len).await.is_ok() && socks.write_all(&data).await.is_ok() {
                                                                    let mut lbuf=[0u8;2];
                                                                    if socks.read_exact(&mut lbuf).await.is_ok() {
                                                                        let rlen = u16::from_be_bytes(lbuf) as usize;
                                                                        let mut rbuf = vec![0u8; rlen];
                                                                        if socks.read_exact(&mut rbuf).await.is_ok() {
                                                                            let _ = ls_cloned.send_to(&rbuf, &dst_addr, &src_addr);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        } else {
                            let host = socks_host.clone();
                            tokio::spawn(async move {
                                use tokio::net::TcpStream;
                                // Optional UDP via SOCKS5 (disabled by default)
                                if std::env::var("TUN_ENABLE_UDP").ok().as_deref() == Some("1") {
                                    // (Feature gated) UDP path not implemented by default
                                    let _ = TcpStream::connect((host.as_str(), socks_port)).await;
                                }
                            });
                        }
                    }
                    Err(e) => { log::warn!("[TUN][WIN] UDP recv error: {}", e); break; }
                }
            }
        }));

        // Keep running
        self.dev = None;
        self.is_running = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { return Ok(()); }
        log::info!("[TUN][WIN] Stopping Wintun + tun2socks");
        if let Err(e) = self.clear_routes_windows() { log::warn!("[TUN][WIN] clear routes failed: {}", e); }
        for h in self.bridge_tasks.drain(..) { h.abort(); }
        self.dev.take();
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
        // Prepare optional exclusion for remote SS server IP (from env SS_REMOTE_HOST)
        let remote_ip_rule = {
            use std::net::ToSocketAddrs;
            if let Ok(host) = std::env::var("SS_REMOTE_HOST") {
                if let Ok(mut it) = (host.as_str(), 0u16).to_socket_addrs() {
                    if let Some(sa) = it.find(|sa| sa.is_ipv4()) {
                        if let std::net::IpAddr::V4(v4) = sa.ip() {
                            format!("              New-NetRoute -DestinationPrefix {}/32 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;\n", v4)
                        } else { String::new() }
                    } else { String::new() }
                } else { String::new() }
            } else { String::new() }
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

            # Ensure local loopback and private ranges stay off the TUN
            if ($mainIndex -ne $null) {{
              New-NetRoute -DestinationPrefix 127.0.0.0/8 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 10.0.0.0/8 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 172.16.0.0/12 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 192.168.0.0/16 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 169.254.0.0/16 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 224.0.0.0/4 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
              New-NetRoute -DestinationPrefix 255.255.255.255/32 -InterfaceIndex $mainIndex -RouteMetric 1 -NextHop 0.0.0.0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;
{remote_ip_rule}            }}

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

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub struct TunManager { is_running: bool }

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl TunManager {
    pub fn new() -> Self { Self { is_running: false } }
    pub async fn start(&mut self) -> Result<()> { self.is_running = true; Ok(()) }
    pub async fn stop(&mut self) -> Result<()> { self.is_running = false; Ok(()) }
    pub fn is_running(&self) -> bool { self.is_running }
}