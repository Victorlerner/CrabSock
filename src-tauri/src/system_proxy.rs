use anyhow::Result;
use std::process::Command;
use std::process::Stdio;

#[cfg(target_os = "windows")]
use winreg::{enums::HKEY_CURRENT_USER, RegKey};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinInet::{InternetSetOptionW, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH};

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub socks_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl ProxySettings {
    pub fn new() -> Self {
        Self {
            http_proxy: None,
            https_proxy: None,
            socks_proxy: None,
            no_proxy: None,
        }
    }

    pub fn with_socks5(host: &str, port: u16) -> Self {
        let proxy_url = format!("socks5://{}:{}", host, port);
        Self {
            http_proxy: Some(proxy_url.clone()),
            https_proxy: Some(proxy_url.clone()),
            socks_proxy: Some(proxy_url),
            // By default bypass localhost,  and private IP ranges
            // This mirrors Outline behavior where private networks are excluded from the tunnel
            no_proxy: Some([
                // loopback / local
                "localhost",
                "127.0.0.1",
                "::1",
                "<local>",
                // link-local (CIDR + wildcard)
                "169.254.0.0/16",
                "169.254.*",
                // RFC1918 (CIDR + wildcard approximations)
                "10.0.0.0/8",
                "10.*",
                "172.16.0.0/12",
                "172.16.*","172.17.*","172.18.*","172.19.*","172.20.*","172.21.*","172.22.*",
                "172.23.*","172.24.*","172.25.*","172.26.*","172.27.*","172.28.*","172.29.*",
                "172.30.*","172.31.*",
                "192.168.0.0/16",
                "192.168.*",
                // Carrier-grade NAT (approximate /10)
                "100.64.0.0/10",
                "100.*",
                // Special-use / documentation / testing subnets (CIDR + wildcard)
                "192.0.0.0/24",   "192.0.0.*",
                "192.0.2.0/24",   "192.0.2.*",
                "192.31.196.0/24", "192.31.196.*",
                "192.52.193.0/24", "192.52.193.*",
                "192.88.99.0/24",  "192.88.99.*",
                "192.175.48.0/24", "192.175.48.*",
                "198.18.0.0/15",   "198.18.*", "198.19.*",
                "198.51.100.0/24", "198.51.100.*",
                "203.0.113.0/24",  "203.0.113.*",
                // Class E (reserved) 240.0.0.0/4 (approximate with 16 wildcards)
                "240.0.0.0/4",
                "240.*","241.*","242.*","243.*","244.*","245.*","246.*","247.*",
                "248.*","249.*","250.*","251.*","252.*","253.*","254.*","255.*",
            ].join(",")),
        }
    }
}

pub struct SystemProxyManager {
    original_settings: Option<ProxySettings>,
    tun_mode: bool,
}

impl SystemProxyManager {
    pub fn new() -> Self {
        Self {
            original_settings: None,
            tun_mode: false,
        }
    }

    pub async fn set_system_proxy(&mut self, settings: &ProxySettings) -> Result<()> {
        log::info!("[SYSTEM_PROXY] Setting system proxy: {:?}", settings);

        // Сохраняем текущие настройки прокси
        if self.original_settings.is_none() {
            self.original_settings = Some(self.get_current_proxy_settings().await?);
        }

        // Устанавливаем новые настройки прокси
        self.set_proxy_settings(settings).await?;

        log::info!("[SYSTEM_PROXY] System proxy set successfully");
        Ok(())
    }

    pub async fn clear_system_proxy(&mut self) -> Result<()> {
        log::info!("[SYSTEM_PROXY] Clearing system proxy");

        // Восстанавливаем оригинальные настройки
        if let Some(ref original) = self.original_settings {
            self.set_proxy_settings(original).await?;
        } else {
            // Если оригинальных настроек нет, просто очищаем прокси
            let empty_settings = ProxySettings::new();
            self.set_proxy_settings(&empty_settings).await?;
        }

        self.original_settings = None;
        log::info!("[SYSTEM_PROXY] System proxy cleared successfully");
        Ok(())
    }

    async fn get_current_proxy_settings(&self) -> Result<ProxySettings> {
        let mut settings = ProxySettings::new();

        // Получаем текущие настройки прокси из переменных окружения
        if let Ok(http_proxy) = std::env::var("http_proxy") {
            settings.http_proxy = Some(http_proxy);
        }
        if let Ok(https_proxy) = std::env::var("https_proxy") {
            settings.https_proxy = Some(https_proxy);
        }
        if let Ok(socks_proxy) = std::env::var("socks_proxy") {
            settings.socks_proxy = Some(socks_proxy);
        }
        if let Ok(no_proxy) = std::env::var("no_proxy") {
            settings.no_proxy = Some(no_proxy);
        }

        Ok(settings)
    }

    async fn set_proxy_settings(&self, settings: &ProxySettings) -> Result<()> {
        // Устанавливаем переменные окружения для текущего процесса
        if let Some(ref http_proxy) = settings.http_proxy {
            std::env::set_var("http_proxy", http_proxy);
            std::env::set_var("HTTP_PROXY", http_proxy);
        } else {
            std::env::remove_var("http_proxy");
            std::env::remove_var("HTTP_PROXY");
        }

        if let Some(ref https_proxy) = settings.https_proxy {
            std::env::set_var("https_proxy", https_proxy);
            std::env::set_var("HTTPS_PROXY", https_proxy);
        } else {
            std::env::remove_var("https_proxy");
            std::env::remove_var("HTTPS_PROXY");
        }

        if let Some(ref socks_proxy) = settings.socks_proxy {
            std::env::set_var("socks_proxy", socks_proxy);
            std::env::set_var("SOCKS_PROXY", socks_proxy);
        } else {
            std::env::remove_var("socks_proxy");
            std::env::remove_var("SOCKS_PROXY");
        }

        if let Some(ref no_proxy) = settings.no_proxy {
            std::env::set_var("no_proxy", no_proxy);
            std::env::set_var("NO_PROXY", no_proxy);
        } else {
            std::env::remove_var("no_proxy");
            std::env::remove_var("NO_PROXY");
        }

        // Apply system proxy per-OS
        #[cfg(target_os = "linux")]
        {
            self.set_linux_system_proxy(settings).await?;
        }
        #[cfg(target_os = "windows")]
        {
            self.set_windows_system_proxy(settings).await?;
        }
        #[cfg(target_os = "macos")]
        {
            self.set_macos_system_proxy(settings).await?;
        }

        Ok(())
    }

    async fn set_linux_system_proxy(&self, settings: &ProxySettings) -> Result<()> {
        let de = detect_desktop_env();
        match de {
            DesktopEnv::Gnome if which("gsettings") => set_proxy_gnome(settings)?,
            DesktopEnv::Kde if which("kwriteconfig5") => set_proxy_kde(settings)?,
            _ => {
                // Пытаемся gsettings → KDE → иначе ничего (env уже выставлены)
                if which("gsettings") {
                    set_proxy_gnome(settings)?;
                } else if which("kwriteconfig5") {
                    set_proxy_kde(settings)?;
                } else {
                    log::warn!("[SYSTEM_PROXY] No known system proxy backend found (gsettings/kwriteconfig5). Using env only.");
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn set_windows_system_proxy(&self, settings: &ProxySettings) -> Result<()> {
        // Windows: prefer driving traffic through local ACL HTTP proxy (127.0.0.1:8080)
        // and install a PAC file to DIRECT-bypass private ranges and VPN (Pritunl/WireGuard/TAP) routes.
        // Keys under: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        //  - ProxyEnable (DWORD)
        //  - ProxyServer (STRING) e.g. "http=127.0.0.1:8080;https=127.0.0.1:8080"
        //  - ProxyOverride (STRING) semicolon-separated patterns
        //  - AutoConfigURL (STRING) to point at PAC file

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        let (key, _) = hkcu.create_subkey(path)?;

        if settings.http_proxy.is_some() || settings.socks_proxy.is_some() {
            // Always drive via local ACL HTTP proxy on Windows
            let proxy_str = "http=127.0.0.1:8080;https=127.0.0.1:8080";
            key.set_value("ProxyEnable", &1u32)?;
            key.set_value("ProxyServer", &proxy_str)?;

            // Build ProxyOverride from provided no_proxy plus known patterns and optional ACL_BYPASS_HOSTS
            let mut overrides: Vec<String> = settings
                .no_proxy
                .clone()
                .unwrap_or_else(|| "localhost,127.0.0.1,<local>".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            // Ensure <local> present
            if !overrides.iter().any(|s| s == "<local>") { overrides.push("<local>".to_string()); }
            // Pritunl-related domains
            overrides.push("*.pritunl.*".to_string());
            // User-provided extra bypass via env ACL_BYPASS_HOSTS -> wildcard
            if let Ok(extra) = std::env::var("ACL_BYPASS_HOSTS") {
                for p in extra.split(',') {
                    let p = p.trim(); if p.is_empty() { continue; }
                    // wrap with wildcards if domain-like
                    if p.contains('.') && !p.contains('*') { overrides.push(format!("*.{}", p.trim_start_matches("*.").trim_end_matches("."))); }
                    else { overrides.push(p.to_string()); }
                }
            }
            let override_val = overrides.join(";");
            key.set_value("ProxyOverride", &override_val)?;

            // Install PAC to dynamically DIRECT-bypass VPN routes
            if let Some(pac_path) = Self::write_windows_pac("127.0.0.1", 8080) {
                key.set_value("AutoConfigURL", &format!("file://{}", pac_path))?;
            }
        } else {
            // disable proxy
            key.set_value("ProxyEnable", &0u32)?;
            let _ = key.delete_value("ProxyServer");
            let _ = key.delete_value("ProxyOverride");
            let _ = key.delete_value("AutoConfigURL");
        }

        // Notify system
        unsafe {
            let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
            let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn write_windows_pac(http_host: &str, http_port: u16) -> Option<String> {
        use std::fs;
        use std::io::Write;
        use std::path::PathBuf;
        use std::process::Command;

        let mut dir = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        dir.push("CrabSock");
        let _ = fs::create_dir_all(&dir);
        let mut pac_path = PathBuf::from(&dir);
        pac_path.push("proxy.pac");

        // Collect IPv4 destination prefixes routed via VPN-like interfaces
        let mut dynamic_routes: Vec<(String, String)> = Vec::new();
        let ps = r#"
            try {
              $routes = Get-NetRoute -AddressFamily IPv4 | Sort-Object -Property RouteMetric
              foreach ($r in $routes) {
                $alias = (Get-NetIPInterface -ifIndex $r.ifIndex -AddressFamily IPv4).InterfaceAlias
                if ($alias -match 'pritunl|wireguard|wintun|tap|openvpn') {
                  $dest = $r.DestinationPrefix # e.g. 10.0.0.0/24
                  Write-Output $dest
                }
              }
            } catch {}
        "#;
        if let Ok(out) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let s = line.trim(); if s.is_empty() { continue; }
                    if let Some((addr, prefix_str)) = s.split_once('/') {
                        if let Ok(prefix) = prefix_str.parse::<u8>() {
                            let mask_u32: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix as u32) };
                            let mask = format!("{}.{}.{}.{}",
                                (mask_u32 >> 24) & 0xff,
                                (mask_u32 >> 16) & 0xff,
                                (mask_u32 >> 8) & 0xff,
                                mask_u32 & 0xff);
                            dynamic_routes.push((addr.to_string(), mask));
                        }
                    }
                }
            }
        }

        let mut pac = format!(r#"function FindProxyForURL(url, host) {{
  if (isPlainHostName(host) ||
      isInNet(host, '10.0.0.0', '255.0.0.0') ||
      isInNet(host, '100.64.0.0', '255.192.0.0') ||
      isInNet(host, '169.254.0.0', '255.255.0.0') ||
      isInNet(host, '172.16.0.0', '255.240.0.0') ||
      isInNet(host, '192.0.0.0', '255.255.255.0') ||
      isInNet(host, '192.0.2.0', '255.255.255.0') ||
      isInNet(host, '192.31.196.0', '255.255.255.0') ||
      isInNet(host, '192.52.193.0', '255.255.255.0') ||
      isInNet(host, '192.88.99.0', '255.255.255.0') ||
      isInNet(host, '192.168.0.0', '255.255.0.0') ||
      isInNet(host, '192.175.48.0', '255.255.255.0') ||
      isInNet(host, '198.18.0.0', '255.254.0.0') ||
      isInNet(host, '198.51.100.0', '255.255.255.0') ||
      isInNet(host, '203.0.113.0', '255.255.255.0') ||
      isInNet(host, '240.0.0.0', '240.0.0.0')) {{
    return 'DIRECT';
  }}
  return 'PROXY {0}:{1}';
}}
"#, http_host, http_port);

        if !dynamic_routes.is_empty() {
            let mut extra = String::new();
            extra.push_str("// dynamic routes via VPN on Windows\nfunction __bypassDynamic(host) {\n");
            extra.push_str("  if (\n");
            for (i, (addr, mask)) in dynamic_routes.iter().enumerate() {
                if i > 0 { extra.push_str("      || "); } else { extra.push_str("      "); }
                extra.push_str(&format!("isInNet(host, '{}', '{}')\n", addr, mask));
            }
            extra.push_str("  ) { return 'DIRECT'; }\n  return null;\n}\n\n");
            let wrapped = format!(
                r#"{extra}
function FindProxyForURL(url, host) {{
  var d = __bypassDynamic(host);
  if (d) return d;
  return ({main})(url, host);
}}
"#,
                extra = extra,
                main = "FindProxyForURL"
            );
            pac.push_str(&wrapped);
        }

        if let Ok(mut f) = fs::File::create(&pac_path) {
            if f.write_all(pac.as_bytes()).is_ok() {
                return Some(pac_path.to_string_lossy().into_owned());
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    async fn set_macos_system_proxy(&self, settings: &ProxySettings) -> Result<()> {
        // On macOS we configure SOCKS proxy using `networksetup` for all network services
        // We intentionally only set SOCKS to keep HTTP/HTTPS untouched
        let services = list_macos_network_services();

        // Determine host:port from provided settings (prefer SOCKS5)
        let maybe_socks = settings
            .socks_proxy
            .as_ref()
            .or(settings.http_proxy.as_ref())
            .cloned();

        if let Some(socks_url) = maybe_socks {
            // Normalize to host, port
            let (host, port) = parse_socks_host_port(&socks_url).unwrap_or(("127.0.0.1".to_string(), 1080u16));

            for service in services {
                // networksetup -setsocksfirewallproxy "Wi-Fi" host port
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsocksfirewallproxy")
                    .arg(&service)
                    .arg(&host)
                    .arg(port.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();

                // Enable
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsocksfirewallproxystate")
                    .arg(&service)
                    .arg("on")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();

                // Bypass domains if provided
                if let Some(ref bypass) = settings.no_proxy {
                    let domains: Vec<String> = bypass
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !domains.is_empty() {
                        let mut cmd = std::process::Command::new("networksetup");
                        cmd.arg("-setproxybypassdomains").arg(&service);
                        for d in domains { cmd.arg(d); }
                        let _ = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
                    }
                }
                // Point HTTP/HTTPS at local ACL HTTP proxy 127.0.0.1:8080 so browsers always hit ACL
                let _ = std::process::Command::new("networksetup")
                    .arg("-setwebproxy")
                    .arg(&service)
                    .arg("127.0.0.1")
                    .arg("8080")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .arg("-setwebproxystate")
                    .arg(&service)
                    .arg("on")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsecurewebproxy")
                    .arg(&service)
                    .arg("127.0.0.1")
                    .arg("8080")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsecurewebproxystate")
                    .arg(&service)
                    .arg("on")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }

            // Install a PAC file to implement CIDR-based bypass (Outline-style) and send the rest via local proxy
            if let Some(pac_path) = write_macos_pac(&host, 0u16, port) {
                for service in list_macos_network_services() {
                    let _ = std::process::Command::new("networksetup")
                        .arg("-setautoproxyurl")
                        .arg(&service)
                        .arg(format!("file://{}", pac_path))
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    let _ = std::process::Command::new("networksetup")
                        .arg("-setautoproxystate")
                        .arg(&service)
                        .arg("on")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
                log::info!("[SYSTEM_PROXY][macOS] PAC installed for services");
            } else {
                log::warn!("[SYSTEM_PROXY][macOS] Failed to write PAC file; relying on SOCKS + domain bypass only");
            }
        } else {
            // Disable SOCKS proxy on all services
            for service in services {
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsocksfirewallproxystate")
                    .arg(&service)
                    .arg("off")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                // Also disable HTTP/HTTPS
                let _ = std::process::Command::new("networksetup")
                    .arg("-setwebproxystate")
                    .arg(&service)
                    .arg("off")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .arg("-setsecurewebproxystate")
                    .arg(&service)
                    .arg("off")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                // Disable Auto Proxy (PAC)
                let _ = std::process::Command::new("networksetup")
                    .arg("-setautoproxystate")
                    .arg(&service)
                    .arg("off")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            log::info!("[SYSTEM_PROXY][macOS] SOCKS proxy disabled for all services");
        }

        Ok(())
    }

    

    pub async fn set_tun_mode(&mut self, enable: bool) -> Result<()> {
        log::info!("[SYSTEM_PROXY] Setting TUN mode: {}", enable);
        
        if enable {
            // Включаем TUN режим - весь трафик идет через VPN
            self.enable_tun_mode().await?;
        } else {
            // Отключаем TUN режим
            self.disable_tun_mode().await?;
        }
        
        self.tun_mode = enable;
        log::info!("[SYSTEM_PROXY] TUN mode set to: {}", enable);
        Ok(())
    }

    async fn enable_tun_mode(&mut self) -> Result<()> {
        log::info!("[SYSTEM_PROXY] Enabling TUN mode - using system proxy with TUN interface");
        
        // Сохраняем текущие настройки прокси
        if self.original_settings.is_none() {
            self.original_settings = Some(self.get_current_proxy_settings().await?);
        }

        // Устанавливаем системный прокси на наш SOCKS5 прокси
        // TUN интерфейс будет использоваться для мониторинга, но трафик идет через системный прокси
        let proxy_settings = ProxySettings::with_socks5("127.0.0.1", 1080);
        self.set_proxy_settings(&proxy_settings).await?;

        Ok(())
    }

    async fn disable_tun_mode(&mut self) -> Result<()> {
        log::info!("[SYSTEM_PROXY] Disabling TUN mode");
        
        // Восстанавливаем оригинальные настройки прокси
        if let Some(ref original) = self.original_settings {
            self.set_proxy_settings(original).await?;
        } else {
            let empty_settings = ProxySettings::new();
            self.set_proxy_settings(&empty_settings).await?;
        }
        // Also disable DE-proxy explicitly on Linux
        #[cfg(target_os = "linux")]
        {
            let de = detect_desktop_env();
            match de {
                DesktopEnv::Gnome if which("gsettings") => {
                    let _ = Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "none"]).output();
                }
                DesktopEnv::Kde if which("kwriteconfig5") => {
                    // ProxyType=0 (No proxy)
                    let _ = Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"]).output();
                    // Clear values
                    let _ = Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", ""]).output();
                    // Apply
                    let _ = Command::new("qdbus").args(["org.kde.kded5", "/kded", "reconfigure"]).stdout(Stdio::null()).stderr(Stdio::null()).output();
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn is_tun_mode(&self) -> bool {
        self.tun_mode
    }
}

#[derive(Clone, Copy, Debug)]
enum DesktopEnv { Gnome, Kde, Unknown }

fn detect_desktop_env() -> DesktopEnv {
    let de = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_lowercase();
    if de.contains("gnome") { return DesktopEnv::Gnome; }
    if de.contains("kde") || de.contains("plasma") { return DesktopEnv::Kde; }
    let ses = std::env::var("DESKTOP_SESSION").unwrap_or_default().to_lowercase();
    if ses.contains("gnome") { return DesktopEnv::Gnome; }
    if ses.contains("kde") || ses.contains("plasma") { return DesktopEnv::Kde; }
    DesktopEnv::Unknown
}

fn which(bin: &str) -> bool {
    Command::new("which").arg(bin).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn set_proxy_gnome(settings: &ProxySettings) -> Result<()> {
    if let Some(ref http_proxy) = settings.http_proxy {
        if let Some(proxy_url) = http_proxy.strip_prefix("socks5://") {
            if let Some((host, port)) = proxy_url.split_once(':') {
                // mode manual
                Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "manual"]).output()?;
                // socks host/port
                Command::new("gsettings").args(["set", "org.gnome.system.proxy.socks", "host", host]).output()?;
                Command::new("gsettings").args(["set", "org.gnome.system.proxy.socks", "port", port]).output()?;
                // ignore-hosts expects array string: ['localhost','127.0.0.1','::1']
                let ignore = settings.no_proxy.clone().unwrap_or_else(|| "localhost,127.0.0.1,::1".to_string());
                let arr = format!("[{}]",
                    ignore.split(',')
                        .map(|s| format!("'{}'", s.trim()))
                        .collect::<Vec<_>>()
                        .join(","));
                let _ = Command::new("gsettings").args(["set", "org.gnome.system.proxy", "ignore-hosts", &arr]).output();
                log::info!("[SYSTEM_PROXY] GNOME proxy set: {}:{}", host, port);
            }
        }
    } else {
        // disable
        Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "none"]).output()?;
        log::info!("[SYSTEM_PROXY] GNOME proxy disabled");
    }
    Ok(())
}

fn set_proxy_kde(settings: &ProxySettings) -> Result<()> {
    // KDE stores in kioslaverc; ProxyType: 0=no, 1=auto, 2=manual
    if let Some(ref http_proxy) = settings.http_proxy {
        if let Some(proxy_url) = http_proxy.strip_prefix("socks5://") {
            if let Some((host, port)) = proxy_url.split_once(':') {
                Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "2"]).output()?;
                let socks_value = format!("socks://{}:{}", host, port);
                Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", &socks_value]).output()?;
                // http/https empty to avoid forcing
                Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", ""]).output()?;
                Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", ""]).output()?;
                // set bypass list if provided
                if let Some(ref bypass) = settings.no_proxy {
                    Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", bypass]).output()?;
                }
                // apply
                let _ = Command::new("qdbus").args(["org.kde.kded5", "/kded", "reconfigure"]).stdout(Stdio::null()).stderr(Stdio::null()).output();
                log::info!("[SYSTEM_PROXY] KDE proxy set: {}:{}", host, port);
            }
        }
    } else {
        // disable
        Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"]).output()?;
        Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", ""]).output()?;
        // clear bypass
        Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", ""]).output()?;
        let _ = Command::new("qdbus").args(["org.kde.kded5", "/kded", "reconfigure"]).stdout(Stdio::null()).stderr(Stdio::null()).output();
        log::info!("[SYSTEM_PROXY] KDE proxy disabled");
    }
    Ok(())
}

impl Default for SystemProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> Vec<String> {
    // Parse `networksetup -listallnetworkservices` and skip header and disabled services (prefixed with '*')
    let output = std::process::Command::new("networksetup").arg("-listallnetworkservices").output();
    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut services: Vec<String> = Vec::new();
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() { continue; }
                if line.starts_with("An asterisk (") { continue; }
                // Skip disabled services (start with '* ')
                if line.starts_with('*') { continue; }
                services.push(line.to_string());
            }
            if !services.is_empty() { return services; }
        }
    }
    // Fallback to common service names
    vec!["Wi-Fi".to_string(), "Ethernet".to_string()]
}

#[cfg(target_os = "macos")]
fn parse_socks_host_port(url: &str) -> Option<(String, u16)> {
    // Accept formats: socks5://host:port, socks://host:port, host:port
    let trimmed = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks://"))
        .unwrap_or(url);
    let (host, port_str) = trimmed.split_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

#[cfg(target_os = "macos")]
fn verify_macos_proxies() -> bool {
    // scutil --proxy prints a plist-like dictionary; check that HTTP, HTTPS or SOCKS are enabled
    if let Ok(out) = std::process::Command::new("scutil").arg("--proxy").output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
            let http_on = text.contains("httpenable : 1") && text.contains("httpproxy : 127.0.0.1") && text.contains("httpport : 8080");
            let https_on = text.contains("httpsenable : 1") && text.contains("httpsproxy : 127.0.0.1") && text.contains("httpsport : 8080");
            let socks_on = text.contains("socksenable : 1");
            return http_on || https_on || socks_on;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn write_macos_pac(http_host: &str, _http_port: u16, socks_port: u16) -> Option<String> {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.push("Library");
    dir.push("Application Support");
    dir.push("CrabSock");
    let _ = fs::create_dir_all(&dir);
    let mut pac_path = PathBuf::from(&dir);
    pac_path.push("proxy.pac");

    // Collect additional IPv4 routes that are bound to utun*/pritunl interfaces to bypass via DIRECT
    let mut dynamic_routes: Vec<(String, String)> = Vec::new();
    if let Ok(out) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                // Example columns: Destination  Gateway  Flags  Refs  Use  Netif  Expire
                // We are interested in lines where Netif starts with utun or contains 'pritunl'
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let destination = parts[0];
                    let netif = parts[6];
                    if netif.starts_with("utun") || netif.to_lowercase().contains("pritunl") {
                        if destination == "default" { continue; }
                        // destination may be in form A.B.C.D/xx or A.B.C.D
                        if let Some((addr, prefix_str)) = destination.split_once('/') {
                            if let Ok(prefix) = prefix_str.parse::<u8>() {
                                // compute mask from prefix
                                let mask_u32: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix as u32) };
                                let mask = format!("{}.{}.{}.{}",
                                    (mask_u32 >> 24) & 0xff,
                                    (mask_u32 >> 16) & 0xff,
                                    (mask_u32 >> 8) & 0xff,
                                    mask_u32 & 0xff);
                                dynamic_routes.push((addr.to_string(), mask));
                            }
                        } else {
                            // host route, use /32 mask
                            dynamic_routes.push((destination.to_string(), "255.255.255.255".to_string()));
                        }
                    }
                }
            }
        }
    }

    // Outline-like excluded subnets via PAC isInNet checks
    let mut pac = format!(r#"function FindProxyForURL(url, host) {{
  if (isPlainHostName(host) ||
      isInNet(host, '10.0.0.0', '255.0.0.0') ||
      isInNet(host, '100.64.0.0', '255.192.0.0') ||
      isInNet(host, '169.254.0.0', '255.255.0.0') ||
      isInNet(host, '172.16.0.0', '255.240.0.0') ||
      isInNet(host, '192.0.0.0', '255.255.255.0') ||
      isInNet(host, '192.0.2.0', '255.255.255.0') ||
      isInNet(host, '192.31.196.0', '255.255.255.0') ||
      isInNet(host, '192.52.193.0', '255.255.255.0') ||
      isInNet(host, '192.88.99.0', '255.255.255.0') ||
      isInNet(host, '192.168.0.0', '255.255.0.0') ||
      isInNet(host, '192.175.48.0', '255.255.255.0') ||
      isInNet(host, '198.18.0.0', '255.254.0.0') ||
      isInNet(host, '198.51.100.0', '255.255.255.0') ||
      isInNet(host, '203.0.113.0', '255.255.255.0') ||
      isInNet(host, '240.0.0.0', '240.0.0.0')) {{
    return 'DIRECT';
  }}
  return 'SOCKS {0}:{1}';
}}
"#, http_host, socks_port);

    // Append dynamic routes from utun/pritunl to DIRECT checks
    if !dynamic_routes.is_empty() {
        let mut extra = String::new();
        extra.push_str("// dynamic routes via utun/pritunl\nfunction __bypassDynamic(host) {\n");
        extra.push_str("  if (\n");
        for (i, (addr, mask)) in dynamic_routes.iter().enumerate() {
            if i > 0 { extra.push_str("      || "); } else { extra.push_str("      "); }
            extra.push_str(&format!("isInNet(host, '{}', '{}')\n", addr, mask));
        }
        extra.push_str("  ) { return 'DIRECT'; }\n  return null;\n}\n\n");
        // Insert call to __bypassDynamic at top: we prepend function and then rewrap main with it
        // Simple way: append a second FindProxyForURL that prioritizes dynamic bypass
        let wrapped = format!(
            r#"{extra}
function FindProxyForURL(url, host) {{
  var d = __bypassDynamic(host);
  if (d) return d;
  return ({main})(url, host);
}}
"#,
            extra = extra,
            main = "FindProxyForURL"
        );
        pac.push_str(&wrapped);
    }

    if let Ok(mut f) = fs::File::create(&pac_path) {
        if f.write_all(pac.as_bytes()).is_ok() {
            return Some(pac_path.to_string_lossy().into_owned());
        }
    }
    None
}
