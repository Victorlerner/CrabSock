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
            no_proxy: Some("localhost,127.0.0.1,::1".to_string()),
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
        // Windows supports system-wide WinINET proxy for WinINet-aware apps. We'll set:
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        //  - ProxyEnable (DWORD)
        //  - ProxyServer (STRING) in format "socks=host:port" for SOCKS
        //  - ProxyOverride (STRING)

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        let (key, _) = hkcu.create_subkey(path)?;

        if let Some(ref http_proxy) = settings.http_proxy {
            // Prefer SOCKS5 overall if provided
            let socks = settings
                .socks_proxy
                .as_ref()
                .or(Some(http_proxy))
                .cloned()
                .unwrap();
            // Normalize to socks=host:port
            let proxy_str = if let Some(rest) = socks.strip_prefix("socks5://") {
                format!("socks={}", rest)
            } else if let Some(rest) = socks.strip_prefix("socks://") {
                format!("socks={}", rest)
            } else if let Some(rest) = socks.strip_prefix("http://") {
                // fallback
                rest.to_string()
            } else {
                format!("socks={}", socks)
            };

            key.set_value("ProxyEnable", &1u32)?;
            key.set_value("ProxyServer", &proxy_str)?;

            let override_val = settings
                .no_proxy
                .clone()
                .unwrap_or_else(|| "localhost;127.0.0.1;<local>".to_string())
                .replace(',', ";");
            key.set_value("ProxyOverride", &override_val)?;
        } else {
            // disable proxy
            key.set_value("ProxyEnable", &0u32)?;
            let _ = key.delete_value("ProxyServer");
        }

        // Notify system
        unsafe {
            let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
            let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
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
                // apply
                let _ = Command::new("qdbus").args(["org.kde.kded5", "/kded", "reconfigure"]).stdout(Stdio::null()).stderr(Stdio::null()).output();
                log::info!("[SYSTEM_PROXY] KDE proxy set: {}:{}", host, port);
            }
        }
    } else {
        // disable
        Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"]).output()?;
        Command::new("kwriteconfig5").args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", ""]).output()?;
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
