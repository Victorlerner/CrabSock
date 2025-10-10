use anyhow::Result;
use std::process::Command;

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

        // Для Linux также устанавливаем системные настройки прокси через gsettings
        if cfg!(target_os = "linux") {
            self.set_linux_system_proxy(settings).await?;
        }

        Ok(())
    }

    async fn set_linux_system_proxy(&self, settings: &ProxySettings) -> Result<()> {
        // Используем gsettings для установки системного прокси в GNOME/KDE
        if let Some(ref http_proxy) = settings.http_proxy {
            // Парсим URL прокси
            if let Some(proxy_url) = http_proxy.strip_prefix("socks5://") {
                if let Some((host, port)) = proxy_url.split_once(':') {
                    // Устанавливаем SOCKS5 прокси
                    
                    // Включаем прокси
                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy", "mode", "manual"])
                        .output()?;

                    // Устанавливаем SOCKS прокси
                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.socks", "host", host])
                        .output()?;

                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.socks", "port", port])
                        .output()?;

                    // Устанавливаем HTTP прокси (тот же SOCKS5)
                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.http", "host", host])
                        .output()?;

                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.http", "port", port])
                        .output()?;

                    // Устанавливаем HTTPS прокси (тот же SOCKS5)
                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.https", "host", host])
                        .output()?;

                    Command::new("gsettings")
                        .args(&["set", "org.gnome.system.proxy.https", "port", port])
                        .output()?;

                    // Устанавливаем исключения (no_proxy)
                    if let Some(ref no_proxy) = settings.no_proxy {
                        Command::new("gsettings")
                            .args(&["set", "org.gnome.system.proxy", "ignore-hosts", no_proxy])
                            .output()?;
                    }

                    log::info!("[SYSTEM_PROXY] Linux system proxy set: {}:{}", host, port);
                }
            }
        } else {
            // Отключаем прокси
            Command::new("gsettings")
                .args(&["set", "org.gnome.system.proxy", "mode", "none"])
                .output()?;

            log::info!("[SYSTEM_PROXY] Linux system proxy disabled");
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

        Ok(())
    }

    pub fn is_tun_mode(&self) -> bool {
        self.tun_mode
    }
}

impl Default for SystemProxyManager {
    fn default() -> Self {
        Self::new()
    }
}
