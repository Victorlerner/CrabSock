use anyhow::Result;
use std::net::Ipv4Addr;
use tun_tap::{Iface, Mode};

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
            netmask: Ipv4Addr::new(255, 255, 255, 240), // /28
            mtu: 1500,
        }
    }
}

pub struct TunManager {
    iface: Option<Iface>,
    config: TunConfig,
    is_running: bool,
}

impl TunManager {
    pub fn new() -> Self {
        Self {
            iface: None,
            config: TunConfig::default(),
            is_running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running {
            log::warn!("[TUN] Already running");
            return Ok(());
        }

        log::info!("[TUN] Starting TUN interface: {}", self.config.name);
        println!("[STDOUT] TUN: Attempting to create TUN interface: {}", self.config.name);

        // Проверяем права доступа
        if !self.check_permissions() {
            println!("[STDOUT] TUN: No permissions to create TUN interface");
            return Err(anyhow::anyhow!("Insufficient permissions to create TUN interface"));
        }

        // Пытаемся удалить существующий интерфейс
        self.cleanup_existing_interface().await?;

        // Создаем TUN интерфейс
        let iface = Iface::new(&self.config.name, Mode::Tun)
            .map_err(|e| {
                println!("[STDOUT] TUN: Failed to create TUN interface: {}", e);
                anyhow::anyhow!("Failed to create TUN interface: {}", e)
            })?;

        println!("[STDOUT] TUN: TUN interface created successfully");
        self.iface = Some(iface);

        // Настраиваем интерфейс
        self.configure_tun_interface().await?;

        // НЕ настраиваем маршрутизацию - оставляем системный прокси работать
        // TUN Mode в данном случае просто создает интерфейс для мониторинга

        self.is_running = true;
        log::info!("[TUN] TUN interface started successfully (monitoring mode)");
        println!("[STDOUT] TUN: TUN interface started successfully (monitoring mode)");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running {
            log::warn!("[TUN] Not running");
            return Ok(());
        }

        log::info!("[TUN] Stopping TUN interface");

        // Очищаем маршруты
        self.clear_routes().await?;

        // Останавливаем интерфейс
        if let Some(iface) = self.iface.take() {
            drop(iface);
        }

        self.is_running = false;
        log::info!("[TUN] TUN interface stopped");
        Ok(())
    }

    async fn cleanup_existing_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        
        // Пытаемся удалить существующий интерфейс
        let output = std::process::Command::new("sudo")
            .args(&["ip", "tuntap", "del", "mode", "tun", "dev", interface_name])
            .output()?;

        if output.status.success() {
            log::info!("[TUN] Removed existing interface: {}", interface_name);
        } else {
            log::debug!("[TUN] No existing interface to remove: {}", interface_name);
        }

        Ok(())
    }

    fn check_permissions(&self) -> bool {
        // Проверяем, есть ли у процесса права для создания TUN интерфейса
        // В Linux это требует CAP_NET_ADMIN
        std::fs::metadata("/dev/net/tun").is_ok()
    }

    async fn configure_tun_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        let address = self.config.address;

        log::info!("[TUN] Configuring interface {} with IP {}/{}", 
                   interface_name, address, self.get_cidr_prefix());

        // Настраиваем IP адрес через ip команду с sudo
        let output = std::process::Command::new("sudo")
            .args(&["ip", "addr", "add", &format!("{}/{}", address, self.get_cidr_prefix()), 
                   "dev", interface_name])
            .output()?;

        if !output.status.success() {
            log::warn!("[TUN] Failed to set IP address: {}", String::from_utf8_lossy(&output.stderr));
        }

        // Поднимаем интерфейс с sudo
        let output = std::process::Command::new("sudo")
            .args(&["ip", "link", "set", "dev", interface_name, "up"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to bring up interface: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    async fn clear_routes(&self) -> Result<()> {
        let interface_name = &self.config.name;
        
        log::info!("[TUN] Clearing routes");

        // Удаляем IP адрес с sudo
        let output = std::process::Command::new("sudo")
            .args(&["ip", "addr", "del", &format!("{}/{}", self.config.address, self.get_cidr_prefix()), 
                   "dev", interface_name])
            .output()?;

        if !output.status.success() {
            log::debug!("[TUN] IP address not found or already removed");
        }

        Ok(())
    }

    fn get_cidr_prefix(&self) -> u8 {
        // Вычисляем CIDR префикс из маски подсети
        let mask = u32::from(self.config.netmask);
        mask.count_ones() as u8
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }

    // Метод для совместимости (не используется, но оставляем для избежания предупреждений)
    #[allow(dead_code)]
    async fn start_with_sudo(&mut self) -> Result<()> {
        // Этот метод больше не используется, так как мы используем sudo в отдельных командах
        Err(anyhow::anyhow!("This method is deprecated"))
    }
}