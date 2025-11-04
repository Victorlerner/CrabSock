use crate::config::ProxyConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub configs: Vec<ProxyConfig>,
    #[serde(default)]
    pub settings: AppSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoutingMode { SystemProxy, Tun }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub routing_mode: RoutingMode,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self { routing_mode: RoutingMode::SystemProxy }
    }
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            configs: Vec::new(),
            settings: AppSettings::default(),
        }
    }
}

pub struct ConfigManager {
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let config_dir = Self::get_config_dir()?;
        let config_path = config_dir.join("configs.json");
        
        // Создаем директорию если не существует
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
            log::info!("[CONFIG] Created config directory: {:?}", config_dir);
        }
        
        Ok(Self { config_path })
    }
    
    fn get_config_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Failed to get config directory"))?;
        
        let app_config_dir = config_dir.join("CrabSock");
        Ok(app_config_dir)
    }
    
    pub async fn load_configs(&self) -> Result<ConfigFile> {
        if !self.config_path.exists() {
            log::info!("[CONFIG] Config file doesn't exist, creating default");
            let default_config = ConfigFile::default();
            self.save_configs(&default_config).await?;
            return Ok(default_config);
        }
        
        let content = tokio::fs::read_to_string(&self.config_path).await?;
        let config: ConfigFile = serde_json::from_str(&content)?;
        
        log::info!("[CONFIG] Loaded {} configs from {:?}", config.configs.len(), self.config_path);
        Ok(config)
    }
    
    pub async fn save_configs(&self, config: &ConfigFile) -> Result<()> {
        let content = serde_json::to_string_pretty(config)?;
        tokio::fs::write(&self.config_path, content).await?;
        
        log::info!("[CONFIG] Saved {} configs to {:?}", config.configs.len(), self.config_path);
        Ok(())
    }
    
    pub async fn add_config(&self, proxy_config: ProxyConfig) -> Result<()> {
        let mut config_file = self.load_configs().await?;
        
        // Проверяем, нет ли уже такого конфига
        let exists = config_file.configs.iter().any(|c| 
            c.server == proxy_config.server && 
            c.port == proxy_config.port && 
            c.proxy_type == proxy_config.proxy_type
        );
        
        if !exists {
            config_file.configs.push(proxy_config);
            self.save_configs(&config_file).await?;
            log::info!("[CONFIG] Added new config");
        } else {
            log::info!("[CONFIG] Config already exists, skipping");
        }
        
        Ok(())
    }
    
    pub async fn remove_config(&self, proxy_config: &ProxyConfig) -> Result<()> {
        let mut config_file = self.load_configs().await?;
        
        config_file.configs.retain(|c| 
            !(c.server == proxy_config.server && 
              c.port == proxy_config.port && 
              c.proxy_type == proxy_config.proxy_type)
        );
        
        self.save_configs(&config_file).await?;
        log::info!("[CONFIG] Removed config");
        Ok(())
    }
    
    pub async fn update_settings(&self, settings: AppSettings) -> Result<()> {
        // settings removed; keep compatibility no-op
        let mut config_file = self.load_configs().await?;
        config_file.settings = settings;
        self.save_configs(&config_file).await?;
        log::info!("[CONFIG] Settings no-op update");
        Ok(())
    }
    
    pub fn get_config_path(&self) -> &Path {
        &self.config_path
    }
}
