use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::error::{VpnError, VpnResult};
use base64::Engine;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyType {
    Shadowsocks,
    VMess,
    VLESS,
    Trojan,
    SOCKS5,
    HTTP,
}

impl FromStr for ProxyType {
    type Err = VpnError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(ProxyType::Shadowsocks),
            "vmess" => Ok(ProxyType::VMess),
            "vless" => Ok(ProxyType::VLESS),
            "trojan" => Ok(ProxyType::Trojan),
            "socks5" | "socks" => Ok(ProxyType::SOCKS5),
            "http" => Ok(ProxyType::HTTP),
            _ => Err(VpnError::InvalidConfig(format!("Unknown proxy type: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: Option<String>,
    pub method: Option<String>,
    pub uuid: Option<String>,
    pub security: Option<String>,
    pub network: Option<String>,
    pub tls: Option<bool>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub ws_path: Option<String>,
    pub ws_headers: Option<std::collections::HashMap<String, String>>,
}

impl ProxyConfig {
    pub fn from_ss_url(url: &str) -> VpnResult<Self> {
        if !url.starts_with("ss://") {
            return Err(VpnError::InvalidConfig("Not a Shadowsocks URL".to_string()));
        }

        // Parse URL to extract components
        let url_obj = url::Url::parse(url)
            .map_err(|_| VpnError::InvalidConfig("Invalid SS URL format".to_string()))?;

        let server = url_obj.host_str()
            .ok_or_else(|| VpnError::InvalidConfig("Missing server in SS URL".to_string()))?
            .to_string();
        
        let port = url_obj.port()
            .ok_or_else(|| VpnError::InvalidConfig("Missing port in SS URL".to_string()))?;

        let username = url_obj.username();
        let password_from_url = url_obj.password();

        let (method, password) = if password_from_url.is_none() {
            // Traditional format: ss://base64(method:password)@server:port
            let decoded = base64::engine::general_purpose::STANDARD_NO_PAD.decode(username)
                .map_err(|_| VpnError::InvalidConfig("Failed to decode SS URL username".to_string()))?;
            
            let decoded_str = String::from_utf8_lossy(&decoded);
            let parts: Vec<&str> = decoded_str.split(':').collect();
            
            if parts.len() != 2 {
                return Err(VpnError::InvalidConfig("Invalid SS URL auth format".to_string()));
            }
            
            (parts[0].to_string(), parts[1].to_string())
        } else {
            // 2022 format: ss://method:password@server:port
            // URL decode the password in case it's encoded
            let decoded_password = urlencoding::decode(password_from_url.unwrap())
                .map_err(|_| VpnError::InvalidConfig("Failed to decode SS URL password".to_string()))?
                .to_string();
            
            (username.to_string(), decoded_password)
        };

        Ok(ProxyConfig {
            proxy_type: ProxyType::Shadowsocks,
            name: format!("{}:{}", server, port),
            server,
            port,
            password: Some(password),
            method: Some(method),
            uuid: None,
            security: None,
            network: None,
            tls: None,
            sni: None,
            skip_cert_verify: None,
            alpn: None,
            ws_path: None,
            ws_headers: None,
        })
    }

    pub fn from_vmess_url(url: &str) -> VpnResult<Self> {
        if !url.starts_with("vmess://") {
            return Err(VpnError::InvalidConfig("Not a VMess URL".to_string()));
        }

        let raw = url.trim_start_matches("vmess://");
        let decoded = base64::engine::general_purpose::STANDARD.decode(raw)
            .map_err(|_| VpnError::InvalidConfig("Failed to decode VMess URL".to_string()))?;
        
        let json_str = String::from_utf8_lossy(&decoded);
        let vmess_config: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| VpnError::InvalidConfig(format!("Failed to parse VMess JSON: {}", e)))?;

        let server = vmess_config["add"].as_str()
            .ok_or_else(|| VpnError::InvalidConfig("Missing server address".to_string()))?
            .to_string();
        
        let port = vmess_config["port"].as_u64()
            .ok_or_else(|| VpnError::InvalidConfig("Missing port".to_string()))? as u16;
        
        let uuid = vmess_config["id"].as_str()
            .ok_or_else(|| VpnError::InvalidConfig("Missing UUID".to_string()))?
            .to_string();
        
        let security = vmess_config["security"].as_str().unwrap_or("auto").to_string();
        let network = vmess_config["net"].as_str().unwrap_or("tcp").to_string();
        let sni = vmess_config["sni"].as_str().map(|s| s.to_string());
        let ws_path = vmess_config["path"].as_str().map(|s| s.to_string());
        let is_tls = security == "tls";

        Ok(ProxyConfig {
            proxy_type: ProxyType::VMess,
            name: format!("{}:{}", server, port),
            server,
            port,
            password: None,
            method: None,
            uuid: Some(uuid),
            security: Some(security),
            network: Some(network),
            tls: Some(is_tls),
            sni,
            skip_cert_verify: Some(false),
            alpn: None,
            ws_path,
            ws_headers: None,
        })
    }

    pub fn from_json(json_str: &str) -> VpnResult<Self> {
        let config: ProxyConfig = serde_json::from_str(json_str)
            .map_err(|e| VpnError::InvalidConfig(format!("Failed to parse JSON config: {}", e)))?;
        Ok(config)
    }

    pub fn from_config_string(config_string: &str) -> VpnResult<Self> {
        if config_string.starts_with("ss://") {
            Self::from_ss_url(config_string)
        } else if config_string.starts_with("vmess://") {
            Self::from_vmess_url(config_string)
        } else if config_string.starts_with('{') {
            Self::from_json(config_string)
        } else {
            Err(VpnError::InvalidConfig("Config must be URL or JSON format".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ss_url_traditional_format() {
        // Traditional format: ss://base64(method:password)@server:port
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388";
        let config = ProxyConfig::from_ss_url(url).unwrap();
        
        assert_eq!(config.proxy_type, ProxyType::Shadowsocks);
        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 8388);
        assert_eq!(config.method, Some("chacha20-ietf-poly1305".to_string()));
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_ss_url_2022_format() {
        // 2022 format: ss://method:password@server:port
        let url = "ss://chacha20-ietf-poly1305:password@example.com:8388";
        let config = ProxyConfig::from_ss_url(url).unwrap();
        
        assert_eq!(config.proxy_type, ProxyType::Shadowsocks);
        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 8388);
        assert_eq!(config.method, Some("chacha20-ietf-poly1305".to_string()));
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_ss_url_2022_format_url_encoded() {
        // 2022 format with URL-encoded password
        let url = "ss://chacha20-ietf-poly1305:pass%40word@example.com:8388";
        let config = ProxyConfig::from_ss_url(url).unwrap();
        
        assert_eq!(config.proxy_type, ProxyType::Shadowsocks);
        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 8388);
        assert_eq!(config.method, Some("chacha20-ietf-poly1305".to_string()));
        assert_eq!(config.password, Some("pass@word".to_string()));
    }

    #[test]
    fn test_traditional_url_parsing() {
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388";
        println!("Testing traditional URL: {}", url);
        
        match url::Url::parse(url) {
            Ok(u) => {
                println!("Host: {:?}", u.host_str());
                println!("Port: {:?}", u.port());
                println!("Username: {:?}", u.username());
                println!("Password: {:?}", u.password());
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}