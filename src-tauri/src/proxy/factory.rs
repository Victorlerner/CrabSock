use crate::config::{ProxyConfig, ProxyType};
use crate::error::VpnError;
use crate::proxy::types::ProxyClient;

use crate::proxy::clients::shadowsocks::ShadowsocksClient;
use crate::proxy::clients::vless::VlessClient;
use crate::proxy::clients::vmess::VmessClient;
use crate::proxy::clients::socks5::Socks5Client;

pub fn build_client(config: ProxyConfig) -> Result<Box<dyn ProxyClient>, VpnError> {
    let client: Box<dyn ProxyClient> = match config.proxy_type.clone() {
        ProxyType::Shadowsocks => Box::new(ShadowsocksClient::new(config)),
        ProxyType::VMess => Box::new(VmessClient::new(config)),
        ProxyType::VLESS => Box::new(VlessClient::new(config)),
        ProxyType::SOCKS5 => Box::new(Socks5Client::new(config)),
        _ => return Err(VpnError::ConnectionFailed("Unsupported proxy type".to_string())),
    };
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg(proxy_type: ProxyType) -> ProxyConfig {
        ProxyConfig {
            proxy_type,
            name: "t".into(),
            server: "example.com".into(),
            port: 1080,
            password: None,
            method: None,
            uuid: None,
            security: None,
            network: None,
            tls: None,
            sni: None,
            skip_cert_verify: None,
            alpn: None,
            ws_path: None,
            ws_headers: None,
            flow: None,
            fingerprint: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_spx: None,
        }
    }

    #[test]
    fn build_client_shadowsocks_ok() {
        let cfg = base_cfg(ProxyType::Shadowsocks);
        let _client = build_client(cfg).unwrap_or_else(|e| panic!("{}", e));
    }

    #[test]
    fn build_client_unsupported_type_err() {
        let cfg = base_cfg(ProxyType::HTTP);
        match build_client(cfg) {
            Err(VpnError::ConnectionFailed(m)) => assert_eq!(m, "Unsupported proxy type"),
            Err(other) => panic!("unexpected error: {}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}


