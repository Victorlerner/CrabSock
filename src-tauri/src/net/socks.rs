use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn ensure_socks_ready(host: &str, port: u16) -> anyhow::Result<()> {
    let addr = (host, port);
    log::info!("[SOCKS] Waiting for local SOCKS at {}:{}", host, port);
    for _ in 0..20 {
        if let Ok(Ok(_)) = timeout(Duration::from_millis(250), TcpStream::connect(addr)).await {
            log::info!("[SOCKS] Local SOCKS is ready at {}:{}", host, port);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    log::warn!("[SOCKS] Local SOCKS endpoint {}:{} not reachable in time", host, port);
    Err(anyhow::anyhow!(format!("Local SOCKS endpoint {}:{} not reachable", host, port)))
}

pub fn get_socks_endpoint() -> (String, u16) {
    if let Ok(proxy) = std::env::var("SOCKS_PROXY") {
        let p = proxy.trim();
        let without_scheme = p.strip_prefix("socks5h://").or_else(|| p.strip_prefix("socks5://")).unwrap_or(p);
        let hostport = without_scheme.split('@').last().unwrap_or(without_scheme);
        let hostport = hostport.split('/').next().unwrap_or(hostport);
        let mut parts = hostport.rsplitn(2, ':');
        if let (Some(port_s), Some(host)) = (parts.next(), parts.next()) {
            if let Ok(port) = port_s.parse::<u16>() {
                log::info!("[SOCKS] Using endpoint from SOCKS_PROXY: {}:{}", host, port);
                return (host.to_string(), port);
            }
        }
        if !hostport.is_empty() {
            log::info!("[SOCKS] Using endpoint from SOCKS_PROXY host only: {}:1080", hostport);
            return (hostport.to_string(), 1080);
        }
    }
    log::info!("[SOCKS] Using default endpoint 127.0.0.1:1080");
    ("127.0.0.1".to_string(), 1080)
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn parse_plain_host_only_defaults_port() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SOCKS_PROXY", "socks5://localhost");
        let (h, p) = get_socks_endpoint();
        assert_eq!(h, "localhost");
        assert_eq!(p, 1080);
        std::env::remove_var("SOCKS_PROXY");
    }

    #[test]
    fn parse_host_and_port() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SOCKS_PROXY", "socks5h://127.0.0.1:1081");
        let (h, p) = get_socks_endpoint();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 1081);
        std::env::remove_var("SOCKS_PROXY");
    }

    #[test]
    fn parse_with_auth_and_path() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SOCKS_PROXY", "socks5://user:pass@10.0.0.2:9999/foo");
        let (h, p) = get_socks_endpoint();
        assert_eq!(h, "10.0.0.2");
        assert_eq!(p, 9999);
        std::env::remove_var("SOCKS_PROXY");
    }
}

