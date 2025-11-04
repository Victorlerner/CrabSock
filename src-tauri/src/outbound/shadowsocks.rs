use serde_json::json;
use serde_json::Value;

use super::strategy::OutboundStrategy;

pub struct ShadowsocksStrategy;

impl OutboundStrategy for ShadowsocksStrategy {
    fn build_outbounds(&self) -> Value {
        let server = std::env::var("SB_SS_SERVER").unwrap_or_else(|_| "".into());
        let port: u16 = std::env::var("SB_SS_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8388);
        let method = std::env::var("SB_SS_METHOD").unwrap_or_else(|_| "chacha20-ietf-poly1305".into());
        let password = std::env::var("SB_SS_PASSWORD").unwrap_or_else(|_| "".into());
        json!([
            {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "method": method,
                "password": password
            },
            { "type": "direct", "tag": "direct" }
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadowsocks_strategy_builds_expected_structure() {
        let v = ShadowsocksStrategy.build_outbounds();
        assert_eq!(v[0]["type"], "shadowsocks");
        assert!(v[0]["server"].is_string());
        assert!(v[0]["server_port"].is_u64());
        assert!(v[0]["method"].is_string());
        assert!(v[0]["password"].is_string());
        assert_eq!(v[1]["type"], "direct");
    }
}

