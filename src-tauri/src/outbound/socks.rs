use serde_json::json;
use serde_json::Value;

use super::strategy::OutboundStrategy;

pub struct SocksStrategy {
    pub server: String,
    pub port: u16,
}

impl OutboundStrategy for SocksStrategy {
    fn build_outbounds(&self) -> Value {
        json!([
            {
                "type": "socks",
                "tag": "proxy",
                "server": self.server,
                "server_port": self.port,
                "version": "5",
                "udp_over_tcp": true
            },
            { "type": "direct", "tag": "direct" }
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_strategy_builds_expected_outbounds() {
        let s = SocksStrategy { server: "127.0.0.1".into(), port: 1080 };
        let v = s.build_outbounds();
        assert_eq!(v[0]["type"], "socks");
        assert_eq!(v[0]["server"], "127.0.0.1");
        assert_eq!(v[0]["server_port"], 1080);
        assert_eq!(v[1]["type"], "direct");
    }
}

