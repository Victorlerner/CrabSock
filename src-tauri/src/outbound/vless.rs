use serde_json::json;
use serde_json::Value;

use super::strategy::OutboundStrategy;

pub struct VlessStrategy;

impl OutboundStrategy for VlessStrategy {
    fn build_outbounds(&self) -> Value {
        let server = std::env::var("SB_VLESS_SERVER").unwrap_or_else(|_| "".into());
        let port: u16 = std::env::var("SB_VLESS_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
        let uuid = std::env::var("SB_VLESS_UUID").unwrap_or_else(|_| "".into());
        let security = std::env::var("SB_VLESS_SECURITY").unwrap_or_else(|_| "reality".into());
        let sni = std::env::var("SB_VLESS_SNI").unwrap_or_else(|_| "".into());
        let fp = std::env::var("SB_VLESS_FP").unwrap_or_else(|_| "chrome".into());
        let flow = std::env::var("SB_VLESS_FLOW").unwrap_or_else(|_| "".into());
        let pbk = std::env::var("SB_VLESS_PBK").unwrap_or_else(|_| "".into());
        let sid = std::env::var("SB_VLESS_SID").unwrap_or_else(|_| "".into());

        json!([
            {
                "type": "vless",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "flow": flow,
                "packet_encoding": "",
                "domain_resolver": "dns-direct",
                "tls": {
                    "enabled": true,
                    "server_name": sni,
                    "utls": { "enabled": true, "fingerprint": fp },
                    "reality": {
                        "enabled": security == "reality",
                        "public_key": pbk,
                        "short_id": sid
                    }
                }
            },
            { "type": "direct", "tag": "direct" }
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_strategy_builds_outbounds_with_keys_present() {
        // Do not assert env-derived values, only structure
        let v = VlessStrategy.build_outbounds();
        assert_eq!(v[0]["type"], "vless");
        assert!(v[0]["server"].is_string());
        assert!(v[0]["server_port"].is_u64());
        assert!(v[0]["uuid"].is_string());
        assert!(v[1]["type"].is_string());
    }
}

