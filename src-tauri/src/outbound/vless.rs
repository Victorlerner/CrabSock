use serde_json::json;
use serde_json::Value;

use super::strategy::OutboundStrategy;

pub struct VlessStrategy;

impl OutboundStrategy for VlessStrategy {
    fn build_outbounds(&self) -> Value {
        use std::net::{IpAddr, ToSocketAddrs};

        let original_server = std::env::var("SB_VLESS_SERVER").unwrap_or_else(|_| "".into());
        let port: u16 = std::env::var("SB_VLESS_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
        let uuid = std::env::var("SB_VLESS_UUID").unwrap_or_else(|_| "".into());
        let security = std::env::var("SB_VLESS_SECURITY").unwrap_or_else(|_| "reality".into());
        let mut sni = std::env::var("SB_VLESS_SNI").unwrap_or_else(|_| "".into());
        let fp = std::env::var("SB_VLESS_FP").unwrap_or_else(|_| "chrome".into());
        let flow = std::env::var("SB_VLESS_FLOW").unwrap_or_else(|_| "".into());
        let pbk = std::env::var("SB_VLESS_PBK").unwrap_or_else(|_| "".into());
        let sid = std::env::var("SB_VLESS_SID").unwrap_or_else(|_| "".into());

        // IMPORTANT (Windows especially): if we pass a hostname here, sing-box will try to resolve it
        // using its own DNS configuration. In our TUN config DNS is detoured via the proxy itself,
        // which can cause "DNS query loopback" when the upstream is not resolvable yet.
        //
        // Fix: resolve hostname to IP in Rust before generating the sing-box config, and keep SNI as hostname.
        let mut server = original_server.clone();
        if !server.is_empty() && server.parse::<IpAddr>().is_err() {
            if let Ok(iter) = (server.as_str(), port).to_socket_addrs() {
                let mut v4: Option<IpAddr> = None;
                let mut v6: Option<IpAddr> = None;
                for sa in iter {
                    match sa.ip() {
                        IpAddr::V4(ip) => { v4 = Some(IpAddr::V4(ip)); break; }
                        IpAddr::V6(ip) => { if v6.is_none() { v6 = Some(IpAddr::V6(ip)); } }
                    }
                }
                let chosen = v4.or(v6);
                if let Some(ip) = chosen {
                    log::info!("[VLESS][TUN] Resolved upstream host {} -> {}", server, ip);
                    server = ip.to_string();
                } else {
                    log::warn!("[VLESS][TUN] Could not resolve upstream host {}; using hostname as-is", server);
                }
            } else {
                log::warn!("[VLESS][TUN] DNS resolution failed for upstream host {}; using hostname as-is", server);
            }
        }

        // If SNI isn't explicitly set, fall back to the original hostname (not the resolved IP).
        if sni.is_empty() {
            sni = original_server.clone();
        }

        json!([
            {
                "type": "vless",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "flow": flow,
                "packet_encoding": "",
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

