use anyhow::Result;
use serde_json::json;
use std::path::PathBuf;

use crate::tun_manager::TunConfig;
use crate::outbound::factory::make_from_env;

pub fn build_singbox_config(cfg: &TunConfig, socks_host: String, socks_port: u16) -> Result<PathBuf> {
    use std::net::{IpAddr, ToSocketAddrs};

    // For Linux we default sing-box log level to "warn",
    // on other platforms we keep "info". Can be overridden via SB_LOG_LEVEL.
    let default_log_level = if cfg!(target_os = "linux") { "warn" } else { "info" };
    let sb_log_level =
        std::env::var("SB_LOG_LEVEL").unwrap_or_else(|_| default_log_level.to_string());
    log::info!("[SING-BOX][CONFIG] Building sing-box config (log.level={sb_log_level}, socks={socks_host}:{socks_port})");

    let mut direct_cidrs: Vec<String> = vec![
        "127.0.0.0/8".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "169.254.0.0/16".to_string(),
        "224.0.0.0/4".to_string(),
        "255.255.255.255/32".to_string(),
    ];
    if let Ok(host) = std::env::var("SS_REMOTE_HOST") {
        let port: u16 = std::env::var("SS_REMOTE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let IpAddr::V4(v4) = ip { direct_cidrs.push(format!("{}/32", v4)); }
        } else if let Ok(iter) = (host.as_str(), port).to_socket_addrs() {
            use std::collections::BTreeSet;
            let mut seen = BTreeSet::new();
            for sa in iter {
                if let IpAddr::V4(v4) = sa.ip() {
                    if seen.insert(v4) { direct_cidrs.push(format!("{}/32", v4)); }
                    if seen.len() >= 8 { break; }
                }
            }
        }
    }

    let inet4 = format!(
        "{}/{}",
        cfg.address,
        {
            let mask = u32::from(cfg.netmask);
            mask.count_ones() as u8
        }
    );

    let outbounds = make_from_env(socks_host, socks_port).build_outbounds();

    // In sing-box 1.11+ we no longer need special outbounds (dns, block),
    // rule actions are used instead.

    // DNS configuration for sing-box 1.12+:
    // use public DNS (8.8.8.8) over UDP – simpler than DoH and without loops.
    let mut dns_rules: Vec<serde_json::Value> = Vec::new();
    
    // Block unwanted DNS queries
    dns_rules.push(json!({ 
        "query_type": [32, 33], 
        "server": "dns-block",
        "disable_cache": true
    }));
    dns_rules.push(json!({ 
        "domain_suffix": [".lan"], 
        "server": "dns-block",
        "disable_cache": true
    }));

    // Build TUN inbound.
    //
    // General scheme:
    // - Windows / macOS: use a more conservative schema with `address` field
    // - Linux: move to modern sing-box schema with `inet4_address`,
    //   to be closer to nekoray and current documentation.
    // TUN inbound is the KEY decision to avoid multiple sudo prompts:
    // use auto_route: true BUT with gvisor stack.
    // gvisor performs routing in userspace, sing-box only creates the interface (one sudo prompt).
    let mut tun_inbound = json!({
        "type": "tun",
        "tag": "tun-in",
        "address": [ inet4 ],
        "mtu": cfg.mtu,
        "auto_route": true,
        "strict_route": true,
        "endpoint_independent_nat": true,
        "sniff": true,
        "sniff_override_destination": false,
        "stack": "gvisor"
    });
    #[cfg(not(target_os = "macos"))]
    {
        // Safe to set interface name on non-macOS platforms
        if let Some(obj) = tun_inbound.as_object_mut() {
            obj.insert("interface_name".to_string(), serde_json::Value::String(cfg.name.clone()));
        }
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS default to system stack; allow env overrides for stack and strict_route
        if let Some(obj) = tun_inbound.as_object_mut() {
            let stack = std::env::var("SB_TUN_STACK").unwrap_or_else(|_| "system".to_string());
            obj.insert("stack".to_string(), serde_json::Value::String(stack));
            // Default to strict_route=true to ensure full-route takeover; can relax via SB_STRICT_ROUTE=0/false
            let strict = std::env::var("SB_STRICT_ROUTE")
                .ok()
                .map(|v| {
                    let v = v.to_ascii_lowercase();
                    v == "1" || v == "true" || v == "yes" || v == "on"
                })
                .unwrap_or(true);
            obj.insert("strict_route".to_string(), serde_json::Value::Bool(strict));
            // Allow overriding interface name via env (off by default)
            if let Ok(ifn) = std::env::var("SB_TUN_IFACE_NAME") {
                if !ifn.is_empty() {
                    obj.insert("interface_name".to_string(), serde_json::Value::String(ifn));
                }
            }
        }
    }

    let mut inbounds: Vec<serde_json::Value> = vec![tun_inbound];
    if std::env::var("SINGBOX_ENABLE_MIXED").ok().as_deref() == Some("1") {
        let mixed_port: u16 = std::env::var("SINGBOX_MIXED_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(1081);
        log::info!("[SING-BOX][CONFIG] Enabling mixed inbound on 127.0.0.1:{mixed_port}");
        inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
            "sniff": true,
            "sniff_override_destination": false
        }));
    }

    let doc = json!({
        "log": { "level": sb_log_level, "timestamp": true },
        "inbounds": inbounds,
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    // IMPORTANT: force TCP DNS over the proxy to avoid UDP/53 and
                    // udp_over_tcp-on-SOCKS issues (which cause EOF in local ss-local).
                    "address": "tcp://8.8.8.8:53",
                    "detour": "proxy"
                },
                {
                    "tag": "dns-block",
                    "address": "rcode://success"
                }
            ],
            "rules": dns_rules,
            "final": "dns-remote"
        },
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": true,
            "final": "proxy",
            "rules": [
                // DNS hijack - intercept all DNS traffic through TUN
                { "protocol": "dns", "action": "hijack-dns" },
                // Local networks go directly
                { "ip_cidr": direct_cidrs, "outbound": "direct" },
                // Block noisy/garbage ports
                { "network": "udp", "port": [135,137,138,139,5353], "action": "reject" },
                { "ip_cidr": ["224.0.0.0/3","ff00::/8"], "action": "reject" },
                { "source_ip_cidr": ["224.0.0.0/3","ff00::/8"], "action": "reject" }
            ]
        }
    });

    let temp = std::env::temp_dir().join(format!("crabsock-singbox-{}.json", std::process::id()));
    std::fs::write(&temp, doc.to_string())
        .map_err(|e| anyhow::anyhow!(format!("write sing-box config failed: {}", e)))?;
    log::info!("[SING-BOX][CONFIG] Wrote config to {}", temp.display());
    Ok(temp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun_manager::TunConfig;
    use std::net::Ipv4Addr;

    #[test]
    fn build_config_with_socks_outbound_contains_expected_fields() {
        std::env::set_var("SB_OUTBOUND_TYPE", "socks");
        std::env::set_var("SINGBOX_ENABLE_MIXED", "0");
        let cfg = TunConfig { name: "crabsock0".into(), address: Ipv4Addr::new(172,19,0,1), netmask: Ipv4Addr::new(255,255,255,240), mtu: 1500 };
        let path = build_singbox_config(&cfg, "127.0.0.1".into(), 1080).expect("config");
        let text = std::fs::read_to_string(&path).expect("read");
        let v: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(v["inbounds"][0]["type"], "tun");
        assert_eq!(v["outbounds"][0]["type"], "socks");
        let _ = std::fs::remove_file(path);
        std::env::remove_var("SB_OUTBOUND_TYPE");
        std::env::remove_var("SINGBOX_ENABLE_MIXED");
    }
}

