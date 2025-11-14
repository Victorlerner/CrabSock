use anyhow::Result;
use serde_json::json;
use std::path::PathBuf;

use crate::tun_manager::TunConfig;
use crate::outbound::factory::make_from_env;

pub fn build_singbox_config(cfg: &TunConfig, socks_host: String, socks_port: u16) -> Result<PathBuf> {
    use std::net::{IpAddr, ToSocketAddrs};

    // Для Linux по умолчанию уменьшаем уровень логов sing-box до "warn",
    // на других платформах оставляем "info". Всегда можно переопределить SB_LOG_LEVEL.
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
    
    // В sing-box 1.11+ не нужны специальные outbounds (dns, block),
    // вместо них используются rule actions

    // DNS Configuration для sing-box 1.12+
    // Используем публичные DNS (8.8.8.8) через UDP - проще чем DoH и без петель
    let mut dns_rules: Vec<serde_json::Value> = Vec::new();
    
    // Блокируем мусорные запросы
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
    // Общая схема:
    // - Windows / macOS: используем более консервативную схему с полем `address`
    // - Linux: переходим на современную схему sing-box с `inet4_address`,
    //   чтобы быть ближе к nekoray и актуальной документации.
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
        // On macOS prefer system stack and relaxed strict_route (some setups fail to apply default route with gVisor)
        if let Some(obj) = tun_inbound.as_object_mut() {
            obj.insert("stack".to_string(), serde_json::Value::String("system".to_string()));
            obj.insert("strict_route".to_string(), serde_json::Value::Bool(false));
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
                    "address": "8.8.8.8"
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
                // DNS hijack - перехватываем все DNS запросы через TUN
                { "protocol": "dns", "action": "hijack-dns" },
                // Локальные сети напрямую
                { "ip_cidr": direct_cidrs, "outbound": "direct" },
                // Блокируем мусорные порты
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

