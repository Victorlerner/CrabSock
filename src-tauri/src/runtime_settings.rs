use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct TunSettings {
    pub interface_name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl TunSettings {
    pub fn inet4_cidr(&self) -> String { format!("{}/{}", self.address, u32::from(self.netmask).count_ones()) }
}

#[derive(Clone, Copy)]
pub enum OutboundKind { Socks, Vless, Shadowsocks }

#[derive(Clone)]
pub struct OutboundSettings { pub kind: OutboundKind }

#[derive(Clone)]
pub struct RuntimeSettings {
    pub tun: TunSettings,
    pub outbound: OutboundSettings,
    pub log_level: String,
}

impl RuntimeSettings {
    pub fn from_env() -> Self {
        let tun = TunSettings {
            interface_name: std::env::var("TUN_IFACE").unwrap_or_else(|_| "crabsock0".into()),
            address: std::env::var("TUN_ADDRESS").ok().and_then(|s| s.parse().ok()).unwrap_or(Ipv4Addr::new(172, 19, 0, 1)),
            netmask: std::env::var("TUN_NETMASK").ok().and_then(|s| s.parse().ok()).unwrap_or(Ipv4Addr::new(255, 255, 255, 240)),
            mtu: std::env::var("TUN_MTU").ok().and_then(|s| s.parse().ok()).unwrap_or(1500),
        };
        let outbound_kind = match std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".into()).as_str() {
            "vless" => OutboundKind::Vless,
            "shadowsocks" => OutboundKind::Shadowsocks,
            _ => OutboundKind::Socks,
        };
        let outbound = OutboundSettings { kind: outbound_kind };
        let log_level = std::env::var("SINGBOX_LOG_LEVEL").unwrap_or_else(|_| "warn".into());
        Self { tun, outbound, log_level }
    }
}

