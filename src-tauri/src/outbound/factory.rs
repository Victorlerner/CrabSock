use super::strategy::OutboundStrategy;
use super::{shadowsocks::ShadowsocksStrategy, socks::SocksStrategy, vless::VlessStrategy};

pub enum OutboundKind {
    Socks,
    Vless,
    Shadowsocks,
}

pub fn make_from_env(socks_host: String, socks_port: u16) -> Box<dyn OutboundStrategy> {
    let outbound_type = std::env::var("SB_OUTBOUND_TYPE").unwrap_or_else(|_| "socks".to_string());
    match outbound_type.as_str() {
        "vless" => Box::new(VlessStrategy),
        "shadowsocks" => Box::new(ShadowsocksStrategy),
        _ => Box::new(SocksStrategy { server: socks_host, port: socks_port }),
    }
}

