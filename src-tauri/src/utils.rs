pub fn init_logging() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        // suppress noisy netlink warnings on newer kernels
        .filter_module("netlink_packet_route", log::LevelFilter::Error)
        .filter_module("rtnetlink", log::LevelFilter::Error)
        // reduce socks server transient disconnect errors during shutdown
        .filter_module("shadowsocks_service::local::socks::server::server", log::LevelFilter::Warn)
        .init();
}

/// Ensure ACL_HTTP_PORT is initialized and return its value.
///
/// Priority:
/// 1) Respect existing ACL_HTTP_PORT if it is a valid u16 *and* the port is free on 127.0.0.1.
/// 2) Otherwise, try to bind the first free port in [2081, 2081+RANGE_LEN) on 127.0.0.1.
///    The selected port is written back to ACL_HTTP_PORT for reuse across the app.
/// 3) Fallback to 2081 if nothing worked (extremely unlikely).
pub fn ensure_acl_http_port_initialized() -> u16 {
    use std::net::TcpListener;

    const PREFERRED_START: u16 = 2081;
    const RANGE_LEN: u16 = 32;

    // 1) Respect explicit environment override, but verify that port is free.
    if let Ok(val) = std::env::var("ACL_HTTP_PORT") {
        if let Ok(port) = val.parse::<u16>() {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                // Port is free — release it immediately and use this value.
                drop(listener);
                log::info!("[ACL_HTTP] Using pre-configured ACL_HTTP_PORT={}", port);
                return port;
            } else {
                log::warn!(
                    "[ACL_HTTP] Pre-configured ACL_HTTP_PORT={} is not available on 127.0.0.1; falling back to automatic selection",
                    port
                );
            }
        }
    }

    // 2) Try to find a free port in the preferred range and persist it.
    for offset in 0..RANGE_LEN {
        let port = PREFERRED_START.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            std::env::set_var("ACL_HTTP_PORT", port.to_string());
            log::info!("[ACL_HTTP] Selected ACL HTTP port {}", port);
            return port;
        }
    }

    // 3) Last resort – return the default start without binding.
    log::warn!(
        "[ACL_HTTP] Failed to find free ACL HTTP port in range {}-{}; falling back to {}",
        PREFERRED_START,
        PREFERRED_START.saturating_add(RANGE_LEN),
        PREFERRED_START
    );
    PREFERRED_START
}
