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
