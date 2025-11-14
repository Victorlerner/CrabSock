pub mod backend;
pub mod backend_factory;
#[cfg(target_os = "linux")]
pub mod linux_backend;
#[cfg(target_os = "linux")]
pub mod linux_singbox_backend;
#[cfg(target_os = "windows")]
pub mod windows_singbox_backend;
#[cfg(target_os = "macos")]
pub mod macos_singbox_backend;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub mod noop_backend;

