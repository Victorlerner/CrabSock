use anyhow::Result;

use super::backend::TunBackend;

#[cfg(target_os = "linux")]
use super::linux_singbox_backend::LinuxSingBoxTun;
#[cfg(target_os = "windows")]
use super::windows_singbox_backend::WindowsSingBoxTun;
#[cfg(target_os = "macos")]
use super::macos_singbox_backend::MacosSingBoxTun;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use super::noop_backend::NoopTun;

pub struct TunBackendFactory;

impl TunBackendFactory {
    pub fn make() -> Box<dyn TunBackend> {
        #[cfg(target_os = "linux")]
        { return Box::new(LinuxTunAdapter::default()); }
        #[cfg(target_os = "windows")]
        { return Box::new(WindowsTunAdapter::default()); }
        #[cfg(target_os = "macos")]
        { return Box::new(MacTunAdapter::default()); }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        { return Box::new(NoopTunAdapter::default()); }
    }
}

#[cfg(target_os = "linux")]
struct LinuxTunAdapter(LinuxSingBoxTun);
#[cfg(target_os = "linux")]
impl Default for LinuxTunAdapter { fn default() -> Self { LinuxTunAdapter(LinuxSingBoxTun::new()) } }
#[cfg(target_os = "linux")]
impl TunBackend for LinuxTunAdapter {
    fn start<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.start()) }
    fn stop<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.stop()) }
    fn is_running(&self) -> bool { self.0.is_running() }
}

#[cfg(target_os = "windows")]
struct WindowsTunAdapter(WindowsSingBoxTun);
#[cfg(target_os = "windows")]
impl Default for WindowsTunAdapter { fn default() -> Self { WindowsTunAdapter(WindowsSingBoxTun::new()) } }
#[cfg(target_os = "windows")]
impl TunBackend for WindowsTunAdapter {
    fn start<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.start()) }
    fn stop<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.stop()) }
    fn is_running(&self) -> bool { self.0.is_running() }
}

#[cfg(target_os = "macos")]
struct MacTunAdapter(MacosSingBoxTun);
#[cfg(target_os = "macos")]
impl Default for MacTunAdapter { fn default() -> Self { MacTunAdapter(MacosSingBoxTun::new()) } }
#[cfg(target_os = "macos")]
impl TunBackend for MacTunAdapter {
    fn start<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.start()) }
    fn stop<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.stop()) }
    fn is_running(&self) -> bool { self.0.is_running() }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
struct NoopTunAdapter(NoopTun);
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl Default for NoopTunAdapter { fn default() -> Self { NoopTunAdapter(NoopTun::new()) } }
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl TunBackend for NoopTunAdapter {
    fn start<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.start()) }
    fn stop<'a>(&'a mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> { Box::pin(self.0.stop()) }
    fn is_running(&self) -> bool { self.0.is_running() }
}

