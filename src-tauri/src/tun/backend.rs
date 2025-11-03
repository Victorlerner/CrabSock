use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub trait TunBackend: Send {
    fn start<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn stop<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn is_running(&self) -> bool;
}

