use anyhow::Result;

pub struct NoopTun { is_running: bool }

impl NoopTun {
    pub fn new() -> Self { Self { is_running: false } }
    pub async fn start(&mut self) -> Result<()> { self.is_running = true; Ok(()) }
    pub async fn stop(&mut self) -> Result<()> { self.is_running = false; Ok(()) }
    pub fn is_running(&self) -> bool { self.is_running }
}

