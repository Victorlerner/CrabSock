use anyhow::Result;
use futures_util::TryStreamExt;
use ipnetwork::Ipv4Network;
use rtnetlink::new_connection;
use std::net::{IpAddr, Ipv4Addr};
use tun_tap::{Iface, Mode};

use crate::linux_capabilities::has_cap_net_admin;
use crate::tun_manager::TunConfig;

pub struct LinuxTun {
    iface: Option<Iface>,
    config: TunConfig,
    is_running: bool,
}

impl LinuxTun {
    pub fn new() -> Self { Self { iface: None, config: TunConfig::default(), is_running: false } }

    pub async fn start(&mut self) -> Result<()> {
        if self.is_running { log::warn!("[TUN] Already running"); return Ok(()); }
        log::info!("[TUN] Starting TUN interface: {}", self.config.name);
        println!("[STDOUT] TUN: Attempting to create TUN interface: {}", self.config.name);
        if !has_cap_net_admin() {
            println!("[STDOUT] TUN: No permissions to create TUN interface");
            return Err(anyhow::anyhow!("Insufficient permissions to create TUN interface"));
        }
        self.cleanup_existing_interface().await?;
        let iface = Iface::new(&self.config.name, Mode::Tun).map_err(|e| {
            println!("[STDOUT] TUN: Failed to create TUN interface: {}", e);
            anyhow::anyhow!("Failed to create TUN interface: {}", e)
        })?;
        println!("[STDOUT] TUN: TUN interface created successfully");
        self.iface = Some(iface);
        self.configure_tun_interface().await?;
        self.is_running = true;
        log::info!("[TUN] TUN interface started successfully (monitoring mode)");
        println!("[STDOUT] TUN: TUN interface started successfully (monitoring mode)");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running { log::warn!("[TUN] Not running"); return Ok(()); }
        log::info!("[TUN] Stopping TUN interface");
        self.clear_routes().await?;
        if let Some(iface) = self.iface.take() { drop(iface); }
        self.is_running = false;
        log::info!("[TUN] TUN interface stopped");
        Ok(())
    }

    async fn cleanup_existing_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        if !has_cap_net_admin() { log::debug!("[TUN] No cap_net_admin, skip cleanup"); return Ok(()); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => {
                    let index = msg.header.index;
                    let _ = handle.link().del(index).execute().await;
                    log::info!("[TUN] Removed existing interface: {}", interface_name);
                }
                _ => break,
            }
        }
        Ok(())
    }

    async fn configure_tun_interface(&self) -> Result<()> {
        let interface_name = &self.config.name;
        let address = self.config.address;
        log::info!("[TUN] Configuring interface {} with IP {}/{}", interface_name, address, self.get_cidr_prefix());
        if !has_cap_net_admin() { return Err(anyhow::anyhow!("Insufficient permissions to configure TUN (cap_net_admin missing)")); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        let mut maybe_index: Option<u32> = None;
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => { maybe_index = Some(msg.header.index); break; }
                _ => break,
            }
        }
        let index = maybe_index.ok_or_else(|| anyhow::anyhow!("Interface not found after creation"))?;
        handle.link().set(index).up().execute().await?;
        let cidr = Ipv4Network::new(address, self.get_cidr_prefix()).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        handle.address().add(index, IpAddr::V4(cidr.ip()), cidr.prefix()).execute().await?;
        Ok(())
    }

    async fn clear_routes(&self) -> Result<()> {
        let interface_name = &self.config.name;
        log::info!("[TUN] Clearing routes");
        if !has_cap_net_admin() { log::debug!("[TUN] No cap_net_admin, skip clear routes"); return Ok(()); }
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        loop {
            match links.try_next().await {
                Ok(Some(msg)) => {
                    let index = msg.header.index;
                    let _ = handle.link().del(index).execute().await;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn get_cidr_prefix(&self) -> u8 {
        let mask = u32::from(self.config.netmask);
        mask.count_ones() as u8
    }

    pub fn is_running(&self) -> bool { self.is_running }
}

