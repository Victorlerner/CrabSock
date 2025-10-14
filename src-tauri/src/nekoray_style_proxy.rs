use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use log::info;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct NekorayStyleProxy {
    local_addr: SocketAddr,
    remote_server: String,
    remote_port: u16,
    max_connections: usize,
    buffer_size: usize,
    udp_fragment: bool,
}

impl NekorayStyleProxy {
    pub fn new(local_addr: SocketAddr, remote_server: String, remote_port: u16) -> Self {
        Self {
            local_addr,
            remote_server,
            remote_port,
            max_connections: 5000, // Больше соединений как в nekoray
            buffer_size: 512 * 1024, // 512KB буфер для максимальной производительности
            udp_fragment: true, // UDP фрагментация как в nekoray
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.local_addr).await?;
        info!("Nekoray-style proxy listening on {}", self.local_addr);
        info!("Max connections: {}, Buffer size: {}KB, UDP fragment: {}", 
               self.max_connections, self.buffer_size / 1024, self.udp_fragment);

        // Создаем семафор для ограничения количества одновременных соединений
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let remote_server = Arc::new(self.remote_server.clone());
        let remote_port = self.remote_port;
        let buffer_size = self.buffer_size;
        let udp_fragment = self.udp_fragment;

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let semaphore = semaphore.clone();
                    let remote_server = remote_server.clone();
                    
                    tokio::spawn(async move {
                        // Получаем разрешение на обработку соединения
                        let _permit = match semaphore.acquire().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                log::warn!("Too many connections, dropping {}", addr);
                                return;
                            }
                        };

                        if let Err(e) = Self::handle_client_nekoray_style(
                            stream, 
                            remote_server.as_str(), 
                            remote_port, 
                            buffer_size,
                            udp_fragment
                        ).await {
                            log::debug!("Error handling client {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_client_nekoray_style(
        mut client: TcpStream, 
        remote_server: &str, 
        remote_port: u16,
        buffer_size: usize,
        udp_fragment: bool
    ) -> Result<()> {
        // Устанавливаем TCP_NODELAY для уменьшения задержки
        if let Err(e) = client.set_nodelay(true) {
            log::debug!("Failed to set TCP_NODELAY: {}", e);
        }
        
        // Устанавливаем TCP_CORK для лучшей группировки пакетов (Linux)
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = client.as_raw_fd();
                let cork: libc::c_int = 1;
                if libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CORK, 
                    &cork as *const _ as *const libc::c_void, 
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t) != 0 {
                    log::debug!("Failed to set TCP_CORK");
                }
            }
        }

        // Устанавливаем таймаут для handshake (быстрее как в nekoray)
        let handshake_timeout = Duration::from_secs(3); // Еще быстрее

        // Читаем SOCKS5 handshake с таймаутом
        let mut buffer = [0u8; 1024];
        let n = timeout(handshake_timeout, client.read(&mut buffer)).await??;

        if n < 3 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 handshake"));
        }

        // Проверяем версию SOCKS5
        if buffer[0] != 0x05 {
            return Err(anyhow::anyhow!("Unsupported SOCKS version"));
        }

        // Отвечаем на handshake (без аутентификации)
        client.write_all(&[0x05, 0x00]).await?;

        // Читаем команду CONNECT с таймаутом
        let n = timeout(handshake_timeout, client.read(&mut buffer)).await??;
        if n < 10 {
            return Err(anyhow::anyhow!("Invalid CONNECT request"));
        }

        // Проверяем команду CONNECT
        if buffer[1] != 0x01 {
            return Err(anyhow::anyhow!("Unsupported command"));
        }

        // Извлекаем адрес назначения
        let (_target_addr, _target_port) = Self::parse_address(&buffer[3..n])?;

        // Подключаемся к удаленному серверу через Shadowsocks с таймаутом
        let remote_addr = format!("{}:{}", remote_server, remote_port);
        let connect_timeout = Duration::from_secs(5); // Быстрее подключение
        
        let mut remote = timeout(connect_timeout, TcpStream::connect(&remote_addr)).await??;
        
        // Устанавливаем TCP_NODELAY для удаленного соединения
        if let Err(e) = remote.set_nodelay(true) {
            log::debug!("Failed to set TCP_NODELAY on remote: {}", e);
        }
        
        // Устанавливаем TCP_CORK для удаленного соединения (Linux)
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = remote.as_raw_fd();
                let cork: libc::c_int = 1;
                if libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CORK, 
                    &cork as *const _ as *const libc::c_void, 
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t) != 0 {
                    log::debug!("Failed to set TCP_CORK on remote");
                }
            }
        }

        // Отвечаем клиенту об успешном подключении
        let response = [
            0x05, 0x00, 0x00, 0x01, // SOCKS5, SUCCESS, RSV, IPv4
            0x00, 0x00, 0x00, 0x00, // IP: 0.0.0.0
            0x00, 0x00,             // Port: 0
        ];
        client.write_all(&response).await?;

        // Начинаем оптимизированное проксирование данных в стиле nekoray
        Self::proxy_data_nekoray_style(&mut client, &mut remote, buffer_size, udp_fragment).await?;

        Ok(())
    }

    fn parse_address(data: &[u8]) -> Result<(String, u16)> {
        if data.len() < 4 {
            return Err(anyhow::anyhow!("Invalid address data"));
        }

        match data[0] {
            0x01 => {
                // IPv4
                if data.len() < 7 {
                    return Err(anyhow::anyhow!("Invalid IPv4 address"));
                }
                let ip = format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((ip, port))
            }
            0x03 => {
                // Domain name
                let len = data[1] as usize;
                if data.len() < len + 4 {
                    return Err(anyhow::anyhow!("Invalid domain name"));
                }
                let domain = String::from_utf8(data[2..2+len].to_vec())?;
                let port = u16::from_be_bytes([data[2+len], data[3+len]]);
                Ok((domain, port))
            }
            _ => Err(anyhow::anyhow!("Unsupported address type"))
        }
    }

    async fn proxy_data_nekoray_style(
        client: &mut TcpStream, 
        remote: &mut TcpStream, 
        buffer_size: usize,
        udp_fragment: bool
    ) -> Result<()> {
        let (mut client_read, mut client_write) = client.split();
        let (mut remote_read, mut remote_write) = remote.split();

        // Используем максимальные буферы для лучшей производительности
        let client_to_remote = async {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                let n = client_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                
                // UDP фрагментация как в nekoray
                if udp_fragment && n > 1500 {
                    // Разбиваем большие пакеты на фрагменты
                    for chunk in buffer[..n].chunks(1500) {
                        remote_write.write_all(chunk).await?;
                    }
                } else {
                    remote_write.write_all(&buffer[..n]).await?;
                }
            }
            Ok::<(), std::io::Error>(())
        };

        let remote_to_client = async {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                let n = remote_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                
                // UDP фрагментация как в nekoray
                if udp_fragment && n > 1500 {
                    // Разбиваем большие пакеты на фрагменты
                    for chunk in buffer[..n].chunks(1500) {
                        client_write.write_all(chunk).await?;
                    }
                } else {
                    client_write.write_all(&buffer[..n]).await?;
                }
            }
            Ok::<(), std::io::Error>(())
        };

        // Ждем завершения любой из задач
        tokio::select! {
            result = client_to_remote => {
                if let Err(e) = result {
                    log::debug!("Client to remote error: {}", e);
                }
            }
            result = remote_to_client => {
                if let Err(e) = result {
                    log::debug!("Remote to client error: {}", e);
                }
            }
        }

        Ok(())
    }
}




