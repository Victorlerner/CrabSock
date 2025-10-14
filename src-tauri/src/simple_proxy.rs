use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use log::info;
use tokio::time::{timeout, Duration};

pub struct SimpleSocks5Proxy {
    local_addr: SocketAddr,
    remote_server: String,
    remote_port: u16,
}

impl SimpleSocks5Proxy {
    pub fn new(local_addr: SocketAddr, remote_server: String, remote_port: u16) -> Self {
        Self {
            local_addr,
            remote_server,
            remote_port,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.local_addr).await?;
        info!("SOCKS5 proxy listening on {}", self.local_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New connection from {}", addr);
                    
                    // Обрабатываем каждое соединение в отдельной задаче
                    let remote_server = self.remote_server.clone();
                    let remote_port = self.remote_port;
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, remote_server, remote_port).await {
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

    async fn handle_client(mut client: TcpStream, remote_server: String, remote_port: u16) -> Result<()> {
        // Устанавливаем таймаут для handshake
        let handshake_timeout = Duration::from_secs(10);
        
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
        let (target_addr, target_port) = Self::parse_address(&buffer[3..n])?;
        
        info!("Connecting to {}:{}", target_addr, target_port);

        // Подключаемся к удаленному серверу через Shadowsocks с таймаутом
        let remote_addr = format!("{}:{}", remote_server, remote_port);
        let connect_timeout = Duration::from_secs(30);
        let mut remote = timeout(connect_timeout, TcpStream::connect(&remote_addr)).await??;
        
        // Отвечаем клиенту об успешном подключении
        let response = [
            0x05, 0x00, 0x00, 0x01, // SOCKS5, SUCCESS, RSV, IPv4
            0x00, 0x00, 0x00, 0x00, // IP: 0.0.0.0
            0x00, 0x00,             // Port: 0
        ];
        client.write_all(&response).await?;

        // Начинаем проксирование данных
        Self::proxy_data(&mut client, &mut remote).await?;

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

    async fn proxy_data(client: &mut TcpStream, remote: &mut TcpStream) -> Result<()> {
        use tokio::io::AsyncReadExt;
        
        let (mut client_read, mut client_write) = client.split();
        let (mut remote_read, mut remote_write) = remote.split();

        // Увеличиваем размер буфера для лучшей производительности
        let buffer_size = 64 * 1024; // 64KB буфер

        // Проксируем данные в обе стороны
        let client_to_remote = async {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                let n = client_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                remote_write.write_all(&buffer[..n]).await?;
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
                client_write.write_all(&buffer[..n]).await?;
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
