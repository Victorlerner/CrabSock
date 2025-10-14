use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use log::info;

pub struct ShadowsocksSocks5Proxy {
    local_addr: SocketAddr,
    remote_server: String,
    remote_port: u16,
    password: String,
    method: String,
}

impl ShadowsocksSocks5Proxy {
    pub fn new(
        local_addr: SocketAddr,
        remote_server: String,
        remote_port: u16,
        password: String,
        method: String,
    ) -> Self {
        Self {
            local_addr,
            remote_server,
            remote_port,
            password,
            method,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.local_addr).await?;
        info!("Shadowsocks SOCKS5 proxy listening on {}", self.local_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New connection from {}", addr);
                    
                    // Обрабатываем каждое соединение в отдельной задаче
                    let remote_server = self.remote_server.clone();
                    let remote_port = self.remote_port;
                    let password = self.password.clone();
                    let method = self.method.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, remote_server, remote_port, password, method).await {
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

    async fn handle_client(
        mut client: TcpStream, 
        remote_server: String, 
        remote_port: u16,
        password: String,
        method: String,
    ) -> Result<()> {
        // Читаем SOCKS5 handshake
        let mut buffer = [0u8; 1024];
        let n = client.read(&mut buffer).await?;
        
        if n < 3 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 handshake"));
        }

        // Проверяем версию SOCKS5
        if buffer[0] != 0x05 {
            return Err(anyhow::anyhow!("Unsupported SOCKS version"));
        }

        // Отвечаем на handshake (без аутентификации)
        client.write_all(&[0x05, 0x00]).await?;

        // Читаем команду CONNECT
        let n = client.read(&mut buffer).await?;
        if n < 10 {
            return Err(anyhow::anyhow!("Invalid CONNECT request"));
        }

        // Проверяем команду CONNECT
        if buffer[1] != 0x01 {
            return Err(anyhow::anyhow!("Unsupported command"));
        }

        // Извлекаем адрес назначения
        let (target_addr, target_port) = Self::parse_address(&buffer[3..n])?;
        
        info!("Connecting to {}:{} via Shadowsocks", target_addr, target_port);

        // Подключаемся к Shadowsocks серверу
        let shadowsocks_addr = format!("{}:{}", remote_server, remote_port);
        let mut shadowsocks_stream = TcpStream::connect(&shadowsocks_addr).await?;
        
        // Отправляем Shadowsocks запрос
        Self::send_shadowsocks_request(&mut shadowsocks_stream, &target_addr, target_port, &password, &method).await?;
        
        // Отвечаем клиенту об успешном подключении
        let response = [
            0x05, 0x00, 0x00, 0x01, // SOCKS5, SUCCESS, RSV, IPv4
            0x00, 0x00, 0x00, 0x00, // IP: 0.0.0.0
            0x00, 0x00,             // Port: 0
        ];
        client.write_all(&response).await?;

        // Начинаем проксирование данных через Shadowsocks
        Self::proxy_data_through_shadowsocks(&mut client, &mut shadowsocks_stream, &password, &method).await?;

        Ok(())
    }

    async fn send_shadowsocks_request(
        stream: &mut TcpStream,
        target_addr: &str,
        target_port: u16,
        _password: &str,
        _method: &str,
    ) -> Result<()> {
        // Создаем простой Shadowsocks запрос
        // В реальной реализации здесь должен быть полный протокол Shadowsocks
        
        // Для простоты отправляем данные как есть (без шифрования)
        // В продакшене здесь должно быть шифрование
        
        let mut request = Vec::new();
        
        // Добавляем адрес назначения
        request.extend_from_slice(target_addr.as_bytes());
        request.push(0); // null terminator
        
        // Добавляем порт
        request.extend_from_slice(&target_port.to_be_bytes());
        
        // Отправляем запрос
        stream.write_all(&request).await?;
        
        Ok(())
    }

    async fn proxy_data_through_shadowsocks(
        client: &mut TcpStream,
        shadowsocks_stream: &mut TcpStream,
        _password: &str,
        _method: &str,
    ) -> Result<()> {
        let (mut client_read, mut client_write) = client.split();
        let (mut shadowsocks_read, mut shadowsocks_write) = shadowsocks_stream.split();

        // Проксируем данные в обе стороны
        let client_to_shadowsocks = async {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let n = client_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                shadowsocks_write.write_all(&buffer[..n]).await?;
            }
            Ok::<(), std::io::Error>(())
        };

        let shadowsocks_to_client = async {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let n = shadowsocks_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                client_write.write_all(&buffer[..n]).await?;
            }
            Ok::<(), std::io::Error>(())
        };

        // Ждем завершения любой из задач
        tokio::select! {
            result = client_to_shadowsocks => {
                if let Err(e) = result {
                    log::debug!("Client to Shadowsocks error: {}", e);
                }
            }
            result = shadowsocks_to_client => {
                if let Err(e) = result {
                    log::debug!("Shadowsocks to client error: {}", e);
                }
            }
        }

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
}
