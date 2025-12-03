use anyhow::Result;
use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::io::ErrorKind;

fn host_matches_bypass(_host: &str) -> bool { false }

async fn resolve_addrs(host: &str, port: u16) -> Vec<std::net::SocketAddr> {
    let target = format!("{}:{}", host, port);
    match tokio::net::lookup_host(target).await {
        Ok(it) => it.collect(),
        Err(_) => vec![],
    }
}

fn ip_is_private(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip4) => {
            let o = ip4.octets();
            (o[0] == 10)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] >= 240)
        }
        std::net::IpAddr::V6(_ip6) => false,
    }
}

async fn should_bypass(host: &str, port: u16) -> bool {
    if host_matches_bypass(host) { return true; }
    for sa in resolve_addrs(host, port).await {
        if ip_is_private(&sa.ip()) { return true; }
    }
    // Best-effort: check if route uses utun/pritul via `route -n get` (macOS)
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("route").args(["-n", "get", host]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if text.contains("utun") || text.contains("pritunl") { return true; }
            }
        }
    }
    false
}

async fn socks5_connect_through(
    upstream_host: &str,
    upstream_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)).await?;
    let _ = s.set_nodelay(true);
    // greeting: version 5, 1 method, no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] { anyhow::bail!("SOCKS5 no-auth rejected"); }
    // CONNECT request with domain name
    let host_bytes = target_host.as_bytes();
    let mut req = Vec::with_capacity(5 + host_bytes.len() + 2);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await?;
    // read reply: VER REP RSV ATYP ...
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 { anyhow::bail!("SOCKS5 connect failed rep={}", head[1]); }
    // read BND.ADDR + BND.PORT
    let to_read = match head[3] { 0x01 => 4, 0x03 => { let mut l=[0u8;1]; s.read_exact(&mut l).await?; l[0] as usize }, 0x04 => 16, _ => 0 };
    if to_read > 0 { let mut buf = vec![0u8; to_read]; s.read_exact(&mut buf).await?; }
    let mut port_buf = [0u8; 2]; s.read_exact(&mut port_buf).await?;
    Ok(s)
}

async fn relay(mut a: TcpStream, mut b: TcpStream) -> Result<()> {
    let _ = a.set_nodelay(true);
    let _ = b.set_nodelay(true);
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok((_ab, _ba)) => {
            // Best-effort half-close on both ends
            let _ = a.shutdown().await;
            let _ = b.shutdown().await;
            Ok(())
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::NotConnected | ErrorKind::TimedOut => {
                    // Treat common hang-up conditions as normal termination
                    Ok(())
                }
                _ => Err(e.into()),
            }
        }
    }
}

pub async fn run_acl_http_proxy(bind_addr: &str, socks_upstream: (&str, u16)) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("ACL HTTP proxy listening on {}", bind_addr);
    loop {
        let (mut client, peer) = listener.accept().await?;
        let _ = client.set_nodelay(true);
        let (socks_host, socks_port) = (socks_upstream.0.to_string(), socks_upstream.1);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = match client.read(&mut buf).await { Ok(n) => n, Err(e) => { warn!("read err {}", e); return; } };
            if n == 0 { return; }
            let req = String::from_utf8_lossy(&buf[..n]);
            let mut lines = req.lines();
            let first = lines.next().unwrap_or("");
            // Expect CONNECT host:port HTTP/1.1
            let (method, rest) = match first.split_once(' ') { Some(v)=>v, None=>("", "") };
            if method != "CONNECT" {
                let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await;
                return;
            }
            let (hostport, _ver) = match rest.split_once(' ') { Some(v)=>v, None=>("", "") };
            let (host, port) = match hostport.rsplit_once(':') { Some((h,p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)), None => (hostport.to_string(), 443) };

            info!("CONNECT {}:{} from {}", host, port, peer);
            let use_direct = should_bypass(&host, port).await;
            let upstream = if use_direct {
                match TcpStream::connect(format!("{}:{}", host, port)).await { Ok(s)=>s, Err(e)=>{ let _=client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await; warn!("direct conn failed: {}", e); return; } }
            } else {
                match socks5_connect_through(&socks_host, socks_port, &host, port).await { Ok(s)=>s, Err(e)=>{ let _=client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await; warn!("socks conn failed: {}", e); return; } }
            };

            if let Err(e) = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await { warn!("resp err {}", e); return; }
            if let Err(e) = relay(client, upstream).await { warn!("relay err {}", e); }
        });
    }
}


