use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Run the SOCKS5 proxy. If `tls` is Some((cert_path, key_path)) the proxy will accept
/// TLS on the client side (client -> proxy TLS) using rustls. TLS support is feature-gated
/// behind the `tls` Cargo feature.
pub async fn run(listen: &str, tls: Option<(String, String)>, auth: Option<(String, String)>) -> Result<()> {
    if tls.is_some() && !cfg!(feature = "tls") {
        return Err(anyhow!("compiled without TLS support; rebuild with `--features tls`"));
    }

    #[cfg(feature = "tls")]
    let acceptor = if let Some((cert_path, key_path)) = tls {
        Some(build_tls_acceptor(&cert_path, &key_path)?)
    } else {
        None
    };

    // For normal run, bind and run accept loop
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind to {}", listen))?;

    info!(%listen, "SOCKS5 proxy listening");

    accept_loop(listener, acceptor, auth).await
}

/// Start the server in background and return the bound socket address and JoinHandle.
/// Useful for tests.
pub async fn start_background(listen: &str, tls: Option<(String, String)>, auth: Option<(String, String)>) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    if tls.is_some() && !cfg!(feature = "tls") {
        return Err(anyhow!("compiled without TLS support; rebuild with `--features tls`"));
    }

    #[cfg(feature = "tls")]
    let acceptor = if let Some((cert_path, key_path)) = tls {
        Some(build_tls_acceptor(&cert_path, &key_path)?)
    } else {
        None
    };

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind to {}", listen))?;

    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        if let Err(e) = accept_loop(listener, acceptor, auth).await {
            tracing::warn!(error = %e, "accept loop terminated");
        }
    });

    Ok((addr, handle))
}

async fn accept_loop(
    listener: TcpListener,
    #[allow(unused_variables)]
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    auth: Option<(String, String)>,
) -> Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        info!(%peer, "accepted connection");
        #[cfg(feature = "tls")]
        let acceptor = acceptor.clone();

        let auth = auth.clone();

        tokio::spawn(async move {
            let res = async {
                #[cfg(feature = "tls")]
                {
                    if let Some(acceptor) = acceptor {
                        // perform TLS handshake
                        match acceptor.accept(socket).await {
                            Ok(stream) => handle_client(stream, auth).await,
                            Err(e) => {
                                warn!(%peer, error = %e, "tls handshake failed");
                                Err(anyhow!("tls handshake failed: {}", e))
                            }
                        }
                    } else {
                        handle_client(socket, auth).await
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    // tls feature not enabled
                    handle_client(socket, auth).await
                }
            }
            .await;

            if let Err(e) = res {
                warn!(%peer, error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_client<S>(mut socket: S, auth: Option<(String, String)>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1) Negotiation
    let ver = socket.read_u8().await?;
    if ver != 0x05 {
        return Err(anyhow!("unsupported socks version: {}", ver));
    }

    let nmethods = socket.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    debug!(?methods, "methods from client");

    // pick method: if auth is configured and client supports user/pass (0x02) use it,
    // otherwise if client supports NO AUTH (0x00) use that.
    let method = if auth.is_some() && methods.iter().any(|m| *m == 0x02) {
        0x02
    } else if methods.iter().any(|m| *m == 0x00) {
        0x00
    } else {
        0xff
    };

    socket.write_all(&[0x05, method]).await?;
    if method == 0xff {
        return Err(anyhow!("no acceptable auth methods"));
    }

    // If username/password required, perform subnegotiation (RFC 1929)
    if method == 0x02 {
        // version
        let v = socket.read_u8().await?;
        if v != 0x01 {
            // auth version must be 1
            socket.write_all(&[0x01, 0x01]).await?;
            return Err(anyhow!("invalid auth version: {}", v));
        }
        let ulen = socket.read_u8().await? as usize;
        let mut ubuf = vec![0u8; ulen];
        socket.read_exact(&mut ubuf).await?;
        let plen = socket.read_u8().await? as usize;
        let mut pbuf = vec![0u8; plen];
        socket.read_exact(&mut pbuf).await?;
        let uname = String::from_utf8(ubuf).map_err(|e| anyhow!(e))?;
        let pwd = String::from_utf8(pbuf).map_err(|e| anyhow!(e))?;

        if let Some((ref u, ref p)) = auth {
            if &uname == u && &pwd == p {
                socket.write_all(&[0x01, 0x00]).await?; // success
            } else {
                socket.write_all(&[0x01, 0x01]).await?; // failure
                return Err(anyhow!("authentication failed"));
            }
        } else {
            socket.write_all(&[0x01, 0x01]).await?; // no auth configured -> failure
            return Err(anyhow!("authentication required but not configured"));
        }
    }

    // 2) Request
    let ver = socket.read_u8().await?;
    if ver != 0x05 {
        return Err(anyhow!("unsupported request version: {}", ver));
    }

    let cmd = socket.read_u8().await?;
    let _rsv = socket.read_u8().await?;
    let atyp = socket.read_u8().await?;

    // If UDP ASSOCIATE (0x03) we need to create a UDP relay socket and return its
    // address as the bound address in the reply.
    if cmd == 0x03 {
        // Currently support IPv4/IPv6/domain for client's supplied DST (ignored by us)
        // Create UDP socket and spawn relay task
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = udp_socket.local_addr()?;

        // reply success with BND.ADDR = local_addr
        match local_addr {
            std::net::SocketAddr::V4(sa) => {
                let ip = sa.ip().octets();
                let port = sa.port().to_be_bytes();
                let mut resp = vec![0x05u8, 0x00, 0x00, 0x01];
                resp.extend_from_slice(&ip);
                resp.extend_from_slice(&port);
                socket.write_all(&resp).await?;
            }
            std::net::SocketAddr::V6(sa) => {
                let ip = sa.ip().octets();
                let port = sa.port().to_be_bytes();
                let mut resp = vec![0x05u8, 0x00, 0x00, 0x04];
                resp.extend_from_slice(&ip);
                resp.extend_from_slice(&port);
                socket.write_all(&resp).await?;
            }
        }

        // Spawn UDP relay task. It will forward between client UDP peer and remote destinations
        tokio::spawn(async move {
            if let Err(e) = udp_relay(udp_socket).await {
                tracing::warn!(error = %e, "udp relay failed");
            }
        });

        // Keep TCP connection open until client closes it
        let mut buf = [0u8; 1];
        // Read until EOF or error - basically keep the TCP connection alive
        let _ = socket.read(&mut buf).await;

        return Ok(());
    }

    let dest = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            let port = socket.read_u16().await?;
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::from(addr)), port)
        }
        0x03 => {
            // domain
            let len = socket.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            socket.read_exact(&mut buf).await?;
            let host = String::from_utf8(buf).map_err(|e| anyhow!(e))?;
            let port = socket.read_u16().await?;
            let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no address found for host"))?
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            let port = socket.read_u16().await?;
            SocketAddr::new(std::net::IpAddr::from(addr), port)
        }
        _ => return Err(anyhow!("unsupported addr type: {}", atyp)),
    };

    if cmd != 0x01 {
        // only support CONNECT now
        // reply: command not supported (0x07)
        socket
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(anyhow!("only CONNECT supported"));
    }

    info!(%dest, "CONNECT request");

    // try connect to destination
    match TcpStream::connect(dest).await {
        Ok(mut upstream) => {
            // reply success. For BND.ADDR and PORT we can return 0.0.0.0:0
            let resp = [0x05u8, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            socket.write_all(&resp).await?;

            // proxy data both ways
            match tokio::io::copy_bidirectional(&mut socket, &mut upstream).await {
                Ok((_a, _b)) => {
                    debug!("connection closed");
                }
                Err(e) => {
                    warn!(error = %e, "proxy IO error");
                }
            }

            // Ensure sockets are shutdown cleanly
            let _ = socket.shutdown().await;
            let _ = upstream.shutdown().await;
        }
        Err(e) => {
            warn!(error = %e, %dest, "failed to connect to destination");
            // general failure reply: 0x01
            let resp = [0x05u8, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            socket.write_all(&resp).await?;
            return Err(anyhow!("connect error: {}", e));
        }
    }

    Ok(())
}

#[cfg(feature = "tls")]
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use std::fs::File;
    use std::io::BufReader;

    let certfile = File::open(cert_path).with_context(|| format!("failed to open cert file: {}", cert_path))?;
    let keyfile = File::open(key_path).with_context(|| format!("failed to open key file: {}", key_path))?;
    let mut certreader = BufReader::new(certfile);
    let mut keyreader = BufReader::new(keyfile);

    let certs = rustls_pemfile::certs(&mut certreader)
        .map_err(|_| anyhow!("failed to parse certs"))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    // prefer pkcs8, then rsa
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut keyreader)
        .map_err(|_| anyhow!("failed to parse private key"))?;

    if keys.is_empty() {
        // rewind and try rsa
        let keyfile = File::open(key_path)?;
        let mut keyreader = BufReader::new(keyfile);
        keys = rustls_pemfile::rsa_private_keys(&mut keyreader)
            .map_err(|_| anyhow!("failed to parse rsa private key"))?;
    }

    if keys.is_empty() {
        return Err(anyhow!("no private keys found in {}", key_path));
    }

    let key = PrivateKey(keys.remove(0));

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to build ServerConfig: {}", e))?;

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

async fn udp_relay(mut udp_socket: tokio::net::UdpSocket) -> Result<()> {
    use tokio::net::UdpSocket;

    // track client peer address (where to send replies)
    let mut client_peer: Option<std::net::SocketAddr> = None;
    let mut buf = vec![0u8; 65536];

    loop {
        let (n, src) = udp_socket.recv_from(&mut buf).await?;
        // Expected packet format: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
        if n < 4 {
            continue;
        }
        client_peer.get_or_insert(src);

        let rsv = &buf[0..2];
        let _frag = buf[2];
        let atyp = buf[3];

        if rsv != [0, 0] {
            continue;
        }

        let mut idx = 4;
        let dest = match atyp {
            0x01 => {
                if n < idx + 4 + 2 {
                    continue;
                }
                let ip = std::net::Ipv4Addr::new(buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]);
                idx += 4;
                let port = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
                idx += 2;
                std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            0x03 => {
                let len = buf[idx] as usize;
                idx += 1;
                if n < idx + len + 2 {
                    continue;
                }
                let host = match std::str::from_utf8(&buf[idx..idx + len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                };
                idx += len;
                let port = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
                idx += 2;
                // resolve
                match tokio::net::lookup_host((host.as_str(), port)).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => continue,
                    },
                    Err(_) => continue,
                }
            }
            0x04 => {
                if n < idx + 16 + 2 {
                    continue;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[idx..idx + 16]);
                idx += 16;
                let port = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
                idx += 2;
                std::net::SocketAddr::new(std::net::IpAddr::from(ip), port)
            }
            _ => continue,
        };

        let data = &buf[idx..n];

        // send to dest
        let _ = udp_socket.send_to(data, dest).await;

        // try to read response from dest and send back to client
        // We create a temporary socket to receive the response with a small timeout
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let _ = sock.send_to(data, dest).await;
        let mut resp_buf = [0u8; 65536];
        if let Ok((rn, _)) = tokio::time::timeout(std::time::Duration::from_millis(300), sock.recv_from(&mut resp_buf)).await {
            if let Ok((rn, _)) = rn {
                if let Some(client_addr) = client_peer {
                    // wrap response with UDP header
                    let mut packet = vec![0u8, 0u8, 0u8, 0x01];
                    if let std::net::SocketAddr::V4(sa) = dest {
                        packet.extend_from_slice(&sa.ip().octets());
                        packet.extend_from_slice(&sa.port().to_be_bytes());
                    } else if let std::net::SocketAddr::V6(sa) = dest {
                        packet[3] = 0x04;
                        packet.extend_from_slice(&sa.ip().octets());
                        packet.extend_from_slice(&sa.port().to_be_bytes());
                    }
                    packet.extend_from_slice(&resp_buf[..rn]);
                    let _ = udp_socket.send_to(&packet, client_addr).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Add simple unit tests later
}
