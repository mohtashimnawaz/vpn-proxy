use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Run the SOCKS5 proxy. If `tls` is Some((cert_path, key_path)) the proxy will accept
/// TLS on the client side (client -> proxy TLS) using rustls. TLS support is feature-gated
/// behind the `tls` Cargo feature.
pub async fn run(listen: &str, tls: Option<(String, String)>) -> Result<()> {
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

    info!(%listen, "SOCKS5 proxy listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        info!(%peer, "accepted connection");
        #[cfg(feature = "tls")]
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let res = async {
                #[cfg(feature = "tls")]
                {
                    if let Some(acceptor) = acceptor {
                        // perform TLS handshake
                        match acceptor.accept(socket).await {
                            Ok(stream) => handle_client(stream).await,
                            Err(e) => {
                                warn!(%peer, error = %e, "tls handshake failed");
                                Err(anyhow!("tls handshake failed: {}", e))
                            }
                        }
                    } else {
                        handle_client(socket).await
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    // tls feature not enabled
                    let _ = peer; // silence unused
                    handle_client(socket).await
                }
            }
            .await;

            if let Err(e) = res {
                warn!(%peer, error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_client<S>(mut socket: S) -> Result<()>
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

    // we only support NO AUTH (0x00)
    let method = if methods.iter().any(|m| *m == 0x00) { 0x00 } else { 0xff };
    socket.write_all(&[0x05, method]).await?;
    if method == 0xff {
        return Err(anyhow!("no acceptable auth methods"));
    }

    // 2) Request
    let ver = socket.read_u8().await?;
    if ver != 0x05 {
        return Err(anyhow!("unsupported request version: {}", ver));
    }

    let cmd = socket.read_u8().await?;
    let _rsv = socket.read_u8().await?;
    let atyp = socket.read_u8().await?;

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

#[cfg(test)]
mod tests {
    // Add simple unit tests later
}
