use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::{BTreeMap, HashMap};

// Metrics for UDP events
#[derive(Default)]
struct Metrics {
    udp_frag_received: AtomicU64,
    udp_frag_assembled: AtomicU64,
    udp_frag_dropped: AtomicU64,
    udp_mapping_created: AtomicU64,
    udp_mapping_expired: AtomicU64,
}

impl Metrics {
    fn incr_frag_received(&self) { self.udp_frag_received.fetch_add(1, Ordering::Relaxed); }
    fn incr_frag_assembled(&self) { self.udp_frag_assembled.fetch_add(1, Ordering::Relaxed); }
    fn incr_frag_dropped(&self) { self.udp_frag_dropped.fetch_add(1, Ordering::Relaxed); }
    fn incr_mapping_created(&self) { self.udp_mapping_created.fetch_add(1, Ordering::Relaxed); }
    fn incr_mapping_expired(&self) { self.udp_mapping_expired.fetch_add(1, Ordering::Relaxed); }
    fn snapshot(&self) -> HashMap<&'static str, u64> {
        let mut m = HashMap::new();
        m.insert("udp_frag_received", self.udp_frag_received.load(Ordering::Relaxed));
        m.insert("udp_frag_assembled", self.udp_frag_assembled.load(Ordering::Relaxed));
        m.insert("udp_frag_dropped", self.udp_frag_dropped.load(Ordering::Relaxed));
        m.insert("udp_mapping_created", self.udp_mapping_created.load(Ordering::Relaxed));
        m.insert("udp_mapping_expired", self.udp_mapping_expired.load(Ordering::Relaxed));
        m
    }
}

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::default);

pub fn metrics_snapshot() -> HashMap<&'static str, u64> {
    METRICS.snapshot()
}

#[cfg(feature = "tls")]
type TlsAcceptorType = tokio_rustls::TlsAcceptor;
#[cfg(not(feature = "tls"))]
type TlsAcceptorType = ();

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

    #[cfg(not(feature = "tls"))]
    let acceptor = None;

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

    #[cfg(not(feature = "tls"))]
    let acceptor = None;

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
    acceptor: Option<TlsAcceptorType>,
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
                // If bound to 0.0.0.0, return loopback so client can reach it
                let ip = if sa.ip().octets() == [0, 0, 0, 0] {
                    [127, 0, 0, 1]
                } else {
                    sa.ip().octets()
                };
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

async fn udp_relay(udp_socket: tokio::net::UdpSocket) -> Result<()> {
    use std::collections::{BTreeMap, HashMap};
    use std::time::{Duration, Instant};

    // Map remote destination -> (client address, created_at)
    let mut remote_to_client: HashMap<std::net::SocketAddr, (std::net::SocketAddr, Instant)> = HashMap::new();
    // Reassembly buffer keyed by (client, dest)
    type FragMap = BTreeMap<u8, Vec<u8>>;
    struct Assembly {
        frags: FragMap,
        total_size: usize,
        last_seen: Instant,
    }

    let mut assemblies: HashMap<(std::net::SocketAddr, std::net::SocketAddr), Assembly> = HashMap::new();

    // Limits and timings
    let mut buf = vec![0u8; 65536];
    let cleanup_interval = Duration::from_secs(5);
    let assembly_ttl = Duration::from_secs(30); // per-assembly TTL
    let mapping_ttl = Duration::from_secs(60); // explicit TTL for remote->client mapping
    const MAX_REASSEMBLY_SIZE: usize = 64 * 1024; // 64KiB
    const MAX_FRAGMENTS: usize = 256;
    let mut last_cleanup = Instant::now();

    loop {
        // Periodic cleanup of stale assemblies
        if last_cleanup.elapsed() > cleanup_interval {
            let now = Instant::now();
            assemblies.retain(|_, a| now.duration_since(a.last_seen) < assembly_ttl);
            // expire remote mappings that are stale as well
            let before = remote_to_client.len();
            remote_to_client.retain(|_k, v| now.duration_since(v.1) < mapping_ttl);
            let after = remote_to_client.len();
            if before != after {
                let expired = (before - after) as u64;
                for _ in 0..expired { METRICS.incr_mapping_expired(); }
                info!(expired = expired, "expired UDP mappings due to TTL");
            }
            last_cleanup = now;
        }

        let (n, src) = udp_socket.recv_from(&mut buf).await?;

        // Distinguish packets coming from clients (they will contain SOCKS5 UDP header RSV(2)=0x0000)
        // vs packets coming from remote destinations (no SOCKS5 header)
        if n >= 4 && &buf[0..2] == [0u8, 0u8] {
            // client -> proxy
            METRICS.incr_frag_received();
            let frag = buf[2];
            let atyp = buf[3];

            let mut idx = 4usize;
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

            let payload = buf[idx..n].to_vec();

            // If fragmented (frag != 0), buffer fragments keyed by (client, dest)
            let key = (src, dest);
            if frag != 0 {
                let entry = assemblies.entry(key).or_insert(Assembly {
                    frags: BTreeMap::new(),
                    total_size: 0,
                    last_seen: Instant::now(),
                });

                // bounds checks
                if entry.frags.len() >= MAX_FRAGMENTS {
                    warn!(%src, %dest, "too many fragments, dropping");
                    METRICS.incr_frag_dropped();
                    continue;
                }
                if entry.total_size + payload.len() > MAX_REASSEMBLY_SIZE {
                    warn!(%src, %dest, "fragment would exceed max reassembly size, dropping assembly");
                    assemblies.remove(&key);
                    METRICS.incr_frag_dropped();
                    continue;
                }

                entry.total_size += payload.len();
                entry.frags.insert(frag, payload);
                entry.last_seen = Instant::now();

                // If a final fragment already exists (frag==0 in map), attempt assembly when all fragments are present
                if entry.frags.get(&0).is_some() {
                    // Check for contiguous fragment indices 1..=max
                    let max_frag = *entry.frags.keys().max().unwrap_or(&0);
                    let mut missing = false;
                    for i in 1..=max_frag {
                        if !entry.frags.contains_key(&i) {
                            missing = true;
                            break;
                        }
                    }
                    if missing {
                        // wait for missing fragments until TTL expires
                        debug!(%src, %dest, "fragments out-of-order / missing, waiting for remainder");
                    } else {
                        // assemble
                        let mut assembled = Vec::new();
                        for (_k, v) in entry.frags.iter() {
                            assembled.extend_from_slice(v);
                        }
                        assemblies.remove(&key);
                        let _ = udp_socket.send_to(&assembled, dest).await;
                        remote_to_client.insert(dest, (src, Instant::now()));
                        METRICS.incr_frag_assembled();
                        METRICS.incr_mapping_created();
                        info!(%src, %dest, "fragments assembled and sent");
                    }
                }

                continue;
            } else {
                // frag == 0
                if let Some(mut entry) = assemblies.remove(&key) {
                    // Ensure we have contiguous fragments 1..=max
                    let max_frag = *entry.frags.keys().max().unwrap_or(&0);
                    let mut missing = false;
                    for i in 1..=max_frag {
                        if !entry.frags.contains_key(&i) {
                            missing = true;
                            break;
                        }
                    }
                    if missing {
                        warn!(%src, %dest, "missing fragments on final fragment, dropping assembly");
                        METRICS.incr_frag_dropped();
                        continue;
                    }

                    // Check size
                    if entry.total_size + payload.len() > MAX_REASSEMBLY_SIZE {
                        warn!(%src, %dest, "assembled size exceeds max, dropping");
                        METRICS.incr_frag_dropped();
                        continue;
                    }

                    // combine all fragments plus this last payload
                    let mut assembled = Vec::new();
                    for (_k, v) in entry.frags.iter() {
                        assembled.extend_from_slice(v);
                    }
                    assembled.extend_from_slice(&payload);
                    let _ = udp_socket.send_to(&assembled, dest).await;
                    remote_to_client.insert(dest, (src, Instant::now()));
                    METRICS.incr_frag_assembled();
                    METRICS.incr_mapping_created();
                    info!(%src, %dest, "fragments assembled on final fragment and sent");
                    continue;
                }
                // not fragmented, send directly
                let _ = udp_socket.send_to(&payload, dest).await;
                remote_to_client.insert(dest, (src, Instant::now()));
                METRICS.incr_mapping_created();
            }
        } else {
            // packet from remote destination -> forward to client if we have mapping
            let src_addr = src;
            // expire old mappings
            let now = Instant::now();
            remote_to_client.retain(|_k, v| now.duration_since(v.1) < mapping_ttl);
            if let Some((client_addr, _)) = remote_to_client.get(&src_addr) {
                // wrap with SOCKS5 UDP header
                let mut packet = vec![0u8, 0u8, 0u8, 0x01];
                if let std::net::SocketAddr::V4(sa) = src_addr {
                    packet.extend_from_slice(&sa.ip().octets());
                    packet.extend_from_slice(&sa.port().to_be_bytes());
                } else if let std::net::SocketAddr::V6(sa) = src_addr {
                    packet[3] = 0x04;
                    packet.extend_from_slice(&sa.ip().octets());
                    packet.extend_from_slice(&sa.port().to_be_bytes());
                }
                packet.extend_from_slice(&buf[..n]);
                let _ = udp_socket.send_to(&packet, *client_addr).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Add simple unit tests later
}
