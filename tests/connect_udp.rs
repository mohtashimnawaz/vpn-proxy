use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_connect_end_to_end() {
    // Start a TCP echo server
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("local addr");
    let echo_handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = echo_listener.accept().await {
            let mut buf = vec![0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                }
            }
        }
    });

    // Start socks proxy
    let (proxy_addr, _proxy_handle) = vpn_proxy::socks5::start_background("127.0.0.1:0", None, None)
        .await
        .expect("start proxy");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to proxy and do SOCKS5 handshake + CONNECT to echo server
    let mut sock = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect proxy");

    // greeting: SOCKS5, 1 method NO AUTH
    sock.write_all(&[0x05u8, 0x01, 0x00]).await.expect("write greeting");
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("read method");
    assert_eq!(resp, [0x05, 0x00]);

    // send CONNECT to echo server (IPv4)
    if let std::net::SocketAddr::V4(sa) = echo_addr {
        let ip = sa.ip().octets();
        let port = sa.port().to_be_bytes();
        let mut req = vec![0x05u8, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&port);
        sock.write_all(&req).await.expect("write connect");

        let mut rep = [0u8; 10];
        sock.read_exact(&mut rep).await.expect("read connect rep");
        assert_eq!(rep[1], 0x00u8); // success

        // Now send data through the established tunnel and expect echo
        sock.write_all(b"hello tcp").await.expect("write data");
        let mut buf = [0u8; 16];
        let n = sock.read(&mut buf).await.expect("read echo");
        assert_eq!(&buf[..n], b"hello tcp");
    } else {
        panic!("unexpected echo addr family");
    }

    // cleanup
    let _ = echo_handle.abort();
}

#[tokio::test]
async fn test_udp_associate_end_to_end() {
    // Start a UDP echo server
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let echo_addr = udp_echo.local_addr().expect("udp local addr");
    let udp_handle = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            match udp_echo.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let _ = udp_echo.send_to(&buf[..n], src).await;
                }
                Err(_) => break,
            }
        }
    });

    // Start socks proxy
    let (proxy_addr, _proxy_handle) = vpn_proxy::socks5::start_background("127.0.0.1:0", None, None)
        .await
        .expect("start proxy");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to proxy and do SOCKS5 handshake + UDP ASSOCIATE
    let mut sock = tokio::net::TcpStream::connect(proxy_addr).await.expect("connect proxy");

    // greeting: SOCKS5, 1 method NO AUTH
    sock.write_all(&[0x05u8, 0x01, 0x00]).await.expect("write greeting");
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("read method");
    assert_eq!(resp, [0x05, 0x00]);

    // send UDP ASSOCIATE (IPv4 0.0.0.0:0)
    let mut req = vec![0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    sock.write_all(&req).await.expect("write udp assoc");

    // read reply: version, rep, rsv, atyp, addr/port
    let mut header = [0u8; 4];
    sock.read_exact(&mut header).await.expect("read udp rep hdr");
    assert_eq!(header[1], 0x00u8); // success
    let atyp = header[3];
    let udp_proxy_addr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await.expect("read ip");
            let mut portb = [0u8; 2];
            sock.read_exact(&mut portb).await.expect("read port");
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), u16::from_be_bytes(portb))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await.expect("read ip6");
            let mut portb = [0u8; 2];
            sock.read_exact(&mut portb).await.expect("read port");
            std::net::SocketAddr::new(std::net::IpAddr::from(ip), u16::from_be_bytes(portb))
        }
        _ => panic!("unsupported atyp"),
    };

    // Create UDP socket to send datagram to proxy's UDP listening address
    let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind udp client");

    // Build SOCKS5 UDP datagram to send to echo server
    // UDP header: RSV(2)=0x0000, FRAG=0x00, ATYP, DST.ADDR, DST.PORT, DATA
    if let std::net::SocketAddr::V4(echo_v4) = echo_addr {
        let mut packet = vec![0u8, 0u8, 0x00u8, 0x01u8];
        packet.extend_from_slice(&echo_v4.ip().octets());
        packet.extend_from_slice(&echo_v4.port().to_be_bytes());
        packet.extend_from_slice(b"hello udp");

        udp_client.send_to(&packet, udp_proxy_addr).await.expect("send udp to proxy");

        // Receive response from proxy
        let mut buf = [0u8; 65536];
        let (n, _src) = tokio::time::timeout(Duration::from_secs(1), udp_client.recv_from(&mut buf)).await.expect("recv timeout").expect("recv");

        // Parse returned SOAP UDP datagram: RSV(2), FRAG, ATYP, ADDR, PORT, DATA
        assert!(n > 4);
        assert_eq!(&buf[0..2], &[0u8, 0u8]);
        let frag = buf[2];
        assert_eq!(frag, 0x00);
        let atyp = buf[3];
        assert_eq!(atyp, 0x01);
        // skip to data
        let data_idx = 4 + 4 + 2; // IPv4 addr + port
        assert_eq!(&buf[data_idx..n], b"hello udp");

        // Now test fragmentation: send first fragment (frag=1), then final fragment (frag=0)
        let payload1 = b"hello ";
        let payload2 = b"udp frag";
        let mut frag1 = vec![0u8, 0u8, 0x01u8, 0x01u8];
        frag1.extend_from_slice(&echo_v4.ip().octets());
        frag1.extend_from_slice(&echo_v4.port().to_be_bytes());
        frag1.extend_from_slice(payload1);
        udp_client.send_to(&frag1, udp_proxy_addr).await.expect("send frag1");

        let mut frag2 = vec![0u8, 0u8, 0x00u8, 0x01u8];
        frag2.extend_from_slice(&echo_v4.ip().octets());
        frag2.extend_from_slice(&echo_v4.port().to_be_bytes());
        frag2.extend_from_slice(payload2);
        udp_client.send_to(&frag2, udp_proxy_addr).await.expect("send frag2");

        let (n, _src) = tokio::time::timeout(Duration::from_secs(1), udp_client.recv_from(&mut buf)).await.expect("recv timeout").expect("recv");
        // check payload
        let data_idx = 4 + 4 + 2;
        assert_eq!(&buf[data_idx..n], b"hello udp frag");
    } else {
        panic!("unexpected echo addr family");
    }

    let _ = udp_handle.abort();
}
