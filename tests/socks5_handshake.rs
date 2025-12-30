use std::time::Duration;

#[tokio::test]
async fn test_no_auth_handshake() {
    // start server on ephemeral port
    let (addr, handle) = vpn_proxy::socks5::start_background("127.0.0.1:0", None, None)
        .await
        .expect("start server");

    // give server a moment
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");

    // send greeting: SOCKS5, 1 method, NO AUTH
    sock.write_all(&[0x05u8, 0x01, 0x00]).await.expect("write");

    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("read");
    assert_eq!(resp, [0x05, 0x00]);

    // shutdown
    handle.abort();
}

#[tokio::test]
async fn test_username_password_auth_success() {
    let (addr, handle) = vpn_proxy::socks5::start_background(
        "127.0.0.1:0",
        None,
        Some(("testuser".to_string(), "testpass".to_string())),
    )
    .await
    .expect("start server");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");

    // send greeting: SOCKS5, 2 methods (NO AUTH, USER/PASS)
    sock.write_all(&[0x05u8, 0x02, 0x00, 0x02]).await.expect("write");

    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("read");
    // server should select USER/PASS (0x02)
    assert_eq!(resp, [0x05, 0x02]);

    // perform auth: version(1), ulen, uname, plen, pass
    let uname = b"testuser";
    let pass = b"testpass";
    let mut auth = vec![0x01u8, uname.len() as u8];
    auth.extend_from_slice(uname);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);

    sock.write_all(&auth).await.expect("write auth");

    let mut auth_resp = [0u8; 2];
    sock.read_exact(&mut auth_resp).await.expect("read auth");
    assert_eq!(auth_resp, [0x01, 0x00]);

    handle.abort();
}

#[tokio::test]
async fn test_username_password_auth_failure() {
    let (addr, handle) = vpn_proxy::socks5::start_background(
        "127.0.0.1:0",
        None,
        Some(("testuser".to_string(), "testpass".to_string())),
    )
    .await
    .expect("start server");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");

    // send greeting: SOCKS5, 1 method (USER/PASS)
    sock.write_all(&[0x05u8, 0x01, 0x02]).await.expect("write");

    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("read");
    assert_eq!(resp, [0x05, 0x02]);

    // perform auth with wrong password
    let uname = b"testuser";
    let pass = b"wrong";
    let mut auth = vec![0x01u8, uname.len() as u8];
    auth.extend_from_slice(uname);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);

    sock.write_all(&auth).await.expect("write auth");

    let mut auth_resp = [0u8; 2];
    sock.read_exact(&mut auth_resp).await.expect("read auth");
    assert_eq!(auth_resp, [0x01, 0x01]);

    handle.abort();
}
