use transport::udp;
use tokio::net::lookup_host;

// #[tokio::test]
pub async fn test_communication() {
    let server = udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let client = udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let server_addr = server.address;
    let msg = b"echo";

    client.send_to(msg, server_addr).await.unwrap();

    let mut buf = [0u8; 1024];

    let len = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], msg);
}

#[tokio::test]
pub async fn check_google_stun() {
    let request: &[u8] = &[
        0x00, 0x01, 
        0x00, 0x00,

        0x21, 0x12, 0xA4, 0x42,

        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
    ];

    let google_stun_udp = udp::UdpTransport::bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
    let google_stun_udp_address = lookup_host("stun.l.google.com:19302").await.unwrap().find(|addr| addr.is_ipv4()).unwrap();
    google_stun_udp.send_to(request, google_stun_udp_address).await.unwrap();
    let mut buf: [u8; 1024] = [0u8; 1024];
    let size = google_stun_udp.recv_from(&mut buf).await.unwrap();
    assert_eq!(true, true);
}

