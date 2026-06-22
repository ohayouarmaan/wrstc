use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: UdpSocket,
    pub address: SocketAddr
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self{ socket, address: addr })
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr
    ) -> std::io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> std::io::Result<usize> {
        Ok(self.socket.recv_from(buf).await?.0)
    }
}

