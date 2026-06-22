use transport::udp;
use crate::parser::StunMessage;
use tokio::net::lookup_host;
// use crate::parser::{StunMessageHeader};


pub struct StunClient {
    stun_socket: udp::UdpTransport,
}

pub enum StunClientErrors {
    InitializingStunClient,
    ResolvingStunHostAddr,
    GettingStunResponse,
    ParsingStunResponse
}

impl StunClient {
    pub async fn new(stun_server_addr: Option<&str>) -> Result<Self, StunClientErrors> {
        let stun_server_addr = stun_server_addr.unwrap_or("stun.l.google.com:19302");
        let stun_server_addr = lookup_host(stun_server_addr)
            .await
            .map_err(|_| StunClientErrors::ResolvingStunHostAddr)?
            .find(|addr| addr.is_ipv4())
            .ok_or(StunClientErrors::ResolvingStunHostAddr)?;

        Ok(Self {
            stun_socket: udp::UdpTransport::bind(stun_server_addr).await.map_err(|_| StunClientErrors::InitializingStunClient)?,
        })
    }

    pub async fn get_stun_results(&mut self) -> Result<(), StunClientErrors> {
        todo!();
    }
}
