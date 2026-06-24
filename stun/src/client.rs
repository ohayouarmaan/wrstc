use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use transport::udp;
use crate::parser::StunMessageResponse;
use tokio::net::lookup_host;
use tokio::sync::oneshot::Sender;
use crate::parser::{encode, decode, MessageType, StunAttributeTypes, AttributeEncode, ParserErrors, StunMessageRequest};


pub struct StunClient {
    stun_socket: Arc<udp::UdpTransport>,
    transaction_map: Arc<Mutex<HashMap<[u8; 12], Sender<StunMessageResponse>>>>
}

#[derive(Debug)]
pub enum StunClientErrors {
    InitializingStunClient,
    ResolvingStunHostAddr,
    GettingStunResponse(std::io::Error),
    ParsingStunResponse(ParserErrors),
    ParsingError(ParserErrors),
    RecievingOneShotDataError,
    MutexError
}


pub fn generate_transaction_id() -> [u8; 12] {
    let mut buffer_array = [0u8; 12];
    rand::fill(&mut buffer_array);
    buffer_array
}

impl StunClient {
    pub async fn new(stun_server_addr: Option<&str>) -> Result<Self, StunClientErrors> {
        Ok(Self {
            stun_socket: Arc::new(udp::UdpTransport::bind("0.0.0.0:0".parse().unwrap()).await.map_err(|_| StunClientErrors::InitializingStunClient)?),
            transaction_map: Arc::new(Mutex::new(HashMap::new()))
        })
    }

    async fn start_recieving_loop(&mut self) {
        let transaction_map = Arc::clone(&self.transaction_map);
        let socket = Arc::clone(&self.stun_socket);
        tokio::spawn(async move {
            loop {
                let mut buff = vec![0u8; 548]; // 548 comes from
                                               // https://datatracker.ietf.org/doc/html/rfc8489
                                               // section 6.1
                let read_size = socket.recv_from(&mut buff).await.unwrap();
                let msg = decode(buff[..read_size].to_vec()).unwrap();
                let tx = {
                    let mut map = transaction_map.lock().unwrap();

                    if map.contains_key(msg.transaction_id()) {
                        map.remove(msg.transaction_id())
                            .unwrap()
                    } else {
                        continue;
                    }
                };

                tx.send(msg).unwrap();
            }
        });
    }

    pub async fn send_request(&mut self, message: StunMessageRequest, destination: SocketAddr) -> Result<StunMessageResponse, StunClientErrors> {
        let txn_id = generate_transaction_id();
        let mut attrs_param = Vec::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<StunMessageResponse>();
        
        for attr in message.attributes.keys() {
            attrs_param.push(AttributeEncode{
                value: message.attributes.get(attr).unwrap(),
                attribute_type: attr
            });
        }

        let encoded_data = encode(&message.message_type, &txn_id, attrs_param).map_err(StunClientErrors::ParsingError)?;
        self.transaction_map.lock().map_err(|_| StunClientErrors::MutexError)?.insert(txn_id, tx);
        let _ = self.stun_socket.send_to(&encoded_data, destination).await.map_err(StunClientErrors::GettingStunResponse)?;
        let data = rx.await.map_err(|_| StunClientErrors::RecievingOneShotDataError)?;
        Ok(data)
    }
}

#[tokio::test]
async fn test_binding_request_roundtrip() {
    let mut client = StunClient::new(None)
        .await
        .unwrap();

    client.start_recieving_loop().await;

    let request = StunMessageRequest {
        message_type: MessageType::BindingRequest,
        message_length: 0,
        magic_cookie: vec![0x21, 0x12, 0xA4, 0x42],
        transaction_id: vec![0; 12],
        attributes: HashMap::new(),
    };

    let google_stun_udp_address = lookup_host("stun.l.google.com:19302")
        .await
        .unwrap()
        .find(|addr| addr.is_ipv4())
        .unwrap();

    let response = client
        .send_request(request, google_stun_udp_address)
        .await
        .expect("failed to receive response");

    assert!(matches!(
        response.message_type,
        MessageType::BindingResponse
    ));

    assert_eq!(
        response.magic_cookie(),
        &[0x21, 0x12, 0xA4, 0x42]
    );

    assert_eq!(response.transaction_id().len(), 12);

    assert!(
        response.attr_value(&StunAttributeTypes::XorMappedAddress)
            .is_ok()
    );
}
