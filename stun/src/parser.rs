#[derive(Debug)]
pub enum ParserErrors {
    UnknownMessageType
}

#[derive(Debug, Eq, PartialEq)]
pub enum StunAttributeTypes {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    XorMappedAddress = 0x0020,
    ResponseOrigin = 0x802b,
    Software = 0x8022,
    Pathset = 0xb001,
}

#[derive(Debug)]
pub enum MessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101
}

#[derive(Debug)]
pub struct StunMessageHeader<'a> {
    message_type: MessageType,
    message_length: u16,
    magic_cookie: &'a [u8; 4],
    transaction_id: &'a [u8; 12],
}

#[derive(Debug)]
pub struct StunAttribute<'a> {
    attribute_type: StunAttributeTypes,
    length: u16,
    value: &'a [u8]
}

#[derive(Debug)]
pub struct StunMessage<'a> {
    header: StunMessageHeader<'a>,
    attributes: Vec<StunAttribute<'a>>
}

pub fn encode() -> Vec<u8> {
    todo!()
}

pub fn decode<'a>(buffer: &'a [u8]) -> Result<StunMessage<'a>, ParserErrors> {
    let header_bytes = &buffer[0..20];
    let attributes_bytes = &buffer[20..];
    let (type_bytes, header_bytes) = header_bytes.split_at(2);
    let message_type = match type_bytes {
        [0x00, 0x01] => MessageType::BindingRequest,
        [0x01, 0x01] => MessageType::BindingResponse,
        _ => return Err(ParserErrors::UnknownMessageType),
    };

    let (length_bytes, header_bytes) = header_bytes.split_at(2);
    let length = u16::from_be_bytes(length_bytes.try_into().map_err(|_| ParserErrors::UnknownMessageType)?);

    let (magic_cookie, header_bytes) = header_bytes.split_at(4);
    let magic_cookie: &[u8; 4] = magic_cookie.try_into().map_err(|_| ParserErrors::UnknownMessageType)?;

    let (transaction_id, header_bytes) = header_bytes.split_at(12);
    let transaction_id: &[u8; 12] = transaction_id.try_into().map_err(|_| ParserErrors::UnknownMessageType)?;

    let mut attrs: Vec<StunAttribute> = Vec::new();
    let mut atr_bytes = attributes_bytes;
    while !atr_bytes.is_empty() {
        let (attribute_type_bytes, attributes_bytes) = attributes_bytes.split_at(2);
        let attribute_type = match attribute_type_bytes {
            [0x00, 0x01] => StunAttributeTypes::MappedAddress,
            [0x00, 0x06] => StunAttributeTypes::Username,
            [0x00, 0x08] => StunAttributeTypes::MessageIntegrity,
            [0x00, 0x20] => StunAttributeTypes::XorMappedAddress,
            [0x80, 0x2b] => StunAttributeTypes::ResponseOrigin,
            [0x80, 0x22] => StunAttributeTypes::Software,
            [0xb0, 0x01] => StunAttributeTypes::Pathset,
            _ => return Err(ParserErrors::UnknownMessageType)
        };
        let (attribute_length_bytes, mut attributes_bytes) = attributes_bytes.split_at(2);
        let attribute_length = u16::from_be_bytes(attribute_length_bytes.try_into().map_err(|_| ParserErrors::UnknownMessageType)?);
        let (attribute_value, attribute_bytes) = attributes_bytes.split_at(attribute_length as usize); 
        atr_bytes = attribute_bytes;
        println!("{:?}", attributes_bytes);
        attrs.push(StunAttribute { attribute_type, length: attribute_length, value: attribute_value });
    }
    

    Ok(StunMessage {
        header: StunMessageHeader {
            message_type,
            transaction_id,
            message_length: length,
            magic_cookie,
        },
        attributes: attrs
    })
}

#[test]
fn decode_binding_request() {
    let packet = [
        0x00, 0x01,
        0x00, 0x08,

        0x21, 0x12, 0xA4, 0x42,

        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,

        0x80, 0x22,
        0x00, 0x04,
        0x72, 0x75, 0x73, 0x74,
    ];

    let msg = decode(&packet).unwrap();

    assert!(matches!(
        msg.header.message_type,
        MessageType::BindingRequest
    ));

    assert_eq!(msg.header.message_length, 8);

    assert_eq!(
        msg.header.magic_cookie,
        &[0x21, 0x12, 0xA4, 0x42]
    );

    assert_eq!(
        msg.header.transaction_id,
        &[
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        ]
    );

    assert_eq!(msg.attributes[0].attribute_type, StunAttributeTypes::Software);
    assert_eq!(msg.attributes[0].length, 4);
    assert_eq!(str::from_utf8(msg.attributes[0].value).unwrap(), "rust");
}


