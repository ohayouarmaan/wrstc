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

#[derive(Debug)]
pub struct AttributeEncode {
    attribute_type: StunAttributeTypes,
    value: Vec<u8>
}

pub fn encode<'a>(msg_type: MessageType, transaction_id: &'a str, attributes: Vec<AttributeEncode>) -> Result<Vec<u8>, ParserErrors> {
    let msg_type_u16 = msg_type as u16;
    let msg_type_bytes = [
        (msg_type_u16 >> 8) as u8,
        (msg_type_u16 & 0xFF) as u8,
    ];
    
    let transaction_bytes: &[u8] = transaction_id.as_bytes();
    let mut attrs: Vec<u8> = Vec::new();


    for attr in attributes {
        let mut attr_size: u16 = 0;
        let attribute_type_u16 = attr.attribute_type as u16;
        let attribute_type_bytes = [
            (attribute_type_u16 >> 8) as u8,
            (attribute_type_u16 & 0xFF) as u8,
        ];

        attr_size += attr.value.len() as u16;

        let mut padding: usize = (attr_size % 4) as usize;
        if !attr_size.is_multiple_of(4) {
            padding = (((attr_size + 4) - ((attr_size + 4) % 4)) - attr_size) as usize;
        }

        
        let attr_size_bytes = [
            (attr_size >> 8) as u8,
            (attr_size & 0xFF) as u8,
        ];
        attrs.extend_from_slice(&attribute_type_bytes);
        attrs.extend_from_slice(&attr_size_bytes);
        attrs.extend_from_slice(&attr.value);
        attrs.extend(std::iter::repeat_n(0u8, padding));
    }

    let length_of_attrs = attrs.len() as u16;
    let length_of_attrs_bytes = [
        (length_of_attrs >> 8) as u8,
        (length_of_attrs & 0xFF) as u8,
    ];

    let mut main_encoded_message: Vec<u8> = Vec::new();
    main_encoded_message.extend_from_slice(&msg_type_bytes);
    main_encoded_message.extend_from_slice(&length_of_attrs_bytes);
    main_encoded_message.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    main_encoded_message.extend_from_slice(transaction_bytes);
    main_encoded_message.extend_from_slice(&attrs);
    
    Ok(main_encoded_message)
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

    let (transaction_id, _header_bytes) = header_bytes.split_at(12);
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
        let (attribute_length_bytes, attributes_bytes) = attributes_bytes.split_at(2);
        let attribute_length = u16::from_be_bytes(attribute_length_bytes.try_into().map_err(|_| ParserErrors::UnknownMessageType)?);
        let (attribute_value, attribute_bytes) = attributes_bytes.split_at(attribute_length as usize); 
        atr_bytes = attribute_bytes;
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

#[test]
fn test_encode_binding_request() {
    let transaction_id = "abcdefghijkl";

    let attributes = vec![
        AttributeEncode {
            attribute_type: StunAttributeTypes::Username,
            value: b"John Doe".to_vec(),
        },
        AttributeEncode {
            attribute_type: StunAttributeTypes::Software,
            value: b"wsrtc".to_vec(),
        },
    ];

    let encoded = encode(
        MessageType::BindingRequest,
        transaction_id,
        attributes,
    )
        .expect("failed to encode STUN message");

    assert!(encoded.len() >= 20);
    assert_eq!(&encoded[0..2], &[0x00, 0x01]);
    assert_eq!(&encoded[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    assert_eq!(&encoded[8..20], transaction_id.as_bytes());
    assert!(
        encoded.windows(2).any(|w| w == [0x00, 0x06]),
        "Username attribute not found"
    );
    assert!(
        encoded.windows(2).any(|w| w == [0x80, 0x22]),
        "Software attribute not found"
    );
    assert!(
        encoded.windows(b"John Doe".len())
        .any(|w| w == b"John Doe")
    );
    assert!(
        encoded.windows(b"wsrtc".len())
        .any(|w| w == b"wsrtc")
    );
}

