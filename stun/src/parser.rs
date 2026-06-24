use std::collections::HashMap;

#[derive(Debug)]
pub enum ParserErrors {
    UnknownMessageType
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum StunAttributeTypes {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    XorMappedAddress = 0x0020,
    ResponseOrigin = 0x802b,
    Software = 0x8022,
    Pathset = 0xb001,
}

#[derive(Debug, Clone)]
pub enum MessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101
}

#[derive(Debug)]
pub struct StunAttribute {
    pub attribute_type: StunAttributeTypes,
    pub length: u16,
    value: std::ops::Range<usize>,
}

#[derive(Debug)]
pub struct StunMessageResponse {
    pub bytes: Vec<u8>,
    pub message_type: MessageType,
    pub message_length: u16,
    magic_cookie: std::ops::Range<usize>,
    transaction_id: std::ops::Range<usize>,
    pub attributes: HashMap<StunAttributeTypes, std::ops::Range<usize>>,
}

#[derive(Debug)]
pub struct StunMessageRequest {
    pub message_type: MessageType,
    pub message_length: u16,
    pub magic_cookie: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub attributes: HashMap<StunAttributeTypes, Vec<u8>>,
}

#[derive(Debug)]
pub struct AttributeEncode<'a> {
    pub attribute_type: &'a StunAttributeTypes,
    pub value: &'a [u8]
}

pub fn encode<'a>(msg_type: &'a MessageType, transaction_id: &'a [u8], attributes: Vec<AttributeEncode>) -> Result<Vec<u8>, ParserErrors> {
    let msg_type_u16 = msg_type.clone() as u16;
    let msg_type_bytes = [
        (msg_type_u16 >> 8) as u8,
        (msg_type_u16 & 0xFF) as u8,
    ];
    
    let transaction_bytes: &[u8] = transaction_id;
    let mut attrs: Vec<u8> = Vec::new();


    for attr in attributes {
        let mut attr_size: u16 = 0;
        let attribute_type_u16 = attr.attribute_type.clone() as u16;
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

pub fn decode(
    buffer: Vec<u8>,
) -> Result<StunMessageResponse, ParserErrors> {
    let type_range = 0..2;
    

    let message_type = match buffer[type_range] {
        [0x00, 0x01] => MessageType::BindingRequest,
        [0x01, 0x01] => MessageType::BindingResponse,
        _ => return Err(ParserErrors::UnknownMessageType),
    };


    let length_range = 2..4;

    let message_length = u16::from_be_bytes(
        buffer[length_range]
            .try_into()
            .map_err(|_| ParserErrors::UnknownMessageType)?
    );


    let magic_cookie_range = 4..8;

    let transaction_id_range = 8..20;


    let mut attributes = HashMap::new();

    let mut attr_cursor = 20;

    while attr_cursor < buffer.len() {
        let attr_type_range = attr_cursor..(attr_cursor + 2);
        attr_cursor += 2;

        let attribute_type = match buffer[attr_type_range] {
            [0x00, 0x01] => StunAttributeTypes::MappedAddress,
            [0x00, 0x06] => StunAttributeTypes::Username,
            [0x00, 0x08] => StunAttributeTypes::MessageIntegrity,
            [0x00, 0x20] => StunAttributeTypes::XorMappedAddress,
            [0x80, 0x2b] => StunAttributeTypes::ResponseOrigin,
            [0x80, 0x22] => StunAttributeTypes::Software,
            [0xb0, 0x01] => StunAttributeTypes::Pathset,
            _ => return Err(ParserErrors::UnknownMessageType),
        };

        let attr_length_range = attr_cursor..(attr_cursor + 2);
        attr_cursor += 2;

        let attribute_length = u16::from_be_bytes(
            buffer[attr_length_range]
                .try_into()
                .map_err(|_| ParserErrors::UnknownMessageType)?
        );

        dbg!(attr_cursor, attribute_length);
        let mut attribute_value_range = attr_cursor..(attr_cursor + attribute_length as usize);

        let padded_length = attr_cursor + ((attribute_length as usize + 3) & !3);
        attribute_value_range.end = padded_length;
        attr_cursor += attribute_length as usize;

        attributes.insert(attribute_type, attribute_value_range);
    }

    Ok(StunMessageResponse {
        message_type,
        message_length,
        magic_cookie: magic_cookie_range,
        transaction_id: transaction_id_range,
        attributes,
        bytes: buffer
    })
}

impl StunMessageResponse {
    pub fn magic_cookie(&self) -> &[u8] {
        let r = &self.magic_cookie;
        &self.bytes[r.start..r.end]
    }

    pub fn transaction_id(&self) -> &[u8] {
        let r = &self.transaction_id;
        &self.bytes[r.start..r.end]
    }

    pub fn attr_value(&self, attr_type: &StunAttributeTypes) -> Result<&[u8], ParserErrors> {
        let r = self.attributes.get(attr_type).ok_or(ParserErrors::UnknownMessageType)?;
        dbg!(&attr_type, &r);
        Ok(&self.bytes[r.start..r.end])
    }
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

    let msg = decode(packet.to_vec()).unwrap();

    assert!(matches!(
        msg.message_type,
        MessageType::BindingRequest
    ));

    assert_eq!(msg.message_length, 8);

    assert_eq!(
        &msg.bytes[msg.magic_cookie.clone()],
        &[0x21, 0x12, 0xA4, 0x42]
    );

    assert_eq!(
        &msg.bytes[msg.transaction_id.clone()],
        &[
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        ]
    );

    assert!(
         msg.attributes.keys().any(|t| *t == StunAttributeTypes::Software)
    );


    assert_eq!(
        std::str::from_utf8(
            msg.attr_value(&StunAttributeTypes::Software).unwrap()
        )
        .unwrap(),
        "rust"
    );
}

