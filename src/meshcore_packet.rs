#[derive(Debug, PartialEq)]
pub enum GroupMessagePacketError {
    InvalidPacketLength(usize),
    InvalidPayloadType(u8),
    CorruptedPacketLength(usize),
}

pub fn get_channel_payload_from_raw_packet(
    raw_packet: Vec<u8>,
) -> Result<Vec<u8>, GroupMessagePacketError> {
    if raw_packet.len() < 10 {
        return Err(GroupMessagePacketError::InvalidPacketLength(
            raw_packet.len(),
        ));
    }

    let header = raw_packet[0];

    let mut offset: usize = 1;

    let route_type = header & 0x03;

    // ROUTE_TYPE_TRANSPORT_FLOOD = 0x00
    // ROUTE_TYPE_TRANSPORT_DIRECT = 0x03
    match route_type {
        0 | 3 => {
            offset += 4;
        }
        _ => {}
    }

    // PAYLOAD_TYPE_GRP_TXT = 0x05
    let payload_type = (header >> 2) & 0x0F;

    if payload_type != 5 {
        return Err(GroupMessagePacketError::InvalidPayloadType(payload_type));
    }

    let path_len: usize = raw_packet[offset] as usize;

    // 1, 2, or 3; 4 if bits 7:6 = 11 (reserved)
    let path_hash_size: usize = (path_len >> 6) + 1;
    let path_hop_count: usize = path_len & 63;
    let path_byte_length: usize = path_hop_count * path_hash_size;

    let payload_offset = offset + path_byte_length + 1;

    if payload_offset >= raw_packet.len() {
        return Err(GroupMessagePacketError::CorruptedPacketLength(
            raw_packet.len(),
        ));
    }

    let payload = raw_packet[payload_offset..].to_vec();

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_channel_payload_from_raw_packet() {
        let test_data: Vec<(&str, &str)> = vec![
            (
                // 1 byte path, 1 hoop
                "15411111D9F968645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45",
                "D9F968645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45",
            ),
            (
                // 2 bytes path, 3 hops
                "154374375261D900249ECCE61DF3AB042FC83AC0CB054985026602E5CB3B5014C68FF6D6E3F5C97C018CD3FFE5326C50F3509B3F28BB34E2D583A777DF31D5A37815C8A8D4B3DFC04EC6C9ADDD18C1E944AADCFC3742E6B928DF3454EADA78721D54E23182345563376DA468F935A9D8B1846509CA423B8A82FC10A4397AC38891FAA92E6B475635D0A111",
                "249ECCE61DF3AB042FC83AC0CB054985026602E5CB3B5014C68FF6D6E3F5C97C018CD3FFE5326C50F3509B3F28BB34E2D583A777DF31D5A37815C8A8D4B3DFC04EC6C9ADDD18C1E944AADCFC3742E6B928DF3454EADA78721D54E23182345563376DA468F935A9D8B1846509CA423B8A82FC10A4397AC38891FAA92E6B475635D0A111",
            ),
            (
                // 3 bytes path, 9 hops
                "15895261244E639BA340C467AE3C5C6836515151C77777909088CA5EB36DCC42B893C1901EAEA532D375CA4342ABD85DD9BA1EB503E9A229EFD8177B0F1F31536294B089F31E73A1CA078F2C05E4698D",
                "6DCC42B893C1901EAEA532D375CA4342ABD85DD9BA1EB503E9A229EFD8177B0F1F31536294B089F31E73A1CA078F2C05E4698D",
            ),
        ];

        for (raw_packet_hex, channel_payload_hex) in &test_data {
            let raw_packet = hex::decode(raw_packet_hex).expect("invalid hex");
            let channel_payload = hex::decode(channel_payload_hex).expect("invalid hex");

            match get_channel_payload_from_raw_packet(raw_packet) {
                Err(_) => assert!(false, "Got error, but is OK"),
                Ok(payload) => assert_eq!(channel_payload, payload),
            }
        }
    }

    #[test]
    fn test_get_channel_payload_from_raw_packet_failed() {
        let test_data: Vec<(&str, GroupMessagePacketError)> = vec![
            (
                // Advert
                "110115C2C247E49DDD23EC193015BEEFEB1F6CBE24D895311022F926A0B18B492293973DF0A66A2A29B31BEF288C2D4293ED68461D6C3A1D9CC24FE20518F64DF5246D66A119A7DE028652FA4DDE1E6AC69AD32FEADD1CC63E8D759EBFF6E94314E3A00AC7FB0192000000000000000047686F73742053463620F09F91BB",
                GroupMessagePacketError::InvalidPayloadType(4),
            ),
            (
                // Too short packet
                "110115C2C247E49DDD",
                GroupMessagePacketError::InvalidPacketLength(9),
            ),
        ];

        for (raw_packet_hex, error) in &test_data {
            let raw_packet = hex::decode(raw_packet_hex.to_string()).expect("invalid hex");

            match get_channel_payload_from_raw_packet(raw_packet) {
                Err(err) => assert_eq!(error, &err),
                Ok(_) => assert!(false, "Got OK, but is an error"),
            }
        }
    }
}
