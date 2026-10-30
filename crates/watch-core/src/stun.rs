use crate::network::public_unicast;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut data = [0; 20];
    data[1] = 1;
    data[4..8].copy_from_slice(&COOKIE);
    data[8..].copy_from_slice(&transaction);
    data
}
pub fn decode(data: &[u8], transaction: &[u8; 12]) -> Result<String, &'static str> {
    if data.len() < 20 || data[..2] != [1, 1] || data[4..8] != COOKIE || data[8..20] != *transaction
    {
        return Err("unrelated_response");
    }
    let size = u16::from_be_bytes([data[2], data[3]]) as usize;
    if !size.is_multiple_of(4) || data.len() != 20 + size {
        return Err("invalid_length");
    }
    let mut offset = 20;
    while offset + 4 <= data.len() {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let end = offset + 4 + length;
        if end > data.len() {
            return Err("truncated_attribute");
        }
        let value = &data[offset + 4..end];
        if matches!(kind, 0x0020 | 0x0001) && value.len() >= 8 {
            let count = match value[1] {
                1 => 4,
                2 => 16,
                _ => 0,
            };
            if count == 0 || length != count + 4 {
                return Err("invalid_address");
            }
            let mut raw = value[4..].to_vec();
            if kind == 0x0020 {
                let mask: Vec<_> = COOKIE.iter().chain(transaction.iter()).copied().collect();
                for (byte, mask) in raw.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            let address = if count == 4 {
                Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string()
            } else {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(&raw);
                Ipv6Addr::from(bytes).to_string()
            };
            return public_unicast(&address).ok_or("nonpublic_address");
        }
        offset = end + (4 - length % 4) % 4;
    }
    Err("address_missing")
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn reply(transaction: [u8; 12], address: [u8; 4], xor: bool) -> Vec<u8> {
        let mut packet = binding_request(transaction).to_vec();
        packet[0] = 1;
        packet[1] = 1;
        packet[2..4].copy_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&(if xor { 0x0020u16 } else { 0x0001u16 }).to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 0]);
        packet.extend(
            address
                .iter()
                .enumerate()
                .map(|(i, b)| if xor { b ^ COOKIE[i] } else { *b }),
        );
        packet
    }
    #[test]
    fn strict_binding_decode_and_transaction_identity() {
        let transaction = [7; 12];
        for xor in [true, false] {
            let packet = reply(transaction, [8, 8, 8, 8], xor);
            assert_eq!(decode(&packet, &transaction), Ok("8.8.8.8".into()));
        }
        let mut packet = reply(transaction, [8, 8, 8, 8], true);
        assert_eq!(decode(&packet, &[8; 12]), Err("unrelated_response"));
        packet.push(0);
        assert_eq!(decode(&packet, &transaction), Err("invalid_length"));
        assert_eq!(
            decode(&reply(transaction, [224, 0, 0, 1], true), &transaction),
            Err("nonpublic_address")
        );
        assert_eq!(
            decode(&reply(transaction, [192, 168, 1, 1], true), &transaction),
            Err("nonpublic_address")
        );
    }
}
