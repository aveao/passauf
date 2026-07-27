use iso7816_tlv::ber;
use simplelog::warn;
use std::cmp::max;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn asn1_parse_len(data: Vec<u8>) -> (u8, u32) {
    let result: (u8, u32) = match data[0] {
        0..=0x7f => (1, data[0].into()),
        0x80 => (1, 0u32), // TODO: indefinite amount
        0x81 => (2, data[1].into()),
        0x82 => (3, u32::from_be_bytes([0, 0, data[1], data[2]])),
        0x83 => (4, u32::from_be_bytes([0, data[1], data[2], data[3]])),
        0x84 => (5, u32::from_be_bytes([data[1], data[2], data[3], data[4]])),
        0x84.. => (0, 0u32),
    };
    return result;
}

/// Read an INTEGER's value as an unsigned integer.
///
/// Returns None for negative or oversized values, neither of which any field
/// we read here is allowed to be.
pub fn parse_unsigned_integer(tlv: &ber::Tlv) -> Option<u64> {
    let value_bytes = get_tlv_value_bytes(tlv);
    if value_bytes.is_empty() {
        return None;
    }
    // DER pads with a leading zero to keep a high bit from meaning negative.
    let significant = match value_bytes[0] {
        0x00 => &value_bytes[1..],
        // A set high bit without that padding means the value is negative.
        0x80..=0xFF => return None,
        _ => &value_bytes[..],
    };
    if significant.len() > 8 {
        return None;
    }
    let mut result: u64 = 0;
    for byte in significant {
        result = (result << 8) | u64::from(*byte);
    }
    return Some(result);
}

/// Encode a BER-TLV from raw tag bytes and a value.
///
/// iso7816_tlv refuses to build a constructed tag around an opaque value, but
/// PACE's wrappers (0x7C and 0x7F49) are exactly that: constructed tags whose
/// contents we have already serialized. The definite length forms here are the
/// ones ISO/IEC 7816-4 allows.
#[cfg(feature = "pace")]
pub fn encode_ber(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut encoded = tag.to_vec();
    match value.len() {
        // Short form, the length in a single byte.
        0..=127 => encoded.push(value.len() as u8),
        // Long form, one following length byte.
        128..=255 => encoded.extend_from_slice(&[0x81, value.len() as u8]),
        // Long form, two following length bytes.
        _ => encoded.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]),
    }
    encoded.extend_from_slice(value);
    return encoded;
}

pub fn get_tlv_value_bytes(input_tlv: &ber::Tlv) -> Vec<u8> {
    match input_tlv.value() {
        ber::Value::Primitive(data) => {
            return data.clone();
        }
        ber::Value::Constructed(tlvs) => {
            // We don't use constructed values so this is likely dead code, but alas.
            // The output can be adjusted based on the needs that may arise in the future.
            warn!(
                "Trying to get TLV value from a constructed TLV: {:02x?}",
                input_tlv
            );
            assert!(tlvs.len() == 1);
            return tlvs[0].to_vec();
        }
    }
}

pub fn get_tlv_constructed_value(input_tlv: &ber::Tlv) -> Vec<ber::Tlv> {
    match input_tlv.value() {
        ber::Value::Constructed(tlvs) => {
            return tlvs.clone();
        }
        _ => {
            panic!(
                "Tried to get a constructed TLV when there is none: {:02x?}",
                input_tlv
            );
        }
    }
}

pub fn get_tlv_tag(input_tlv: &ber::Tlv) -> u16 {
    // I'm choosing to keep this to 2 bytes for now. It can be up to 3 by the standard.
    let tag_bytes = input_tlv.tag().to_bytes();
    let mut padding_vec: Vec<u8> = vec![0u8; max(2 - tag_bytes.len(), 0)];
    padding_vec.extend_from_slice(tag_bytes);

    let tag_number = u16::from_be_bytes(padding_vec.try_into().unwrap());
    return tag_number;
}

pub fn sort_tlvs_by_tag(tlvs: &Vec<ber::Tlv>) -> HashMap<u16, &ber::Tlv> {
    let mut rapdu_tlvs: HashMap<u16, &ber::Tlv> = HashMap::new();
    for tlv in tlvs.iter() {
        let tag_number = get_tlv_tag(&tlv);
        rapdu_tlvs.insert(tag_number, tlv);
    }
    return rapdu_tlvs;
}

pub fn get_tlvs_by_tag(tlvs: &Vec<ber::Tlv>, desired_tag_number: u16) -> Vec<&ber::Tlv> {
    let mut rapdu_tlvs: Vec<&ber::Tlv> = vec![];
    for tlv in tlvs.iter() {
        let tag_number = get_tlv_tag(&tlv);
        if desired_tag_number == tag_number {
            rapdu_tlvs.push(tlv);
        }
    }
    return rapdu_tlvs;
}

pub fn get_tlv_by_tag(tlvs: &Vec<ber::Tlv>, desired_tag_number: u16) -> Option<&ber::Tlv> {
    for tlv in tlvs.iter() {
        let tag_number = get_tlv_tag(&tlv);
        if desired_tag_number == tag_number {
            return Some(tlv);
        }
    }
    return None;
}

/// Get the current unix time.
///
/// Assumes we're after 1970 and before 292271023045 :^)
pub fn unix_time() -> u64 {
    // the .unwrap() here assumes we're not in <1970
    return SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
}
