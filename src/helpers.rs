use iso7816_tlv::ber;
use simplelog::warn;
use std::cmp::max;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::icao9303;
use crate::iso7816;
use crate::smartcard_abstractions::Smartcard;
use crate::types::ParsedDataGroup;

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

/// Selects, reads, parses and dumps file
///
/// Returns (dg_info, file_read, parsed_data)
pub fn read_file_by_name<'a>(
    smartcard: &'a mut Box<impl Smartcard + ?Sized>,
    file: icao9303::DataGroupEnum,
    filename_distinguisher: &String,
    base_dump_path: &Option<PathBuf>,
) -> (
    &'a icao9303::DataGroup,
    Option<Vec<u8>>,
    Option<ParsedDataGroup>,
) {
    let dg_info = &icao9303::DATA_GROUPS[file as usize];
    let (file_read, parsed_data) =
        read_file(smartcard, &dg_info, filename_distinguisher, base_dump_path);
    return (dg_info, file_read, parsed_data);
}

/// Selects, reads, parses and dumps file
///
/// Returns (file_read, parsed_data)
pub fn read_file(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    dg_info: &icao9303::DataGroup,
    filename_distinguisher: &String,
    base_dump_path: &Option<PathBuf>,
) -> (Option<Vec<u8>>, Option<ParsedDataGroup>) {
    return secure_read_file(
        smartcard,
        &dg_info,
        filename_distinguisher,
        base_dump_path,
        false,
        &mut 0,
        &vec![],
        &vec![],
    );
}

/// Selects, reads, parses and dumps file with secure comms
///
/// Returns (dg_info, file_read, parsed_data)
pub fn secure_read_file_by_name<'a>(
    smartcard: &'a mut Box<impl Smartcard + ?Sized>,
    file: icao9303::DataGroupEnum,
    filename_distinguisher: &String,
    base_dump_path: &Option<PathBuf>,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> (
    &'a icao9303::DataGroup,
    Option<Vec<u8>>,
    Option<ParsedDataGroup>,
) {
    let dg_info = &icao9303::DATA_GROUPS[file as usize];
    let (file_read, parsed_data) = secure_read_file(
        smartcard,
        &dg_info,
        filename_distinguisher,
        base_dump_path,
        secure_comms,
        ssc,
        ks_enc,
        ks_mac,
    );
    return (dg_info, file_read, parsed_data);
}

/// Selects, reads, parses and dumps file with secure comms
///
/// Returns (file_read, parsed_data)
pub fn secure_read_file(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    dg_info: &icao9303::DataGroup,
    filename_distinguisher: &String,
    base_dump_path: &Option<PathBuf>,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> (Option<Vec<u8>>, Option<ParsedDataGroup>) {
    let file_read =
        iso7816::select_and_read_file(smartcard, dg_info, secure_comms, ssc, ks_enc, ks_mac);
    let mut parsed_data: Option<ParsedDataGroup> = None;
    match file_read {
        Some(ref file_data) => {
            parsed_data = (dg_info.parser)(&file_data, &dg_info, true);
            let filename = format!("{}-{}", filename_distinguisher, dg_info.name).replace(".", "_");

            if base_dump_path.is_some() {
                let _ = (dg_info.dumper)(
                    &file_data,
                    &parsed_data,
                    base_dump_path.as_ref().unwrap(),
                    &filename,
                );
            }
        }
        None => {}
    }
    return (file_read, parsed_data);
}

/// Get the current unix time.
///
/// Assumes we're after 1970 and before 292271023045 :^)
pub(crate) fn unix_time() -> u64 {
    // the .unwrap() here assumes we're not in <1970
    return SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
}
