use crate::icao9303;
use crate::iso7816;
use crate::proxmark;
use crate::smartcard_abstractions::Smartcard;
use iso7816::StatusCode;
use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::cmp::{max, min};
use std::collections::HashMap;

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

pub fn exchange_apdu(
    smartcard: &mut impl Smartcard,
    apdu: &mut iso7816::ApduCommand,
    assert_on_status: bool,
) -> (Vec<u8>, u16) {
    let (rapdu, status_code) = secure_exchange_apdu(
        smartcard,
        apdu,
        assert_on_status,
        false,
        &mut 0,
        &vec![],
        &vec![],
    );
    return (rapdu, status_code);
}

pub fn secure_exchange_apdu(
    smartcard: &mut impl Smartcard,
    apdu: &mut iso7816::ApduCommand,
    assert_on_status: bool,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> (Vec<u8>, u16) {
    let mut done_exchanging = false;
    let mut rapdu_data: Vec<u8> = vec![];
    let mut status_code_bytes: Vec<u8> = vec![];
    while !done_exchanging {
        debug!("> APDU (secure: {:?}): {:x?}", secure_comms, apdu);
        let apdu_bytes = if secure_comms {
            apdu.bac_secure_serialize(ssc, ks_enc, ks_mac)
        } else {
            apdu.serialize()
        };

        rapdu_data = smartcard.exchange_apdu(&apdu_bytes).unwrap();
        status_code_bytes = iso7816::get_status_code_bytes(&rapdu_data);

        // - 4 bytes for status code and and hash
        if secure_comms {
            match iso7816::parse_secure_rapdu(
                &rapdu_data[..rapdu_data.len() - 4],
                ssc,
                ks_enc,
                ks_mac,
            ) {
                Some(data) => {
                    rapdu_data = data;
                }
                None => {}
            };
        } else {
            rapdu_data = rapdu_data[..rapdu_data.len() - 4].to_vec();
        }

        // ISO/IEC 7816-4 says:
        // If SW1 is set to '6C', then the process is aborted and before issuing
        // any other command, the same command may be re-issued using SW2
        // (exact number of available data bytes) as short Le field.
        if status_code_bytes[0] == 0x6C {
            debug!(
                "Got a SW1=6C, re-requesting {:?} with Le={:?}",
                apdu, status_code_bytes[1]
            );
            apdu.max_resp_len = u16::from(status_code_bytes[1]);
        } else {
            done_exchanging = true;
        }
    }

    // TODO: validate hash
    let status_code = u16::from_be_bytes(status_code_bytes.try_into().unwrap());

    if assert_on_status {
        // Intentionally not checking 61 here.
        // One shouldn't use assert_on_status if you handle 61.
        assert!(status_code == StatusCode::Ok as u16);
    }

    return (rapdu_data, status_code);
}

pub fn select_and_read_file(smartcard: &mut impl Smartcard, filename: &str) -> Option<Vec<u8>> {
    return secure_select_and_read_file(smartcard, filename, false, &mut 0, &vec![], &vec![]);
}

pub fn secure_select_and_read_file(
    smartcard: &mut impl Smartcard,
    filename: &str,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> Option<Vec<u8>> {
    let dg_info = icao9303::DATA_GROUPS.get(filename).unwrap();

    info!("<d>Selecting {} ({})</>", filename, dg_info.description);
    let mut apdu = iso7816::apdu_select_file_by_ef(dg_info.file_id);
    let (_, status_code) = secure_exchange_apdu(
        smartcard,
        &mut apdu,
        false,
        secure_comms,
        ssc,
        ks_enc,
        ks_mac,
    );

    if status_code != StatusCode::Ok as u16 {
        warn!("{} not found (this is probably fine).", filename);
        return None;
    }

    info!("<d>Reading {} ({})</>", filename, dg_info.description);
    let mut total_data: Vec<u8> = vec![];
    let mut bytes_to_read = 0x05;
    let mut file_len: u16 = 0;
    while bytes_to_read > 0 {
        let mut apdu = iso7816::apdu_read_binary(total_data.len() as u16, bytes_to_read);
        let (apdu_data, status_code) = secure_exchange_apdu(
            smartcard,
            &mut apdu,
            false,
            secure_comms,
            ssc,
            ks_enc,
            ks_mac,
        );
        let status_code_bytes = status_code.to_be_bytes();

        // Unfortunately, ICAO 9303 does not allow us to read file sizes.
        // We must, therefore, read the ASN.1 header to get the size.
        // I'd love to replace this with a better solution if I find one.
        if total_data.is_empty() && status_code_bytes[0] == 0x90 {
            // TODO: this does not account for non-ASN1 files. We can use .is_asn1.
            let (field_len, asn1_len) = asn1_parse_len(apdu_data[1..].to_vec());
            // TODO: rethink this u16.
            // We should account for u32 even tho its unlikely.
            // offset by 1 as we're skipping the initial tag.
            file_len = (1u32 + field_len as u32 + asn1_len) as u16;
        }

        debug!(
            "Reading file, file_len: {:?} total_data.len(): {:?} apdu_data.len(): {:?}",
            file_len,
            total_data.len(),
            apdu_data.len()
        );

        // ISO/IEC 7816-4 says:
        // If SW1 is set to '61', then the process is completed and before issuing
        // any other command, a get response command may be issued with the same CLA
        // and using SW2 (number of data bytes still available) as short Le field.
        if status_code_bytes[0] == 0x61 {
            bytes_to_read = u16::from(status_code_bytes[1]);
        } else if (((total_data.len() + apdu_data.len()) as u16) < file_len)
            && (status_code_bytes[0] == 0x90)
        {
            bytes_to_read = min(0x80, file_len - (total_data.len() + apdu_data.len()) as u16);
        } else {
            bytes_to_read = 0;
            // if the read failed at some point, return None
            // TODO: this'd be a good spot to report status code text
            if status_code_bytes[0] != 0x90 {
                return None;
            }
        }

        total_data.extend(apdu_data);
    }
    debug!("Read file ({:?}b): {:?}", total_data.len(), total_data);
    // only return data if it's not empty.
    return if total_data.is_empty() {
        None
    } else {
        Some(total_data)
    };
}
