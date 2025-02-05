use crate::icao9303;
use crate::iso7816;
use crate::proxmark;
use iso7816::StatusCode;
use log::{debug, info, warn};
use std::cmp::min;

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

pub fn asn1_gen_len(len: usize) -> Vec<u8> {
    // We're casting to u32 here as we don't support bigger values.
    let len_bytes = (len as u32).to_be_bytes();
    let length_encoder: &[u8] = match len as u32 {
        0..=0x7f => &[len_bytes[3]],
        0x80..=0xff => &[0x81, len_bytes[3]],
        0x100..=0xffff => &[0x82, len_bytes[2], len_bytes[3]],
        0x10000..=0xffffff => &[0x83, len_bytes[1], len_bytes[2], len_bytes[3]],
        0x1000000..=0xffffffff => &[0x84, len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]],
    };
    return length_encoder.to_vec();
}

pub fn exchange_apdu(
    port: &mut Box<dyn serialport::SerialPort>,
    apdu: &mut iso7816::ApduCommand,
    assert_on_status: bool,
) -> (proxmark::PM3PacketResponseNG, u16) {
    return secure_exchange_apdu(
        port,
        apdu,
        assert_on_status,
        false,
        &mut 0,
        &vec![],
        &vec![],
    );
}

pub fn secure_exchange_apdu(
    port: &mut Box<dyn serialport::SerialPort>,
    apdu: &mut iso7816::ApduCommand,
    assert_on_status: bool,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> (proxmark::PM3PacketResponseNG, u16) {
    let mut done_exchanging = false;
    // initializing with an empty response here so that compiler doesn't complain
    let mut response = proxmark::PM3PacketResponseNG::empty();
    while !done_exchanging {
        debug!("> APDU (secure: {:?}): {:x?}", secure_comms, apdu);
        let apdu_bytes = if secure_comms {
            apdu.bac_secure_serialize(ssc, ks_enc, ks_mac)
        } else {
            apdu.serialize()
        };
        response = proxmark::exchange_apdu_14a(port, &apdu_bytes, false).unwrap();
        let status_code_bytes = iso7816::get_status_code_bytes(&response.data);

        if secure_comms {
            // TODO: validate response here
            *ssc += 1;
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
    let status_code = iso7816::get_status_code(&response.data);

    if assert_on_status {
        // Intentionally not checking 61 here.
        // One shouldn't use assert_on_status if you handle 61.
        assert!(status_code == StatusCode::Ok as u16);
    }

    return (response, status_code);
}

pub fn select_and_read_file(
    port: &mut Box<dyn serialport::SerialPort>,
    filename: &str,
) -> Option<Vec<u8>> {
    return secure_select_and_read_file(port, filename, false, &mut 0, &vec![], &vec![]);
}

pub fn secure_select_and_read_file(
    port: &mut Box<dyn serialport::SerialPort>,
    filename: &str,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> Option<Vec<u8>> {
    let dg_info = icao9303::DATA_GROUPS.get(filename).unwrap();

    info!("Selecting {} ({})", filename, dg_info.description);
    let mut apdu = iso7816::apdu_select_file_by_ef(dg_info.file_id);
    let (_, status_code) =
        secure_exchange_apdu(port, &mut apdu, false, secure_comms, ssc, ks_enc, ks_mac);

    if status_code != StatusCode::Ok as u16 {
        warn!("{} not found (this is probably fine).", filename);
        return None;
    }

    info!("Reading {} ({})", filename, dg_info.description);
    let mut data: Vec<u8> = vec![];
    let mut bytes_to_read = 0x05;
    let mut total_len: u16 = 0;
    while bytes_to_read > 0 {
        let mut apdu = iso7816::apdu_read_binary(data.len() as u16, bytes_to_read);
        let (response, status_code) =
            secure_exchange_apdu(port, &mut apdu, false, secure_comms, ssc, ks_enc, ks_mac);
        let status_code_bytes = status_code.to_be_bytes();
        // - 4 bytes for status code and and hash
        let read_byte_count = response.data.len() - 4;

        // Unfortunately, ICAO 9303 does not allow us to read file sizes.
        // We must, therefore, read the ASN.1 header to get the size.
        // I'd love to replace this with a better solution if I find one.
        if data.is_empty() && status_code_bytes[0] == 0x90 {
            // TODO: this does not account for non-ASN1 files. We can use .is_asn1.
            let (field_len, asn1_len) = asn1_parse_len(response.data[1..].to_vec());
            // TODO: rethink this u16.
            // We should account for u32 even tho its unlikely.
            // offset by 1 as we're skipping the initial tag.
            total_len = (1u32 + field_len as u32 + asn1_len) as u16;
        }

        debug!(
            "Reading file, total_len: {:?} data.len(): {:?} read_byte_count: {:?}",
            total_len,
            data.len(),
            read_byte_count
        );

        // ISO/IEC 7816-4 says:
        // If SW1 is set to '61', then the process is completed and before issuing
        // any other command, a get response command may be issued with the same CLA
        // and using SW2 (number of data bytes still available) as short Le field.
        if status_code_bytes[0] == 0x61 {
            bytes_to_read = u16::from(status_code_bytes[1]);
        } else if (((data.len() + read_byte_count) as u16) < total_len)
            && (status_code_bytes[0] == 0x90)
        {
            bytes_to_read = min(0x80, total_len - (data.len() + read_byte_count) as u16);
        } else {
            bytes_to_read = 0;
            // if the read failed at some point, return None
            // TODO: this'd be a good spot to report status code text
            if status_code_bytes[0] != 0x90 {
                return None;
            }
        }

        let new_data = response.data[0..read_byte_count].to_vec();
        data.extend(new_data);
    }
    debug!("Read file ({:?}b): {:?}", data.len(), data);
    // only return data if it's not empty.
    return if data.is_empty() { None } else { Some(data) };
}
