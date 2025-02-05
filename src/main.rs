mod icao9303;
mod iso7816;
#[cfg(feature = "proxmark")]
mod proxmark;
mod types;
use std::env;
use iso7816::StatusCode;
use log::{debug, info, warn};
use simplelog::{CombinedLogger, TermLogger};
use std::cmp::min;

fn exchange_apdu(
    port: &mut Box<dyn serialport::SerialPort>,
    apdu: &mut iso7816::ApduCommand,
    assert_on_status: bool,
) -> (proxmark::PM3PacketResponseNG, u16) {
    let mut done_exchanging = false;
    // initializing with an empty response here so that compiler doesn't complain
    let mut response = proxmark::PM3PacketResponseNG::empty();
    while !done_exchanging {
        debug!("> APDU: {:x?}", apdu);
        let apdu_bytes = apdu.serialize();
        response = proxmark::exchange_apdu_14a(port, &apdu_bytes, false);
        let status_code_bytes = iso7816::get_status_code_bytes(&response.data);

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

fn asn1_parse_len(data: Vec<u8>) -> (u8, u32) {
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

fn select_and_read_file(
    port: &mut Box<dyn serialport::SerialPort>,
    filename: &str,
) -> Option<Vec<u8>> {
    let dg_info = icao9303::DATA_GROUPS.get(filename).unwrap();

    info!("Selecting {} ({})", filename, dg_info.description);
    let mut apdu = iso7816::apdu_select_file_by_ef(dg_info.file_id);
    let (_, status_code) = exchange_apdu(port, &mut apdu, false);

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
        let (response, status_code) = exchange_apdu(port, &mut apdu, false);
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

fn bac(
    port: &mut Box<dyn serialport::SerialPort>,
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) {
    info!("Starting Basic Access Control");

    // Get RND.IC by calling GET_CHALLENGE.
    let mut apdu = iso7816::apdu_get_challenge();
    let (response, _) = exchange_apdu(port, &mut apdu, true);
    let rnd_ic = &response.data[0..8];

    // Calculate E_IFD and M_IFD
    let (e_ifd, m_ifd) = icao9303::calculate_bac_key_and_mac(
        rnd_ic.to_vec(),
        document_number,
        date_of_birth,
        date_of_expiry,
    );

    // Do EXTERNAL_AUTHENTICATION with the key and MAC we calculated.
    let external_auth_data = vec![e_ifd, m_ifd].concat();
    let mut apdu = iso7816::apdu_external_authentication(external_auth_data);
    let (response, _) = exchange_apdu(port, &mut apdu, true);
    info!("Successfully authenticated!");

    // TODO: calculate session_keys
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let log_level = simplelog::LevelFilter::Info;
    // TODO: make the path adjustable
    let mut port = proxmark::connect(&args[1]);
    CombinedLogger::init(vec![TermLogger::new(
        log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();

    // Select a nearby eMRTD
    proxmark::select_14a(&mut port, false);

    let mut pace_available = false;

    let file_data = select_and_read_file(&mut port, "EF.CardAccess");
    let dg_info = icao9303::DATA_GROUPS.get("EF.CardAccess").unwrap();
    match file_data {
        Some(file_data) => {
            pace_available = true;
            (dg_info.parser)(file_data);
        } // TODO: print about ef cardaccess results
        None => warn!("PACE isn't available on this eMRTD. Will try BAC."),
    }

    // read all files under the master file
    for (_, (dg_name, dg_info)) in icao9303::DATA_GROUPS.entries.iter().enumerate() {
        // debug!("{:?} - {:?}", dg_name, dg_info);
        if dg_name == &"EF.CardAccess" || dg_info.in_lds1 || (dg_info.pace_only && !pace_available)
        {
            continue;
        }
        let file_data = select_and_read_file(&mut port, dg_name);
        match file_data {
            Some(file_data) => (dg_info.parser)(file_data), // TODO: print about it
            None => {}
        }
    }

    info!("Selecting eMRTD LDS1 applet");
    let mut apdu = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec());
    let (_, status_code) = exchange_apdu(&mut port, &mut apdu, true);

    // auth goes here
    bac(&mut port, &args[2], &args[3], &args[4]);

    // read all the rest of files

    proxmark::quit_session(&mut port);
    drop(port);
}
