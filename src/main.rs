mod dg_parsers;
mod helpers;
mod icao9303;
mod iso7816;
#[cfg(feature = "proxmark")]
mod proxmark;
mod smartcard_abstractions;
mod types;

use rand::Rng;
use simplelog::{info, warn, CombinedLogger, TermLogger};
use smartcard_abstractions::{InterfaceDevice, ProxmarkInterface, Smartcard};
use std::env;

fn do_bac_authentication(
    port: &mut impl Smartcard,
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> (Vec<u8>, Vec<u8>, u64) {
    info!("Starting Basic Access Control");

    // Get RND.IC by calling GET_CHALLENGE.
    let mut apdu = iso7816::apdu_get_challenge();
    let (rapdu, _) = helpers::exchange_apdu(port, &mut apdu, true);
    // get the first 8 bytes of the response, which is the actual response
    // (rest is SW and checksum)
    let rnd_ic = &rapdu[0..8];

    // Generate RND.IFD
    let mut rnd_ifd = [0u8; 8];
    rand::rng().fill(&mut rnd_ifd[..]);

    // Generate keying material K.IFD
    let mut k_ifd = [0u8; 16];
    rand::rng().fill(&mut k_ifd[..]);

    // Calculate K.ENC, E.IFD and M.IFD
    let (k_enc, e_ifd, m_ifd) = icao9303::calculate_bac_eifd_and_mifd(
        rnd_ic,
        &rnd_ifd,
        &k_ifd,
        document_number,
        date_of_birth,
        date_of_expiry,
    );

    // Do EXTERNAL_AUTHENTICATION with the key and MAC we calculated.
    let external_auth_data = vec![e_ifd, m_ifd].concat();
    let mut apdu = iso7816::apdu_external_authentication(external_auth_data);
    let (rapdu, _) = helpers::exchange_apdu(port, &mut apdu, true);
    info!("Successfully authenticated!");

    // Calculate session keys
    let (ks_enc, ks_mac) = icao9303::calculate_bac_session_keys(
        &rapdu[0..40],
        k_enc.as_slice(),
        rnd_ifd.as_slice(),
        k_ifd.as_slice(),
    );

    // Calculate session counter
    let ssc = icao9303::calculate_initial_ssc_bac(rnd_ic, &rnd_ifd);

    return (ks_enc, ks_mac, ssc);
}

fn do_authentication(
    pace_available: bool,
    smartcard: &mut impl Smartcard,
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> (Vec<u8>, Vec<u8>, u64) {
    // TODO: check if reading things without auth is possible, GH#7
    // TODO: make the return type of this an AuthState object,
    // have it state if we need secure comms and what arguments are relevant
    if pace_available {
        info!("PACE is available on this document, but it's not implemented by passauf yet.");
    }
    return do_bac_authentication(smartcard, document_number, date_of_birth, date_of_expiry);
}

fn main() {
    let log_level = simplelog::LevelFilter::Info;

    let args: Vec<String> = env::args().collect();
    let mut interface = ProxmarkInterface::connect(Some(&args[1]));
    CombinedLogger::init(vec![TermLogger::new(
        log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();

    // Select a nearby eMRTD
    let mut smartcard = interface.select().unwrap();

    let mut pace_available = false;

    let file_data = helpers::select_and_read_file(&mut smartcard, "EF.CardAccess");
    let dg_info = icao9303::DATA_GROUPS.get("EF.CardAccess").unwrap();
    match file_data {
        Some(file_data) => {
            pace_available = true;
            (dg_info.parser)(file_data, &dg_info, true);
        }
        None => warn!("PACE isn't available on this eMRTD. Will try BAC."),
    }

    // read all files under the master file
    for (_, (dg_name, dg_info)) in icao9303::DATA_GROUPS.entries.iter().enumerate() {
        if dg_name == &"EF.CardAccess" || dg_info.in_lds1 || (dg_info.pace_only && !pace_available)
        {
            continue;
        }
        let file_data = helpers::select_and_read_file(&mut smartcard, dg_name);
        match file_data {
            Some(file_data) => {
                (dg_info.parser)(file_data, &dg_info, true);
            }
            None => {}
        }
    }

    info!("Selecting eMRTD LDS1 applet");
    let mut apdu = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec());
    let (_, status_code) = helpers::exchange_apdu(&mut smartcard, &mut apdu, true);
    assert!(status_code == iso7816::StatusCode::Ok as u16);

    // Authenticate
    let (ks_enc, ks_mac, mut ssc) =
        do_authentication(pace_available, &mut smartcard, &args[2], &args[3], &args[4]);

    let file_data = helpers::secure_select_and_read_file(
        &mut smartcard,
        "EF.COM",
        true,
        &mut ssc,
        &ks_enc,
        &ks_mac,
    )
    .unwrap();
    let dg_info = icao9303::DATA_GROUPS.get("EF.COM").unwrap();
    let parse_result = (dg_info.parser)(file_data, &dg_info, true).unwrap();
    let ef_com_file: types::EFCom = match parse_result {
        types::ParsedDataGroup::EFCom(ef_com_file) => ef_com_file,
        _ => {
            panic!("Expected EFCom but got {:x?}", parse_result);
        }
    };

    // read all files under the LDS1 file
    for (_, (dg_name, dg_info)) in icao9303::DATA_GROUPS.entries.iter().enumerate() {
        // is_binary is temporary here
        if dg_name == &"EF.COM"
            || !dg_info.in_lds1
            || dg_info.pace_only
            || dg_info.is_binary
            || !ef_com_file.data_group_tag_list.contains(&dg_info.tag)
        {
            continue;
        }
        let file_data = helpers::secure_select_and_read_file(
            &mut smartcard,
            dg_name,
            true,
            &mut ssc,
            &ks_enc,
            &ks_mac,
        );
        match file_data {
            Some(file_data) => {
                (dg_info.parser)(file_data, &dg_info, true);
            }
            None => {}
        }
    }

    // Read and compare EF_SOD

    drop(smartcard);
}
