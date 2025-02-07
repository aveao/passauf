mod dg_parsers;
mod helpers;
mod icao9303;
mod iso7816;
#[cfg(feature = "proxmark")]
mod proxmark;
mod types;

use rand::Rng;
use simplelog::{info, warn, CombinedLogger, TermLogger};
use std::env;

fn do_bac_authentication(
    port: &mut Box<dyn serialport::SerialPort>,
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> (Vec<u8>, Vec<u8>, u64) {
    info!("Starting Basic Access Control");

    // Get RND.IC by calling GET_CHALLENGE.
    let mut apdu = iso7816::apdu_get_challenge();
    let (response, _) = helpers::exchange_apdu(port, &mut apdu, true);
    // get the first 8 bytes of the response, which is the actual response
    // (rest is SW and checksum)
    let rnd_ic = &response.data[0..8];

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
    let (response, _) = helpers::exchange_apdu(port, &mut apdu, true);
    info!("Successfully authenticated!");

    // Calculate session keys
    let (ks_enc, ks_mac) = icao9303::calculate_bac_session_keys(
        &response.data[0..40],
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
    port: &mut Box<dyn serialport::SerialPort>,
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
    return do_bac_authentication(port, document_number, date_of_birth, date_of_expiry);
}

fn main() {
    let log_level = simplelog::LevelFilter::Info;

    let args: Vec<String> = env::args().collect();
    let mut port = proxmark::connect(&args[1]).unwrap();
    CombinedLogger::init(vec![TermLogger::new(
        log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();

    // Select a nearby eMRTD
    let _ = proxmark::select_14a(&mut port, false).unwrap();

    let mut pace_available = false;

    let file_data = helpers::select_and_read_file(&mut port, "EF.CardAccess");
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
        // debug!("{:?} - {:?}", dg_name, dg_info);
        if dg_name == &"EF.CardAccess" || dg_info.in_lds1 || (dg_info.pace_only && !pace_available)
        {
            continue;
        }
        let file_data = helpers::select_and_read_file(&mut port, dg_name);
        match file_data {
            Some(file_data) => {
                (dg_info.parser)(file_data, &dg_info, true);
            }
            None => {}
        }
    }

    info!("Selecting eMRTD LDS1 applet");
    let mut apdu = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec());
    let (_, status_code) = helpers::exchange_apdu(&mut port, &mut apdu, true);
    assert!(status_code == iso7816::StatusCode::Ok as u16);

    // Authenticate
    let (ks_enc, ks_mac, mut ssc) =
        do_authentication(pace_available, &mut port, &args[2], &args[3], &args[4]);

    let file_data =
        helpers::secure_select_and_read_file(&mut port, "EF.COM", true, &mut ssc, &ks_enc, &ks_mac)
            .unwrap();
    let dg_info = icao9303::DATA_GROUPS.get("EF.COM").unwrap();
    (dg_info.parser)(file_data, &dg_info, true);

    // read all the rest of files

    let _ = proxmark::quit_session(&mut port);
    drop(port);
}
