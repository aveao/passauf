mod dg_parsers;
mod helpers;
mod icao9303;
mod iso7816;
#[cfg(feature = "proxmark")]
mod proxmark;
mod smartcard_abstractions;
mod types;

use clap::{CommandFactory, Parser};
use simplelog::{info, warn, CombinedLogger, TermLogger};
use smartcard_abstractions::{connect_to_interface_by_name, InterfaceDevice, ProxmarkInterface};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Path of the reader to use.
    #[arg(short, long)]
    path: Option<String>,

    /// Reader backend to use.
    #[arg(short, long, value_name = "proxmark/pcsc", ignore_case = true, default_value_t = ("proxmark".to_string()))]
    reader: String,

    /// Date of birth, YYMMDD (Requires DoE and Doc Number, mutually exclusive with CAN)
    #[arg(
        short = 'b',
        long = "dob",
        value_name = "YYMMDD",
        required_unless_present = "card_access_number"
    )]
    date_of_birth: Option<String>,

    /// Date of document expiry, YYMMDD (Requires DoB and Doc Number, mutually exclusive with CAN)
    #[arg(
        short = 'e',
        long = "doe",
        value_name = "YYMMDD",
        required_unless_present = "card_access_number"
    )]
    date_of_expiry: Option<String>,

    /// Document number (Requires DoB and DoE, mutually exclusive with CAN)
    #[arg(
        short = 'n',
        long = "num",
        required_unless_present = "card_access_number"
    )]
    document_number: Option<String>,

    /// Card Access Number (PACE-only, mutually exclusive with DoB, DoE and Doc Number)
    #[arg(short = 'c', long = "can", required_unless_present_any=["date_of_birth", "date_of_expiry", "document_number"])]
    card_access_number: Option<String>,

    /// Enable debug logging
    #[arg(long = "debug", conflicts_with = "trace", default_value_t = false)]
    debug: bool,

    /// Enable trace logging
    #[arg(long = "trace", conflicts_with = "debug", default_value_t = false)]
    trace: bool,
}

fn main() {
    let args = CliArgs::parse();

    // TODO: this can be improved
    let log_level = if args.debug {
        simplelog::LevelFilter::Debug
    } else if args.trace {
        simplelog::LevelFilter::Trace
    } else {
        simplelog::LevelFilter::Info
    };

    CombinedLogger::init(vec![TermLogger::new(
        log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();

    // Connect to given reader
    let mut interface = connect_to_interface_by_name(&args.reader, &args.path)
        .expect("Couldn't find given interface.");

    // Select a nearby eMRTD
    let mut smartcard = interface
        .select()
        .expect("Couldn't select an eMRTD in range.");
    let mut pace_available = false;

    let file_data = iso7816::select_and_read_file(&mut smartcard, "EF.CardAccess");
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
        let file_data = iso7816::select_and_read_file(&mut smartcard, dg_name);
        match file_data {
            Some(file_data) => {
                (dg_info.parser)(file_data, &dg_info, true);
            }
            None => {}
        }
    }

    info!("Selecting eMRTD LDS1 applet");
    let (_, status_code) = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
        .exchange(&mut smartcard, true);
    assert!(status_code == iso7816::StatusCode::Ok as u16);

    // Authenticate
    if args.card_access_number.is_some() {
        panic!("PACE/CAN isn't implemented, cannot proceed with authentication.");
    }
    let (ks_enc, ks_mac, mut ssc) = icao9303::do_authentication(
        pace_available,
        &mut smartcard,
        &args.document_number.unwrap(),
        &args.date_of_birth.unwrap(),
        &args.date_of_expiry.unwrap(),
    );

    let file_data = iso7816::secure_select_and_read_file(
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
        let file_data = iso7816::secure_select_and_read_file(
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

    // TODO: Read and compare EF_SOD

    // temporary: dump EF_DG2 image
    let file_data = iso7816::secure_select_and_read_file(
        &mut smartcard,
        "EF.DG2",
        true,
        &mut ssc,
        &ks_enc,
        &ks_mac,
    )
    .unwrap();
    let dg_info = icao9303::DATA_GROUPS.get("EF.DG2").unwrap();
    let parse_result = (dg_info.parser)(file_data, &dg_info, true).unwrap();

    let ef_dg2_file: types::EFDG2 = match parse_result {
        types::ParsedDataGroup::EFDG2(ef_com_file) => ef_com_file,
        _ => {
            panic!("Expected EFDG2 but got {:x?}", parse_result);
        }
    };

    let filename =
        "/tmp/EF.DG2".to_owned() + &ef_dg2_file.biometrics[0].image_format.get_extension();
    let mut f = std::fs::File::create(&filename).unwrap();
    std::io::Write::write_all(&mut f, &ef_dg2_file.biometrics[0].data).unwrap();
    f.sync_all().unwrap();
    info!("Saved EF_DG2 image to {}.", &filename);

    drop(smartcard);
}
