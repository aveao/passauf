mod dg_parsers;
mod helpers;
mod icao9303;
mod iso7816;
#[cfg(feature = "proxmark")]
mod proxmark;
mod smartcard_abstractions;
mod types;

use clap::Parser;
use simplelog::{info, warn, CombinedLogger, TermLogger};
use smartcard_abstractions::{InterfaceDevice, ReaderInterface};
use std::path::PathBuf;
use types::DataGroupEnum;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Dump files? (path can be optionally supplied, defaults to current directory)
    #[arg(long = "dump", value_name = "PATH", default_missing_value = ".", value_parser = clap::value_parser!(PathBuf), num_args = 0..=1)]
    dump_path: Option<PathBuf>,

    /// Path of the reader to use.
    #[arg(short = 'p', long, value_name = "PATH")]
    reader: Option<String>,

    /// Reader backend interface to use.
    #[arg(short = 'i', long, value_name = "proxmark/pcsc", ignore_case = true, default_value_t = ReaderInterface::Proxmark)]
    backend: ReaderInterface,

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

    /// Log level (trace/debug/info/warn/error)
    #[arg(long = "level", ignore_case = true, default_value_t = simplelog::LevelFilter::Info)]
    log_level: simplelog::LevelFilter,
}

fn main() {
    let args = CliArgs::parse();

    CombinedLogger::init(vec![TermLogger::new(
        args.log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();

    let filename_distinguisher = match args.document_number.as_ref() {
        Some(document_number) => document_number,
        None => &helpers::unix_time().to_string(),
    };

    // Connect to given reader
    let mut interface = args
        .backend
        .connect(&args.reader)
        .expect("Couldn't find given interface.");

    // Select a nearby eMRTD
    let mut smartcard = interface
        .select()
        .expect("Couldn't select an eMRTD in range.");

    // Read EF.CardAccess
    let (_, file_read, _) = helpers::read_file_by_name(
        &mut smartcard,
        DataGroupEnum::EFCardAccess,
        &filename_distinguisher,
        &args.dump_path,
    );
    // TODO: Use parsed_data.is_some() here when we finally can parse EF.CardAccess
    let pace_available = file_read.is_some();
    if !pace_available {
        warn!("PACE isn't available on this eMRTD. Will authenticate with BAC.");
    }

    // Read all files under the master file
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.CardAccess"
            || dg_info.in_lds1
            || (dg_info.pace_only && !pace_available)
        {
            continue;
        }
        helpers::read_file(
            &mut smartcard,
            dg_info,
            &filename_distinguisher,
            &args.dump_path,
        );
    }

    // Select eMRTD applet
    info!("Selecting eMRTD LDS1 applet");
    let _ = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
        .exchange(&mut smartcard, true);

    // Authenticate
    if args.card_access_number.is_some() {
        panic!("PACE/CAN isn't implemented, cannot proceed with authentication.");
    }
    let (ks_enc, ks_mac, mut ssc) = icao9303::do_authentication(
        pace_available,
        &mut smartcard,
        &args.document_number.as_ref().unwrap(),
        &args.date_of_birth.unwrap(),
        &args.date_of_expiry.unwrap(),
    );

    // Read EF.COM, which contains a file list
    let (_, _, parse_result) = helpers::secure_read_file_by_name(
        &mut smartcard,
        DataGroupEnum::EFCom,
        &filename_distinguisher,
        &args.dump_path,
        true,
        &mut ssc,
        &ks_enc,
        &ks_mac,
    );
    let parsed_ef_com = parse_result.unwrap();
    let ef_com_file: types::EFCom = match parsed_ef_com {
        types::ParsedDataGroup::EFCom(ef_com_file) => ef_com_file,
        _ => {
            panic!("Expected EFCom but got {:x?}", parsed_ef_com);
        }
    };

    // read all files under the LDS1 file
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.COM"
            || !dg_info.in_lds1
            || dg_info.pace_only
            || (dg_info.is_binary && args.dump_path.is_none())
            || !ef_com_file.data_group_tag_list.contains(&dg_info.tag)
        {
            continue;
        }

        helpers::secure_read_file(
            &mut smartcard,
            dg_info,
            &filename_distinguisher,
            &args.dump_path,
            true,
            &mut ssc,
            &ks_enc,
            &ks_mac,
        );
    }

    // TODO: Read EF_SOD and compare hashes of files

    drop(smartcard);
}
