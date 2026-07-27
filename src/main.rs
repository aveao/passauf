mod dg_parsers;
mod helpers;
mod icao9303;
mod iso7816;
#[cfg(feature = "pace")]
mod pace;
#[cfg(feature = "proxmark")]
mod proxmark;
mod secure_messaging;
mod smartcard_abstractions;
mod types;

use clap::Parser;
use simplelog::{info, warn, CombinedLogger, TermLogger};
use smartcard_abstractions::ReaderInterface;
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
    #[arg(short = 'i', long, value_name = "proxmark/pcsc", ignore_case = true, default_value_t = ReaderInterface::PCSC)]
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
    let (_, _, parsed_card_access) = helpers::read_file_by_name(
        &mut smartcard,
        DataGroupEnum::EFCardAccess,
        &filename_distinguisher,
        &args.dump_path,
    );

    // A document can carry EF.CardAccess without offering PACE in it, so this
    // has to come from the parsed SecurityInfos rather than from the file
    // merely being readable.
    #[cfg(feature = "pace")]
    let card_access = match parsed_card_access {
        Some(types::ParsedDataGroup::EFCardAccess(card_access)) => Some(card_access),
        _ => None,
    };
    #[cfg(feature = "pace")]
    let pace_available = card_access
        .as_ref()
        .map_or(false, |card_access| card_access.supports_pace());
    #[cfg(not(feature = "pace"))]
    let pace_available = false;

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

    // Authenticate, preferring PACE when the document offers a variant we can
    // run, and falling back to BAC otherwise.
    #[cfg(feature = "pace")]
    let pace_session = match (pace_available, &card_access) {
        (true, Some(card_access)) => {
            let pace_password = match &args.card_access_number {
                Some(card_access_number) => {
                    Some(pace::password::Password::Can(card_access_number.clone()))
                }
                // The MRZ password needs all three fields, which clap only
                // guarantees when no CAN was given.
                None => match (
                    &args.document_number,
                    &args.date_of_birth,
                    &args.date_of_expiry,
                ) {
                    (Some(document_number), Some(date_of_birth), Some(date_of_expiry)) => {
                        Some(pace::password::Password::Mrz {
                            document_number: document_number.clone(),
                            date_of_birth: date_of_birth.clone(),
                            date_of_expiry: date_of_expiry.clone(),
                        })
                    }
                    _ => None,
                },
            };

            match pace_password {
                Some(pace_password) => pace::try_pace(
                    &mut smartcard,
                    card_access.pace_infos().as_slice(),
                    &pace_password,
                ),
                None => None,
            }
        }
        _ => None,
    };
    #[cfg(not(feature = "pace"))]
    let pace_session: Option<secure_messaging::SecureMessaging> = None;

    let mut sm = match pace_session {
        Some(sm) => sm,
        None => {
            if args.card_access_number.is_some() {
                panic!(
                    "PACE did not succeed and BAC needs the document number, date of birth \
                     and date of expiry, which a CAN cannot substitute for."
                );
            }
            if pace_available {
                warn!("Falling back to BAC.");
            }
            icao9303::do_bac_authentication(
                &mut smartcard,
                &args.document_number.as_ref().unwrap(),
                args.date_of_birth.as_ref().unwrap(),
                args.date_of_expiry.as_ref().unwrap(),
            )
        }
    };

    // Read EF.COM, which contains a file list
    let (_, _, parse_result) = helpers::secure_read_file_by_name(
        &mut smartcard,
        DataGroupEnum::EFCom,
        &filename_distinguisher,
        &args.dump_path,
        Some(&mut sm),
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
            Some(&mut sm),
        );
    }

    // TODO: Read EF_SOD and compare hashes of files

    drop(smartcard);
}
