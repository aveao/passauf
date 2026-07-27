use clap::Parser;
use simplelog::{error, info, warn, CombinedLogger, TermLogger};
use std::path::PathBuf;

use passauf::session::{
    self, AccessKey, Authentication, ChipAuthentication, ReadOptions, SessionError,
};
use passauf::smartcard_abstractions::ReaderInterface;

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

impl CliArgs {
    /// Turn the flags into the one thing that unlocks the document.
    ///
    /// clap has already enforced that either a CAN or all three MRZ fields are
    /// present, which is what makes the unwraps here safe.
    fn access_key(&self) -> AccessKey {
        return match &self.card_access_number {
            Some(card_access_number) => AccessKey::Can(card_access_number.clone()),
            None => AccessKey::Mrz {
                document_number: self.document_number.clone().unwrap(),
                date_of_birth: self.date_of_birth.clone().unwrap(),
                date_of_expiry: self.date_of_expiry.clone().unwrap(),
            },
        };
    }
}

/// Summarize what the hash check established, once every file has been read.
fn print_integrity_summary(integrity: &session::Integrity) {
    if !integrity.security_object_read {
        return;
    }

    if integrity.checked.is_empty() {
        warn!("No data group hashes could be checked against EF.SOD.");
    } else if integrity.mismatched.is_empty() {
        info!(
            "<green>All {} data group hashes match EF.SOD.</>",
            integrity.checked.len()
        );
        info!(
            "<d>Note: EF.SOD's own signature is not verified, so this shows the document is \
             internally consistent, not that it is genuine.</>"
        );
    } else {
        error!(
            "<red>{} of {} data groups do NOT match EF.SOD</> (DG{}). The document has been \
             altered, or was read incorrectly.",
            integrity.mismatched.len(),
            integrity.checked.len(),
            integrity
                .mismatched
                .iter()
                .map(|number| number.to_string())
                .collect::<Vec<_>>()
                .join(", DG")
        );
    }

    if !integrity.unchecked.is_empty() {
        info!(
            "<d>Not checked, as they were not read: {}.</>",
            integrity
                .unchecked
                .iter()
                .map(|number| format!("DG{}", number))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
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

    // A CAN is only usable through PACE, so without it there is no point
    // touching a reader at all. Say so before the user goes looking for a card.
    if args.card_access_number.is_some() && !cfg!(feature = "pace") {
        error!("<red>--can needs PACE, but this build of passauf has no PACE support</> (the `pace` feature was disabled at compile time).");
        error!("Rebuild with the `pace` feature, which is enabled by default, or authenticate with --num, --dob and --doe instead.");
        std::process::exit(1);
    }

    let access_key = args.access_key();
    let options = ReadOptions {
        file_prefix: session::file_prefix_for(&access_key),
        access_key,
        // Without --dump the large files aren't worth the wait, since there is
        // nowhere for their contents to go.
        read_binary_files: args.dump_path.is_some(),
        dump_path: args.dump_path.clone(),
        print: true,
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

    let result = match session::read_document(&mut smartcard, &options, &mut |_| {}) {
        Ok(result) => result,
        Err(error) => {
            error!("<red>{}</>", error);
            // The reader still needs releasing, so fall out rather than exiting
            // from here.
            drop(smartcard);
            std::process::exit(match error {
                SessionError::NoFileList => 2,
                _ => 1,
            });
        }
    };

    match &result.authentication {
        Authentication::Pace { algorithm } => {
            info!("<d>Authenticated with PACE ({})</>", algorithm)
        }
        Authentication::Bac => info!("<d>Authenticated with BAC</>"),
    }
    match &result.chip_authentication {
        ChipAuthentication::Passed { source, curve } => info!(
            "<green>Chip Authentication passed</> against the {} key on {}.",
            source, curve
        ),
        ChipAuthentication::Failed => error!("<red>Chip Authentication failed.</>"),
        // Both of these already said their piece as warnings while reading.
        ChipAuthentication::NoKeyAvailable | ChipAuthentication::NotAttempted => {}
    }

    print_integrity_summary(&result.integrity);

    drop(smartcard);
}
