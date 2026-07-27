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
#[cfg(feature = "pace")]
use simplelog::debug;
use simplelog::{error, info, warn, CombinedLogger, TermLogger};
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

/// Complete a PACE-CAM check against the keys DG14 offers.
///
/// A pass proves the chip holds the private key for the Chip Authentication key
/// it presented. It does not prove that key belongs to a genuine document:
/// ICAO 9303 p11 section 4.4.3.5.2 requires Passive Authentication alongside
/// CAM for that, and while EF.SOD's hashes are checked, its signature is not.
#[cfg(feature = "pace")]
fn verify_chip_authentication(
    pending: &pace::PendingChipAuthentication,
    keys: &[types::ef_cardaccess::ChipAuthenticationPublicKeyInfo],
    source: &str,
) -> bool {
    if keys.is_empty() {
        debug!("{} offers no chip authentication public key.", source);
        return false;
    }

    // A chip may hold several keys, so simply try each. Filtering by the
    // domain parameter ID first would be wrong: a chip is free to spell its
    // curve out as explicit domain parameters instead of naming a standardized
    // one, and then there is no ID to compare. verify() validates the point
    // against the curve PACE ran over anyway, so a key that belongs to some
    // other curve is rejected there.
    for key_info in keys.iter() {
        if pending.verify(&key_info.public_key) {
            info!(
                "<green>Chip Authentication passed</> (the chip holds the private key for its \
                 {} key on {}).",
                source,
                pending.curve()
            );
            info!(
                "<d>Note: without Passive Authentication that key itself is unverified, so this \
                 does not prove the document is genuine.</>"
            );
            return true;
        }
    }

    debug!(
        "No key in {} matches the chip's mapping key ({} tried).",
        source,
        keys.len()
    );
    return false;
}

/// Hold one data group's contents against the hash EF.SOD records for it.
///
/// Returns None when EF.SOD says nothing about this data group, which is not an
/// error in itself but does mean nothing was checked.
fn check_data_group_hash(
    security_object: &types::EFSOD,
    dg_info: &types::DataGroup,
    file_data: &[u8],
) -> Option<bool> {
    let expected = security_object
        .data_group_hashes
        .iter()
        .find(|data_group_hash| data_group_hash.data_group_number == u64::from(dg_info.dg_num))?;

    // The hash covers the file exactly as read, outer tag included.
    let actual = security_object.hash_algorithm.hash(file_data);
    if actual == expected.hash {
        info!(
            "<green>{} matches its {} hash in EF.SOD.</>",
            dg_info.name, security_object.hash_algorithm
        );
        return Some(true);
    }

    error!(
        "<red>{} does NOT match its hash in EF.SOD.</> Expected {}, got {}.",
        dg_info.name,
        expected
            .hash
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>(),
        actual
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    );
    return Some(false);
}

/// Report where EF.COM's file list and EF.SOD's hash list disagree.
///
/// EF.SOD is signed and EF.COM is not, so EF.COM listing fewer data groups than
/// EF.SOD covers is the interesting direction: it is what removing a data group
/// from a document would look like to a reader that trusts EF.COM.
fn data_groups_missing_from_ef_com(
    ef_com: &types::EFCom,
    security_object: &types::EFSOD,
) -> Vec<u64> {
    let mut missing: Vec<u64> = vec![];
    for data_group_hash in security_object.data_group_hashes.iter() {
        let dg_info = types::DATA_GROUPS.iter().find(|dg_info| {
            dg_info.in_lds1 && u64::from(dg_info.dg_num) == data_group_hash.data_group_number
        });
        match dg_info {
            Some(dg_info) if !ef_com.data_group_tag_list.contains(&dg_info.tag) => {
                missing.push(data_group_hash.data_group_number)
            }
            _ => continue,
        }
    }
    return missing;
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

    // Read EF.CardAccess. Only PACE has any use for what's in it.
    #[cfg_attr(not(feature = "pace"), allow(unused_variables))]
    let (_, card_access_file, parsed_card_access) = helpers::read_file_by_name(
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
    // Without the feature there is no parser for EF.CardAccess, so we cannot
    // tell what the document offers, only that we cannot use it.
    #[cfg(not(feature = "pace"))]
    let pace_available = false;

    if !pace_available {
        // Both arms compile either way, so this stays one readable block.
        if cfg!(feature = "pace") {
            warn!("PACE isn't available on this eMRTD. Will authenticate with BAC.");
        } else if card_access_file.is_some() {
            // EF.CardAccess exists purely to carry PACE parameters, so a
            // document that has one almost certainly supports PACE. Blaming the
            // document here would send the user looking in the wrong place.
            warn!("<red>This build of passauf has no PACE support</> (the `pace` feature was disabled at compile time).");
            warn!(
                "This eMRTD has an EF.CardAccess, so it almost certainly does support PACE. \
                 Rebuild with the `pace` feature, which is enabled by default, to use it."
            );
            warn!("Falling back to BAC, which will fail outright if this document is PACE-only.");
        } else {
            warn!("PACE isn't available on this eMRTD. Will authenticate with BAC.");
        }
    }

    // Read all files under the master file
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.CardAccess"
            // EF.CardSecurity needs PACE, so it is read further down.
            || dg_info.name == "EF.CardSecurity"
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

    // Authenticate, preferring PACE when the document offers a variant we can
    // run, and falling back to BAC otherwise.
    //
    // PACE runs here, before the eMRTD applet is selected, which is the order
    // ICAO 9303 p11 Appendix J gives and which leaves the master file selected
    // so EF.CardSecurity can be read afterwards. BAC is the other way round: it
    // authenticates against the applet, so that path selects it first.
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
    let pace_session: Option<(secure_messaging::SecureMessaging, Option<()>)> = None;

    // Chip Authentication Mapping hands back a check that can only be completed
    // once DG14 has been read, which needs secure messaging to be up first.
    #[cfg(feature = "pace")]
    let mut pending_chip_authentication = None;

    let mut sm = match pace_session {
        Some((mut sm, pending)) => {
            #[cfg(feature = "pace")]
            {
                pending_chip_authentication = pending;

                // Still at the master file, and secure messaging is up, so this
                // is the one moment EF.CardSecurity can be read. It is where
                // ICAO 9303 p11 Appendix I takes the PACE-CAM key from, and a
                // document can publish a key here that DG14 never mentions.
                if pending_chip_authentication.is_some() {
                    let (_, _, parsed_card_security) = helpers::secure_read_file_by_name(
                        &mut smartcard,
                        DataGroupEnum::EFCardSecurity,
                        &filename_distinguisher,
                        &args.dump_path,
                        Some(&mut sm),
                    );
                    if let Some(types::ParsedDataGroup::EFCardSecurity(ref card_security)) =
                        parsed_card_security
                    {
                        if let Some(pending) = pending_chip_authentication.take() {
                            if verify_chip_authentication(
                                &pending,
                                &card_security.chip_authentication_public_keys,
                                "EF.CardSecurity",
                            ) {
                                // Verified, so nothing is left pending.
                            } else {
                                // DG14 gets a turn once we are inside LDS1.
                                pending_chip_authentication = Some(pending);
                            }
                        }
                    }
                }
            }
            #[cfg(not(feature = "pace"))]
            let _ = pending;

            // Selecting the applet now happens over secure messaging.
            info!("Selecting eMRTD LDS1 applet");
            let _ = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
                .secure_exchange(&mut smartcard, true, Some(&mut sm));
            sm
        }
        None => {
            if args.card_access_number.is_some() {
                // A CAN is only ever usable through PACE, so there is nothing
                // to fall back to.
                panic!(
                    "PACE did not succeed, and a CAN cannot be used with BAC, which needs the \
                     document number, date of birth and date of expiry instead."
                );
            }
            if pace_available {
                warn!("Falling back to BAC.");
            }
            // BAC authenticates against the applet, so it has to be selected
            // first, and plainly.
            info!("Selecting eMRTD LDS1 applet");
            let _ = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
                .exchange(&mut smartcard, true);
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

    // Read EF.SOD, which records a hash of every data group. It is not itself
    // listed in EF.COM's tag list, so it has to be asked for by name.
    let (_, _, parse_result) = helpers::secure_read_file_by_name(
        &mut smartcard,
        DataGroupEnum::EFSod,
        &filename_distinguisher,
        &args.dump_path,
        Some(&mut sm),
    );
    let security_object = match parse_result {
        Some(types::ParsedDataGroup::EFSOD(security_object)) => Some(security_object),
        _ => {
            warn!("Could not read EF.SOD, so data group hashes cannot be checked.");
            None
        }
    };

    // EF.SOD covers the data groups but not EF.COM, so the two can disagree
    // about which are present. Saying so is worthwhile: EF.COM is what the read
    // loop below trusts.
    if let Some(ref security_object) = security_object {
        for data_group_number in data_groups_missing_from_ef_com(&ef_com_file, security_object) {
            warn!(
                "EF.SOD covers DG{} but EF.COM does not list it, so it will not be read. \
                 EF.COM is not covered by EF.SOD, so an entry removed from it cannot be \
                 detected by EF.SOD's signature.",
                data_group_number
            );
        }
    }

    let mut hashes_checked: Vec<u64> = vec![];
    let mut hashes_mismatched: Vec<u64> = vec![];

    // read all files under the LDS1 file
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.COM"
            || dg_info.name == "EF.SOD"
            || !dg_info.in_lds1
            || dg_info.pace_only
            || (dg_info.is_binary && args.dump_path.is_none())
            || !ef_com_file.data_group_tag_list.contains(&dg_info.tag)
        {
            continue;
        }

        #[cfg_attr(not(feature = "pace"), allow(unused_variables))]
        let (file_read, parsed_data) = helpers::secure_read_file(
            &mut smartcard,
            dg_info,
            &filename_distinguisher,
            &args.dump_path,
            Some(&mut sm),
        );

        // Hash what was actually read and hold it against EF.SOD.
        if let (Some(ref security_object), Some(ref file_data)) = (&security_object, &file_read) {
            match check_data_group_hash(security_object, dg_info, file_data) {
                Some(true) => hashes_checked.push(dg_info.dg_num.into()),
                Some(false) => {
                    hashes_checked.push(dg_info.dg_num.into());
                    hashes_mismatched.push(dg_info.dg_num.into());
                }
                // EF.SOD says nothing about this data group.
                None => {}
            }
        }

        // DG14 carries the chip's static Chip Authentication key, which is what
        // a pending PACE-CAM check has been waiting for.
        #[cfg(feature = "pace")]
        if let Some(pending) = pending_chip_authentication.take() {
            match parsed_data {
                Some(types::ParsedDataGroup::EFDG14(ref dg14)) => {
                    if !verify_chip_authentication(
                        &pending,
                        &dg14.chip_authentication_public_keys,
                        "DG14",
                    ) {
                        warn!(
                            "Chip Authentication FAILED: no key in EF.CardSecurity or DG14 \
                             matches the chip's mapping key. The chip may not be genuine."
                        );
                    }
                }
                // Not DG14, so keep waiting.
                _ => pending_chip_authentication = Some(pending),
            }
        }
    }

    #[cfg(feature = "pace")]
    if pending_chip_authentication.is_some() {
        warn!(
            "Chip Authentication Mapping was used, but the document has no readable DG14 \
             to check it against, so the chip's genuineness is unverified."
        );
    }

    // Summarize what the hash check established.
    if security_object.is_some() {
        if hashes_checked.is_empty() {
            warn!("No data group hashes could be checked against EF.SOD.");
        } else if hashes_mismatched.is_empty() {
            info!(
                "<green>All {} data group hashes match EF.SOD.</>",
                hashes_checked.len()
            );
            info!(
                "<d>Note: EF.SOD's own signature is not verified, so this shows the document is \
                 internally consistent, not that it is genuine.</>"
            );
        } else {
            error!(
                "<red>{} of {} data groups do NOT match EF.SOD</> (DG{}). The document has been \
                 altered, or was read incorrectly.",
                hashes_mismatched.len(),
                hashes_checked.len(),
                hashes_mismatched
                    .iter()
                    .map(|number| number.to_string())
                    .collect::<Vec<_>>()
                    .join(", DG")
            );
        }

        // Anything EF.SOD covers that we never read stays unchecked.
        if let Some(ref security_object) = security_object {
            let unchecked: Vec<String> = security_object
                .data_group_hashes
                .iter()
                .filter(|data_group_hash| {
                    !hashes_checked.contains(&data_group_hash.data_group_number)
                })
                .map(|data_group_hash| format!("DG{}", data_group_hash.data_group_number))
                .collect();
            if !unchecked.is_empty() {
                info!(
                    "<d>Not checked, as they were not read: {}.</>",
                    unchecked.join(", ")
                );
            }
        }
    }

    drop(smartcard);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icao9303::DocumentHashAlgorithm;
    use crate::types::parsed_data_groups::DataGroupHash;

    fn security_object(
        hash_algorithm: DocumentHashAlgorithm,
        hashes: Vec<(u64, Vec<u8>)>,
    ) -> types::EFSOD {
        return types::EFSOD {
            hash_algorithm,
            data_group_hashes: hashes
                .into_iter()
                .map(|(data_group_number, hash)| DataGroupHash {
                    data_group_number,
                    hash,
                })
                .collect(),
        };
    }

    fn data_group(name: &str) -> &'static types::DataGroup {
        return types::DATA_GROUPS
            .iter()
            .find(|dg_info| dg_info.name == name)
            .unwrap();
    }

    /// A data group whose contents hash to the value EF.SOD records passes.
    #[test]
    fn matching_hash_passes() {
        let contents = b"a data group, as read off the chip";
        let expected = DocumentHashAlgorithm::Sha256.hash(contents);
        let sod = security_object(DocumentHashAlgorithm::Sha256, vec![(1, expected)]);

        assert_eq!(
            check_data_group_hash(&sod, data_group("EF.DG1"), contents),
            Some(true)
        );
    }

    /// A single altered byte has to be caught, which is the whole point.
    #[test]
    fn altered_contents_fail() {
        let contents = b"a data group, as read off the chip";
        let expected = DocumentHashAlgorithm::Sha256.hash(contents);
        let sod = security_object(DocumentHashAlgorithm::Sha256, vec![(1, expected)]);

        let mut tampered = contents.to_vec();
        tampered[0] ^= 0x01;
        assert_eq!(
            check_data_group_hash(&sod, data_group("EF.DG1"), &tampered),
            Some(false)
        );
    }

    /// A data group EF.SOD says nothing about is reported as unchecked rather
    /// than as a pass, so it cannot be counted as verified.
    #[test]
    fn a_data_group_absent_from_the_security_object_is_unchecked() {
        let sod = security_object(DocumentHashAlgorithm::Sha256, vec![(1, vec![0u8; 32])]);
        assert_eq!(
            check_data_group_hash(&sod, data_group("EF.DG2"), b"anything"),
            None
        );
    }

    /// The hash algorithm comes from EF.SOD, so an older SHA-1 document works
    /// the same way.
    #[test]
    fn honours_the_algorithm_the_document_names() {
        let contents = b"a data group";
        let sod = security_object(
            DocumentHashAlgorithm::Sha1,
            vec![(1, DocumentHashAlgorithm::Sha1.hash(contents))],
        );
        assert_eq!(
            check_data_group_hash(&sod, data_group("EF.DG1"), contents),
            Some(true)
        );

        // The same contents under the wrong algorithm must not pass.
        let wrong = security_object(
            DocumentHashAlgorithm::Sha256,
            vec![(1, DocumentHashAlgorithm::Sha1.hash(contents))],
        );
        assert_eq!(
            check_data_group_hash(&wrong, data_group("EF.DG1"), contents),
            Some(false)
        );
    }

    /// EF.COM is not covered by EF.SOD's signature, so a data group dropped
    /// from its list would otherwise go unnoticed.
    #[test]
    fn spots_data_groups_missing_from_ef_com() {
        let sod = security_object(
            DocumentHashAlgorithm::Sha256,
            vec![(1, vec![0u8; 32]), (2, vec![0u8; 32])],
        );
        // EF.COM lists only DG1 (tag 0x61), while EF.SOD covers DG1 and DG2.
        let ef_com = types::EFCom {
            lds_version: None,
            unicode_version: None,
            data_group_tag_list: vec![0x61],
        };
        assert_eq!(data_groups_missing_from_ef_com(&ef_com, &sod), vec![2]);

        // With both listed, nothing is missing.
        let ef_com = types::EFCom {
            lds_version: None,
            unicode_version: None,
            data_group_tag_list: vec![0x61, 0x75],
        };
        assert!(data_groups_missing_from_ef_com(&ef_com, &sod).is_empty());
    }
}
