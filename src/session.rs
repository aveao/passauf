///! Reading a document from end to end.
///
/// [`read_document`] runs the whole flow against an already-selected card:
/// read EF.CardAccess, authenticate with PACE or BAC, select the LDS1 applet,
/// then read and check every file the document says it has. It reports what it
/// found rather than printing it, so a caller that isn't a terminal can do
/// something else with the result.
use simplelog::{error, info, warn};
use std::fmt;
use std::path::PathBuf;

use crate::iso7816;
use crate::secure_messaging::SecureMessaging;
use crate::smartcard_abstractions::Smartcard;
use crate::types::{self, DataGroupEnum, ParsedDataGroup};
use crate::{helpers, icao9303};

/// What the reader knows about the document, which is what unlocks it.
///
/// Both are printed on the document itself: the MRZ fields in the machine
/// readable zone, the CAN usually somewhere on the front.
#[derive(Debug, Clone)]
pub enum AccessKey {
    /// The three MRZ fields. BAC accepts only this, PACE accepts it too.
    Mrz {
        document_number: String,
        /// YYMMDD
        date_of_birth: String,
        /// YYMMDD
        date_of_expiry: String,
    },
    /// The Card Access Number. PACE only, there is no BAC fallback for it.
    Can(String),
}

impl AccessKey {
    #[cfg(feature = "pace")]
    fn to_pace_password(&self) -> crate::pace::password::Password {
        return match self {
            AccessKey::Mrz {
                document_number,
                date_of_birth,
                date_of_expiry,
            } => crate::pace::password::Password::Mrz {
                document_number: document_number.clone(),
                date_of_birth: date_of_birth.clone(),
                date_of_expiry: date_of_expiry.clone(),
            },
            AccessKey::Can(card_access_number) => {
                crate::pace::password::Password::Can(card_access_number.clone())
            }
        };
    }
}

/// How much to read, and what to do with it.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    pub access_key: AccessKey,
    /// Read the data groups that hold images (DG2/3/4, DG5, DG15) as well.
    /// These are much larger than the rest, so a read that only wants the
    /// printed details is considerably quicker without them.
    pub read_binary_files: bool,
    /// Where to write each file's contents, if anywhere. Data groups holding
    /// images write those out next to the raw file.
    pub dump_path: Option<PathBuf>,
    /// Prefixed to every dumped filename, to keep documents apart.
    pub file_prefix: String,
    /// Have the parsers print what they found, which is the CLI's output.
    pub print: bool,
}

impl Default for ReadOptions {
    fn default() -> Self {
        return ReadOptions {
            access_key: AccessKey::Can(String::new()),
            read_binary_files: false,
            dump_path: None,
            file_prefix: "document".to_string(),
            print: false,
        };
    }
}

/// Where a read has got to, for a caller that wants to say so.
#[derive(Debug, Clone)]
pub enum Progress {
    /// Reading EF.CardAccess to find out what the document offers.
    ReadingCardAccess,
    /// Running PACE or BAC.
    Authenticating,
    /// A session is up. The string names how it was established.
    Authenticated(String),
    /// Reading one file, named as the document names it.
    ReadingFile(&'static str),
    /// Holding the data groups against EF.SOD.
    Checking,
    Done,
}

impl fmt::Display for Progress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            Progress::ReadingCardAccess => write!(f, "Reading EF.CardAccess"),
            Progress::Authenticating => write!(f, "Authenticating"),
            Progress::Authenticated(method) => write!(f, "Authenticated with {}", method),
            Progress::ReadingFile(name) => write!(f, "Reading {}", name),
            Progress::Checking => write!(f, "Checking data group hashes"),
            Progress::Done => write!(f, "Done"),
        };
    }
}

/// A read that could not be started or could not get far enough to be useful.
///
/// Anything that only affects part of a document is reported in
/// [`DocumentRead`] instead, since the rest of the read is still worth having.
#[derive(Debug)]
pub enum SessionError {
    /// Neither PACE nor BAC established a session. Nearly always a wrong
    /// document number, date of birth, date of expiry or CAN.
    AuthenticationFailed(String),
    /// A CAN was given for a document that does not offer PACE. A CAN cannot be
    /// used with BAC, which wants the MRZ fields instead.
    CanNeedsPace,
    /// A CAN was given but this build has no PACE support.
    PaceUnavailable,
    /// EF.COM did not come back, so there is no list of what to read.
    NoFileList,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            SessionError::AuthenticationFailed(detail) => {
                write!(f, "Could not authenticate with the document: {}", detail)
            }
            SessionError::CanNeedsPace => write!(
                f,
                "This document does not offer PACE, and a CAN cannot be used with BAC, which \
                 needs the document number, date of birth and date of expiry instead."
            ),
            SessionError::PaceUnavailable => write!(
                f,
                "A CAN needs PACE, which was disabled at compile time in this build."
            ),
            SessionError::NoFileList => write!(
                f,
                "Could not read EF.COM, so there is no list of the document's data groups."
            ),
        };
    }
}

impl std::error::Error for SessionError {}

/// How the secure messaging session was established.
#[derive(Debug, Clone, PartialEq)]
pub enum Authentication {
    /// PACE, with the variant the document and we agreed on.
    Pace {
        algorithm: String,
    },
    Bac,
}

impl fmt::Display for Authentication {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            Authentication::Pace { algorithm } => write!(f, "PACE ({})", algorithm),
            Authentication::Bac => write!(f, "BAC"),
        };
    }
}

/// What Chip Authentication Mapping established, when PACE ran it.
///
/// A pass proves the chip holds the private key for the Chip Authentication key
/// it published. It does not prove that key belongs to a genuine document:
/// ICAO 9303 p11 section 4.4.3.5.2 requires Passive Authentication alongside
/// CAM for that, and EF.SOD's signature is not verified here.
#[derive(Debug, Clone, PartialEq)]
pub enum ChipAuthentication {
    /// The document did not offer CAM, or PACE was not used at all.
    NotAttempted,
    /// The chip proved it holds the private key for the key published in
    /// `source`, over `curve`.
    Passed { source: String, curve: String },
    /// CAM ran, but no key the document published matches the chip's mapping
    /// key. The chip may not be genuine.
    Failed,
    /// CAM ran, but neither EF.CardSecurity nor DG14 could be read, so there
    /// was nothing to check against.
    NoKeyAvailable,
}

impl ChipAuthentication {
    /// Of two outcomes from two key sources, the one that says more.
    ///
    /// A key that was checked and did not match says more than "there was no
    /// key to check", which in turn says more than not having looked. A pass
    /// beats all of them: one matching key is the whole check, and a document
    /// that publishes a key in EF.CardSecurity but not DG14 (or the reverse) is
    /// perfectly normal.
    pub fn strongest(self, other: ChipAuthentication) -> ChipAuthentication {
        fn rank(outcome: &ChipAuthentication) -> u8 {
            return match outcome {
                ChipAuthentication::NotAttempted => 0,
                ChipAuthentication::NoKeyAvailable => 1,
                ChipAuthentication::Failed => 2,
                ChipAuthentication::Passed { .. } => 3,
            };
        }
        return if rank(&other) > rank(&self) {
            other
        } else {
            self
        };
    }
}

/// What holding a file's contents against EF.SOD established.
#[derive(Debug, Clone, PartialEq)]
pub enum HashCheck {
    /// EF.SOD was not read, so nothing could be checked.
    NoSecurityObject,
    /// EF.SOD records no hash for this file. EF.COM, EF.CardAccess and
    /// EF.CardSecurity are not covered by it at all.
    NotCovered,
    Matches,
    Mismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
}

/// One file, as far as we got with it.
#[derive(Debug)]
pub struct FileRead {
    pub name: &'static str,
    pub description: &'static str,
    pub file_id: u16,
    /// The file's contents, or None when the document does not have it. A
    /// missing optional data group is normal.
    pub data: Option<Vec<u8>>,
    /// The parsed contents, when there is a parser for this file and it
    /// understood what it got.
    pub parsed: Option<ParsedDataGroup>,
    pub hash: HashCheck,
    /// Everything written to disk for this file, when dumping was asked for.
    pub dumped: Vec<PathBuf>,
}

impl FileRead {
    /// Whether the document actually had this file.
    pub fn present(&self) -> bool {
        return self.data.is_some();
    }
}

/// What the data group hashes in EF.SOD established across the document.
#[derive(Debug, Default)]
pub struct Integrity {
    /// Whether EF.SOD was read at all. Without it nothing below means anything.
    pub security_object_read: bool,
    /// The digest EF.SOD names, e.g. "SHA-256".
    pub hash_algorithm: Option<String>,
    /// Data groups whose contents were held against EF.SOD.
    pub checked: Vec<u64>,
    /// Of those, the ones that did not match.
    pub mismatched: Vec<u64>,
    /// Data groups EF.SOD covers that were never read, so nothing was checked.
    pub unchecked: Vec<u64>,
    /// Data groups EF.SOD covers that EF.COM does not list. EF.COM is not
    /// signed, so this is what removing a data group would look like to a
    /// reader that trusts it.
    pub missing_from_ef_com: Vec<u64>,
}

impl Integrity {
    /// Whether every data group that was read matched EF.SOD.
    ///
    /// This is internal consistency, not authenticity: EF.SOD's own signature
    /// is not verified, so a document rewritten wholesale still passes. See
    /// the note in android/README.md about certificate chains.
    pub fn consistent(&self) -> bool {
        return self.security_object_read && !self.checked.is_empty() && self.mismatched.is_empty();
    }
}

/// Everything one read of a document produced.
#[derive(Debug)]
pub struct DocumentRead {
    pub authentication: Authentication,
    pub chip_authentication: ChipAuthentication,
    /// Every file that was attempted, in the order they were read.
    pub files: Vec<FileRead>,
    pub integrity: Integrity,
    /// Things worth telling the user that aren't tied to one file.
    pub warnings: Vec<String>,
}

impl DocumentRead {
    /// One file by the name the document uses, e.g. "EF.DG1".
    pub fn file(&self, name: &str) -> Option<&FileRead> {
        return self.files.iter().find(|file| file.name == name);
    }

    /// The MRZ from DG1, when it was read.
    pub fn mrz(&self) -> Option<&types::MRZ> {
        return match self.file("EF.DG1")?.parsed.as_ref()? {
            ParsedDataGroup::EFDG1(dg1) => Some(&dg1.mrz),
            _ => None,
        };
    }
}

/// Read a document from a card that has already been selected.
///
/// `progress` is called as the read moves along, for a caller that wants to say
/// what is happening; pass `&mut |_| {}` to ignore it.
pub fn read_document<S>(
    smartcard: &mut Box<S>,
    options: &ReadOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<DocumentRead, SessionError>
where
    S: Smartcard + ?Sized,
{
    let mut files: Vec<FileRead> = vec![];
    let mut warnings: Vec<String> = vec![];

    // A CAN is only usable through PACE, so a build without it can't get
    // anywhere. Say so before touching the card.
    if matches!(options.access_key, AccessKey::Can(_)) && !cfg!(feature = "pace") {
        return Err(SessionError::PaceUnavailable);
    }

    // Read EF.CardAccess. Only PACE has any use for what's in it.
    progress(Progress::ReadingCardAccess);
    let card_access = read_one_file(
        smartcard,
        data_group(DataGroupEnum::EFCardAccess),
        options,
        None,
    );

    // A document can carry EF.CardAccess without offering PACE in it, so this
    // has to come from the parsed SecurityInfos rather than from the file
    // merely being readable.
    #[cfg(feature = "pace")]
    let parsed_card_access = match card_access.parsed {
        Some(ParsedDataGroup::EFCardAccess(ref parsed)) => Some(parsed.clone()),
        _ => None,
    };
    #[cfg(feature = "pace")]
    let pace_available = parsed_card_access
        .as_ref()
        .map_or(false, |card_access| card_access.supports_pace());
    // Without the feature there is no parser for EF.CardAccess, so we cannot
    // tell what the document offers, only that we cannot use it.
    #[cfg(not(feature = "pace"))]
    let pace_available = false;

    let card_access_present = card_access.present();
    files.push(card_access);

    if !pace_available {
        // Both arms compile either way, so this stays one readable block.
        let warning = if !cfg!(feature = "pace") && card_access_present {
            // EF.CardAccess exists purely to carry PACE parameters, so a
            // document that has one almost certainly supports PACE. Blaming the
            // document here would send the user looking in the wrong place.
            "This build of passauf has no PACE support, but this eMRTD has an EF.CardAccess, \
             so it almost certainly does support PACE. Falling back to BAC, which will fail \
             outright if this document is PACE-only."
        } else {
            "PACE isn't available on this eMRTD, authenticating with BAC."
        };
        warn!("{}", warning);
        warnings.push(warning.to_string());
    }

    // Read the rest of the files under the master file, which need no session.
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.CardAccess"
            // EF.CardSecurity needs PACE, so it is read further down.
            || dg_info.name == "EF.CardSecurity"
            || dg_info.in_lds1
            || (dg_info.pace_only && !pace_available)
        {
            continue;
        }
        progress(Progress::ReadingFile(dg_info.name));
        files.push(read_one_file(smartcard, dg_info, options, None));
    }

    // Authenticate, preferring PACE when the document offers a variant we can
    // run, and falling back to BAC otherwise.
    //
    // PACE runs here, before the eMRTD applet is selected, which is the order
    // ICAO 9303 p11 Appendix J gives and which leaves the master file selected
    // so EF.CardSecurity can be read afterwards. BAC is the other way round: it
    // authenticates against the applet, so that path selects it first.
    progress(Progress::Authenticating);

    #[cfg(feature = "pace")]
    let pace_result = match (pace_available, &parsed_card_access) {
        (true, Some(parsed_card_access)) => {
            let pace_password = options.access_key.to_pace_password();
            match crate::pace::select_pace_info(parsed_card_access.pace_infos().as_slice()) {
                Ok(pace_info) => {
                    let algorithm = pace_info.algorithm.to_string();
                    match crate::pace::do_pace_authentication(smartcard, &pace_info, &pace_password)
                    {
                        Ok((sm, pending)) => Some((sm, pending, algorithm)),
                        Err(error) => {
                            warn!("{}", error);
                            None
                        }
                    }
                }
                Err(error) => {
                    warn!("{}", error);
                    None
                }
            }
        }
        _ => None,
    };
    #[cfg(not(feature = "pace"))]
    let pace_result: Option<(SecureMessaging, Option<()>, String)> = None;

    #[cfg_attr(not(feature = "pace"), allow(unused_mut))]
    let mut chip_authentication = ChipAuthentication::NotAttempted;
    // Chip Authentication Mapping hands back a check that can only be completed
    // once DG14 has been read, which needs secure messaging to be up first.
    #[cfg(feature = "pace")]
    let mut pending_chip_authentication: Option<crate::pace::PendingChipAuthentication> = None;

    let (mut sm, authentication) = match pace_result {
        Some((mut sm, pending, algorithm)) => {
            #[cfg(feature = "pace")]
            if let Some(pending) = pending {
                // Still at the master file, and secure messaging is up, so this
                // is the one moment EF.CardSecurity can be read. It is where
                // ICAO 9303 p11 Appendix I takes the PACE-CAM key from, and a
                // document can publish a key here that DG14 never mentions.
                progress(Progress::ReadingFile("EF.CardSecurity"));
                let card_security = read_one_file(
                    smartcard,
                    data_group(DataGroupEnum::EFCardSecurity),
                    options,
                    Some(&mut sm),
                );

                chip_authentication = match card_security.parsed {
                    Some(ParsedDataGroup::EFCardSecurity(ref parsed)) => {
                        verify_chip_authentication(
                            &pending,
                            &parsed.chip_authentication_public_keys,
                            "EF.CardSecurity",
                        )
                    }
                    _ => ChipAuthentication::NoKeyAvailable,
                };

                files.push(card_security);

                // Not settled yet, so DG14 gets a turn once we are inside LDS1.
                if !matches!(chip_authentication, ChipAuthentication::Passed { .. }) {
                    pending_chip_authentication = Some(pending);
                }
            }
            #[cfg(not(feature = "pace"))]
            let _ = pending;

            // Selecting the applet now happens over secure messaging.
            info!("Selecting eMRTD LDS1 applet");
            let _ = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
                .secure_exchange(smartcard, true, Some(&mut sm));
            (sm, Authentication::Pace { algorithm })
        }
        None => {
            let (document_number, date_of_birth, date_of_expiry) = match &options.access_key {
                AccessKey::Mrz {
                    document_number,
                    date_of_birth,
                    date_of_expiry,
                } => (document_number, date_of_birth, date_of_expiry),
                // A CAN is only ever usable through PACE, so there is nothing
                // to fall back to.
                AccessKey::Can(_) => return Err(SessionError::CanNeedsPace),
            };
            if pace_available {
                warn!("Falling back to BAC.");
            }
            // BAC authenticates against the applet, so it has to be selected
            // first, and plainly.
            info!("Selecting eMRTD LDS1 applet");
            let _ = iso7816::apdu_select_file_by_name(icao9303::AID_MRTD_LDS1.to_vec())
                .exchange(smartcard, true);
            let sm = icao9303::do_bac_authentication(
                smartcard,
                document_number,
                date_of_birth,
                date_of_expiry,
            );
            (sm, Authentication::Bac)
        }
    };

    progress(Progress::Authenticated(authentication.to_string()));

    // Read EF.COM, which lists the data groups the document says it has.
    progress(Progress::ReadingFile("EF.COM"));
    let ef_com_read = read_one_file(
        smartcard,
        data_group(DataGroupEnum::EFCom),
        options,
        Some(&mut sm),
    );
    let ef_com = match ef_com_read.parsed {
        Some(ParsedDataGroup::EFCom(ref ef_com)) => ef_com.clone(),
        _ => return Err(SessionError::NoFileList),
    };
    files.push(ef_com_read);

    // Read EF.SOD, which records a hash of every data group. It is not itself
    // listed in EF.COM's tag list, so it has to be asked for by name.
    progress(Progress::ReadingFile("EF.SOD"));
    let ef_sod_read = read_one_file(
        smartcard,
        data_group(DataGroupEnum::EFSod),
        options,
        Some(&mut sm),
    );
    let security_object = match ef_sod_read.parsed {
        Some(ParsedDataGroup::EFSOD(ref security_object)) => Some(security_object.clone()),
        _ => {
            warn!("Could not read EF.SOD, so data group hashes cannot be checked.");
            warnings.push("Could not read EF.SOD, so data group hashes cannot be checked.".into());
            None
        }
    };
    files.push(ef_sod_read);

    let mut integrity = Integrity {
        security_object_read: security_object.is_some(),
        hash_algorithm: security_object
            .as_ref()
            .map(|security_object| security_object.hash_algorithm.to_string()),
        ..Default::default()
    };

    if security_object.is_some() {
        mark_files_read_before_the_security_object(&mut files);
    }

    // EF.SOD covers the data groups but not EF.COM, so the two can disagree
    // about which are present. Saying so is worthwhile: EF.COM is what the read
    // loop below trusts.
    if let Some(ref security_object) = security_object {
        integrity.missing_from_ef_com = data_groups_missing_from_ef_com(&ef_com, security_object);
        for data_group_number in integrity.missing_from_ef_com.iter() {
            let warning = format!(
                "EF.SOD covers DG{} but EF.COM does not list it, so it will not be read. \
                 EF.COM is not covered by EF.SOD, so an entry removed from it cannot be \
                 detected by EF.SOD's signature.",
                data_group_number
            );
            warn!("{}", warning);
            warnings.push(warning);
        }
    }

    // Read everything under the LDS1 applet that EF.COM says is there.
    for dg_info in types::DATA_GROUPS.iter() {
        if dg_info.name == "EF.COM"
            || dg_info.name == "EF.SOD"
            || !dg_info.in_lds1
            || dg_info.pace_only
            || (dg_info.is_binary && !options.read_binary_files)
            || !ef_com.data_group_tag_list.contains(&dg_info.tag)
        {
            continue;
        }

        progress(Progress::ReadingFile(dg_info.name));
        let mut file = read_one_file(smartcard, dg_info, options, Some(&mut sm));

        // Hash what was actually read and hold it against EF.SOD.
        if let (Some(ref security_object), Some(ref file_data)) = (&security_object, &file.data) {
            file.hash = check_data_group_hash(security_object, dg_info, file_data);
            match file.hash {
                HashCheck::Matches => integrity.checked.push(dg_info.dg_num.into()),
                HashCheck::Mismatch { .. } => {
                    integrity.checked.push(dg_info.dg_num.into());
                    integrity.mismatched.push(dg_info.dg_num.into());
                }
                // EF.SOD says nothing about this data group.
                _ => {}
            }
        }

        // DG14 carries the chip's static Chip Authentication key, which is what
        // a pending PACE-CAM check has been waiting for.
        #[cfg(feature = "pace")]
        if let Some(pending) = pending_chip_authentication.take() {
            match file.parsed {
                Some(ParsedDataGroup::EFDG14(ref dg14)) => {
                    chip_authentication =
                        chip_authentication.strongest(verify_chip_authentication(
                            &pending,
                            &dg14.chip_authentication_public_keys,
                            "DG14",
                        ));
                    if chip_authentication == ChipAuthentication::Failed {
                        let warning = "Chip Authentication FAILED: no key in EF.CardSecurity or \
                                       DG14 matches the chip's mapping key. The chip may not be \
                                       genuine."
                            .to_string();
                        warn!("{}", warning);
                        warnings.push(warning);
                    }
                }
                // Not DG14, so keep waiting.
                _ => pending_chip_authentication = Some(pending),
            }
        }

        files.push(file);
    }

    #[cfg(feature = "pace")]
    if pending_chip_authentication.is_some() {
        let warning = "Chip Authentication Mapping was used, but the document has no readable \
                       DG14 to check it against, so the chip's genuineness is unverified."
            .to_string();
        warn!("{}", warning);
        warnings.push(warning);
        chip_authentication = chip_authentication.strongest(ChipAuthentication::NoKeyAvailable);
    }

    // Anything EF.SOD covers that we never read stays unchecked.
    progress(Progress::Checking);
    if let Some(ref security_object) = security_object {
        integrity.unchecked = security_object
            .data_group_hashes
            .iter()
            .filter(|data_group_hash| {
                !integrity
                    .checked
                    .contains(&data_group_hash.data_group_number)
            })
            .map(|data_group_hash| data_group_hash.data_group_number)
            .collect();
    }

    progress(Progress::Done);
    return Ok(DocumentRead {
        authentication,
        chip_authentication,
        files,
        integrity,
        warnings,
    });
}

/// The entry in [`types::DATA_GROUPS`] for a known file.
fn data_group(file: DataGroupEnum) -> &'static types::DataGroup {
    return &types::DATA_GROUPS[file as usize];
}

/// Select, read, parse and (if asked) dump one file.
fn read_one_file<S>(
    smartcard: &mut Box<S>,
    dg_info: &'static types::DataGroup,
    options: &ReadOptions,
    sm: Option<&mut SecureMessaging>,
) -> FileRead
where
    S: Smartcard + ?Sized,
{
    let data = iso7816::select_and_read_file(smartcard, dg_info, sm);
    let mut parsed = None;
    let mut dumped = vec![];

    if let Some(ref file_data) = data {
        parsed = (dg_info.parser)(file_data, dg_info, options.print);

        if let Some(ref dump_path) = options.dump_path {
            let filename = format!("{}-{}", options.file_prefix, dg_info.name).replace(".", "_");
            match (dg_info.dumper)(file_data, &parsed, dump_path, &filename) {
                Ok(paths) => dumped = paths,
                Err(error) => warn!("Could not write {} out: {}", dg_info.name, error),
            }
        }
    }

    return FileRead {
        name: dg_info.name,
        description: dg_info.description,
        file_id: dg_info.file_id,
        data,
        parsed,
        hash: HashCheck::NoSecurityObject,
        dumped,
    };
}

/// Complete a PACE-CAM check against the keys a file offers.
///
/// A pass proves the chip holds the private key for the Chip Authentication key
/// it presented. It does not prove that key belongs to a genuine document:
/// ICAO 9303 p11 section 4.4.3.5.2 requires Passive Authentication alongside
/// CAM for that, and while EF.SOD's hashes are checked, its signature is not.
#[cfg(feature = "pace")]
fn verify_chip_authentication(
    pending: &crate::pace::PendingChipAuthentication,
    keys: &[types::ef_cardaccess::ChipAuthenticationPublicKeyInfo],
    source: &str,
) -> ChipAuthentication {
    if keys.is_empty() {
        simplelog::debug!("{} offers no chip authentication public key.", source);
        return ChipAuthentication::NoKeyAvailable;
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
            return ChipAuthentication::Passed {
                source: source.to_string(),
                curve: pending.curve().to_string(),
            };
        }
    }

    simplelog::debug!(
        "No key in {} matches the chip's mapping key ({} tried).",
        source,
        keys.len()
    );
    return ChipAuthentication::Failed;
}

/// Hold one data group's contents against the hash EF.SOD records for it.
fn check_data_group_hash(
    security_object: &types::EFSOD,
    dg_info: &types::DataGroup,
    file_data: &[u8],
) -> HashCheck {
    let expected = match security_object
        .data_group_hashes
        .iter()
        .find(|data_group_hash| data_group_hash.data_group_number == u64::from(dg_info.dg_num))
    {
        Some(expected) => expected,
        // EF.SOD says nothing about this data group, which is not an error in
        // itself but does mean nothing was checked.
        None => return HashCheck::NotCovered,
    };

    // The hash covers the file exactly as read, outer tag included.
    let actual = security_object.hash_algorithm.hash(file_data);
    if actual == expected.hash {
        info!(
            "<green>{} matches its {} hash in EF.SOD.</>",
            dg_info.name, security_object.hash_algorithm
        );
        return HashCheck::Matches;
    }

    error!(
        "<red>{} does NOT match its hash in EF.SOD.</> Expected {}, got {}.",
        dg_info.name,
        hex(&expected.hash),
        hex(&actual)
    );
    return HashCheck::Mismatch {
        expected: expected.hash.clone(),
        actual,
    };
}

/// Correct the reason the files read before EF.SOD went unchecked.
///
/// EF.CardAccess, EF.DIR, EF.COM and EF.SOD itself are all read before there is
/// a security object to hold anything against, so each one is left saying it
/// was not checked because EF.SOD was not read. Once EF.SOD *has* been read,
/// that reads as a contradiction next to the data groups reporting matches.
/// None of them is a data group, and EF.SOD records no hash for any of them, so
/// the honest reason is that it does not cover them.
fn mark_files_read_before_the_security_object(files: &mut [FileRead]) {
    for file in files.iter_mut() {
        if file.hash == HashCheck::NoSecurityObject {
            file.hash = HashCheck::NotCovered;
        }
    }
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

/// Render bytes as lowercase hex, for the places a digest has to be shown.
pub fn hex(data: &[u8]) -> String {
    return data.iter().map(|byte| format!("{:02x}", byte)).collect();
}

/// A filename component that keeps one document's dump apart from another's.
///
/// The document number is the obvious choice; a CAN read has none to hand, so
/// the clock stands in.
pub fn file_prefix_for(access_key: &AccessKey) -> String {
    return match access_key {
        AccessKey::Mrz {
            document_number, ..
        } => document_number.clone(),
        AccessKey::Can(_) => helpers::unix_time().to_string(),
    };
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

    fn named_data_group(name: &str) -> &'static types::DataGroup {
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
            check_data_group_hash(&sod, named_data_group("EF.DG1"), contents),
            HashCheck::Matches
        );
    }

    /// A single altered byte has to be caught, which is the whole point.
    #[test]
    fn altered_contents_fail() {
        let contents = b"a data group, as read off the chip";
        let expected = DocumentHashAlgorithm::Sha256.hash(contents);
        let sod = security_object(DocumentHashAlgorithm::Sha256, vec![(1, expected.clone())]);

        let mut tampered = contents.to_vec();
        tampered[0] ^= 0x01;
        assert_eq!(
            check_data_group_hash(&sod, named_data_group("EF.DG1"), &tampered),
            HashCheck::Mismatch {
                expected,
                actual: DocumentHashAlgorithm::Sha256.hash(&tampered),
            }
        );
    }

    /// A data group EF.SOD says nothing about is reported as unchecked rather
    /// than as a pass, so it cannot be counted as verified.
    #[test]
    fn a_data_group_absent_from_the_security_object_is_unchecked() {
        let sod = security_object(DocumentHashAlgorithm::Sha256, vec![(1, vec![0u8; 32])]);
        assert_eq!(
            check_data_group_hash(&sod, named_data_group("EF.DG2"), b"anything"),
            HashCheck::NotCovered
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
            check_data_group_hash(&sod, named_data_group("EF.DG1"), contents),
            HashCheck::Matches
        );

        // The same contents under the wrong algorithm must not pass.
        let wrong = security_object(
            DocumentHashAlgorithm::Sha256,
            vec![(1, DocumentHashAlgorithm::Sha1.hash(contents))],
        );
        assert!(matches!(
            check_data_group_hash(&wrong, named_data_group("EF.DG1"), contents),
            HashCheck::Mismatch { .. }
        ));
    }

    /// The files read before EF.SOD must not go on claiming it was never read,
    /// which sits badly next to the data groups underneath them reporting
    /// matches against it.
    #[test]
    fn files_read_before_the_security_object_are_reported_as_uncovered() {
        fn file(name: &'static str, hash: HashCheck) -> FileRead {
            return FileRead {
                name,
                description: "",
                file_id: 0,
                data: Some(vec![]),
                parsed: None,
                hash,
                dumped: vec![],
            };
        }

        let mut files = vec![
            file("EF.CardAccess", HashCheck::NoSecurityObject),
            file("EF.COM", HashCheck::NoSecurityObject),
            file("EF.DG1", HashCheck::Matches),
            file(
                "EF.DG2",
                HashCheck::Mismatch {
                    expected: vec![1],
                    actual: vec![2],
                },
            ),
        ];
        mark_files_read_before_the_security_object(&mut files);

        assert_eq!(files[0].hash, HashCheck::NotCovered);
        assert_eq!(files[1].hash, HashCheck::NotCovered);
        // A real outcome is never overwritten.
        assert_eq!(files[2].hash, HashCheck::Matches);
        assert!(matches!(files[3].hash, HashCheck::Mismatch { .. }));
    }

    /// A document can publish its Chip Authentication key in EF.CardSecurity,
    /// in DG14, or in both, so the two sources have to be combined rather than
    /// the second overwriting the first.
    #[test]
    fn keeps_the_more_informative_chip_authentication_outcome() {
        let passed = ChipAuthentication::Passed {
            source: "DG14".to_string(),
            curve: "brainpoolP256r1".to_string(),
        };

        // A match anywhere is the whole check, so nothing later can undo it.
        assert_eq!(passed.clone().strongest(ChipAuthentication::Failed), passed);
        assert_eq!(
            ChipAuthentication::NoKeyAvailable.strongest(passed.clone()),
            passed
        );

        // A key that was checked and did not match says more than the other
        // source having had no key to offer.
        assert_eq!(
            ChipAuthentication::Failed.strongest(ChipAuthentication::NoKeyAvailable),
            ChipAuthentication::Failed
        );
        assert_eq!(
            ChipAuthentication::NotAttempted.strongest(ChipAuthentication::NoKeyAvailable),
            ChipAuthentication::NoKeyAvailable
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
