///! The JSON a read hands back across the JNI boundary.
///
/// This is the app's view of a document, and deliberately a flat one. The
/// printed details every document has get their own named fields, so the UI can
/// lay them out properly; everything else becomes label/value rows per file, so
/// a data group passauf learns to parse tomorrow shows up in the app without
/// the app changing.
use serde::Serialize;

use crate::dg_parsers::helpers as dg_helpers;
use crate::session::{
    self, Authentication, ChipAuthentication, DocumentRead, FileRead, HashCheck, Integrity,
};
use crate::types::{self, ParsedDataGroup};

/// Everything one read produced, or why it produced nothing.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Whether a session was established and the document was read.
    pub ok: bool,
    /// Why not, when it wasn't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A short, stable name for that reason, from [`session::SessionError::kind`].
    ///
    /// The sentence above is for reading; this is for deciding what to offer. Absent
    /// when the read failed some other way, such as a panic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chip_authentication: Option<ChipAuthenticationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<IntegrityReport>,
    /// The document's printed details, gathered from DG1, DG11 and DG12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<DocumentReport>,
    pub files: Vec<FileReport>,
    /// Paths of every portrait image that was extracted, best first.
    pub portraits: Vec<String>,
    pub warnings: Vec<String>,
    /// passauf's own log for this read, with terminal colours removed.
    pub log: Vec<String>,
}

impl Report {
    pub fn failure(error: String) -> Report {
        return Report {
            ok: false,
            error: Some(error),
            ..Default::default()
        };
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationReport {
    /// "PACE" or "BAC".
    pub method: String,
    /// The PACE variant that ran, when it was PACE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChipAuthenticationReport {
    /// "notAttempted", "passed", "failed" or "noKeyAvailable".
    pub status: String,
    /// Which file published the key that was checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReport {
    pub security_object_read: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    /// Every data group that was read matched EF.SOD. This is internal
    /// consistency only: EF.SOD's signature is not checked, so it does not say
    /// the document is genuine.
    pub consistent: bool,
    pub checked: Vec<u64>,
    pub mismatched: Vec<u64>,
    pub unchecked: Vec<u64>,
    pub missing_from_ef_com: Vec<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub name: String,
    pub description: String,
    /// The file identifier, as "0x0101".
    pub file_id: String,
    /// Whether the document had this file at all.
    pub present: bool,
    pub size: usize,
    /// "notApplicable", "noSecurityObject", "notCovered", "matches" or
    /// "mismatch".
    pub hash_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_hash: Option<String>,
    /// Paths of everything written out for this file.
    pub dumped: Vec<String>,
    /// Of those, the ones that are pictures pulled out of the file, so a
    /// frontend can show them without having to work out which is which.
    pub images: Vec<String>,
    /// What the parser made of it, as rows to display.
    pub details: Vec<Detail>,
}

/// One line of a file's contents, ready to put on screen.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub label: String,
    pub value: String,
}

impl Detail {
    fn new(label: &str, value: impl Into<String>) -> Detail {
        return Detail {
            label: label.to_string(),
            value: value.into(),
        };
    }

    /// A row that is left out entirely when the document didn't fill the field
    /// in, which most of DG11 and DG12 are.
    fn optional(label: &str, value: &Option<String>) -> Option<Detail> {
        return value
            .as_ref()
            .filter(|text| !text.is_empty())
            .map(|text| Detail::new(label, text.clone()));
    }
}

/// The details printed on the document itself.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentReport {
    // From DG1's MRZ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrz_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrz_raw: Option<String>,
    /// Whether every check digit in the MRZ adds up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrz_checksums_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,
    /// Family name, as the MRZ separates it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    /// Given names, space separated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_names: Option<String>,
    /// The holder's name as DG11 spells it out, when the document carries one.
    ///
    /// From DG11 rather than the MRZ because the MRZ is the abbreviated copy:
    /// it truncates a name that does not fit its rows and has no way to write
    /// anything outside its own character set. DG11 is where the issuer put the
    /// name in full, so it is the one to show someone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// "Male", "Female" or "X (or unspecified)".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sex: Option<String>,
    /// YYYY-MM-DD, so the app can format it for the reader's locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_data: Option<String>,

    /// Anything DG11 and DG12 add, as rows. These vary a lot by issuer, and
    /// most documents fill in very few of them.
    pub personal_details: Vec<Detail>,
    pub document_details: Vec<Detail>,
}

/// Turn a completed read into the JSON the app gets.
pub fn build(read: &DocumentRead, log: Vec<String>) -> Report {
    return Report {
        ok: true,
        error: None,
        error_kind: None,
        // Absent for a read rebuilt from files: there was no session to describe.
        authentication: read.authentication.as_ref().map(authentication),
        chip_authentication: Some(chip_authentication(&read.chip_authentication)),
        integrity: Some(integrity(&read.integrity)),
        document: Some(document(read)),
        files: read.files.iter().map(file).collect(),
        portraits: portraits(read),
        warnings: read.warnings.clone(),
        log,
    };
}

fn authentication(authentication: &Authentication) -> AuthenticationReport {
    return match authentication {
        Authentication::Pace { algorithm } => AuthenticationReport {
            method: "PACE".to_string(),
            algorithm: Some(algorithm.clone()),
        },
        Authentication::Bac => AuthenticationReport {
            method: "BAC".to_string(),
            algorithm: None,
        },
    };
}

fn chip_authentication(chip_authentication: &ChipAuthentication) -> ChipAuthenticationReport {
    return match chip_authentication {
        ChipAuthentication::NotAttempted => ChipAuthenticationReport {
            status: "notAttempted".to_string(),
            source: None,
            curve: None,
        },
        ChipAuthentication::Passed { source, curve } => ChipAuthenticationReport {
            status: "passed".to_string(),
            source: Some(source.clone()),
            curve: Some(curve.clone()),
        },
        ChipAuthentication::Failed => ChipAuthenticationReport {
            status: "failed".to_string(),
            source: None,
            curve: None,
        },
        ChipAuthentication::NoKeyAvailable => ChipAuthenticationReport {
            status: "noKeyAvailable".to_string(),
            source: None,
            curve: None,
        },
    };
}

fn integrity(integrity: &Integrity) -> IntegrityReport {
    return IntegrityReport {
        security_object_read: integrity.security_object_read,
        hash_algorithm: integrity.hash_algorithm.clone(),
        consistent: integrity.consistent(),
        checked: integrity.checked.clone(),
        mismatched: integrity.mismatched.clone(),
        unchecked: integrity.unchecked.clone(),
        missing_from_ef_com: integrity.missing_from_ef_com.clone(),
    };
}

fn file(file: &FileRead) -> FileReport {
    let (hash_status, expected_hash, actual_hash) = match &file.hash {
        // For a file EF.SOD could never cover there is no check to have gone
        // missing, and saying one "was not checked" invites the reader to
        // wonder what went wrong when the answer is that nothing was ever
        // meant to happen. Kept apart from notCovered, which is a real absence:
        // a data group EF.SOD *could* have recorded a hash for and did not.
        HashCheck::NoSecurityObject | HashCheck::NotCovered
            if !covered_by_security_object(file) =>
        {
            ("notApplicable", None, None)
        }
        HashCheck::NoSecurityObject => ("noSecurityObject", None, None),
        HashCheck::NotCovered => ("notCovered", None, None),
        HashCheck::Matches => ("matches", None, None),
        HashCheck::Mismatch { expected, actual } => (
            "mismatch",
            Some(session::hex(expected)),
            Some(session::hex(actual)),
        ),
    };

    return FileReport {
        name: file.name.to_string(),
        description: file.description.to_string(),
        file_id: format!("0x{:04X}", file.file_id),
        present: file.present(),
        size: file.data.as_ref().map_or(0, |data| data.len()),
        hash_status: hash_status.to_string(),
        expected_hash,
        actual_hash,
        dumped: file
            .dumped
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        images: file
            .dumped
            .iter()
            .filter(|path| is_extracted_image(path))
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        details: file.parsed.as_ref().map_or_else(Vec::new, details),
    };
}

/// Every portrait the read extracted.
///
/// DG2 holds the encoded face, which is the one a border check would use; DG5
/// holds the portrait as printed on the document, which some issuers include as
/// well. DG2 comes first so the app can just take the head of the list.
fn portraits(read: &DocumentRead) -> Vec<String> {
    let mut portraits = vec![];
    for name in ["EF.DG2", "EF.DG5"] {
        let file = match read.file(name) {
            Some(file) => file,
            None => continue,
        };
        for path in file.dumped.iter().filter(|path| is_extracted_image(path)) {
            portraits.push(path.to_string_lossy().into_owned());
        }
    }
    return portraits;
}

/// Whether EF.SOD could hold a hash for this file at all.
///
/// It covers the LDS1 data groups and nothing else. EF.COM, EF.CardAccess,
/// EF.CardSecurity, EF.DIR and EF.ATR/INFO are not data groups, and EF.SOD does
/// not hash itself, so for all of them the absence of a hash says nothing about
/// the document — it is what the format says should happen.
fn covered_by_security_object(file: &FileRead) -> bool {
    return types::DATA_GROUPS
        .iter()
        .any(|dg_info| dg_info.file_id == file.file_id && dg_info.in_lds1 && dg_info.dg_num > 0);
}

/// Whether a dumped path is a picture pulled out of a file, rather than the
/// file's own contents.
///
/// Every dumper writes the raw file as `.bin` and gives anything it extracted
/// a name of its own, so that is the whole rule. It is stated here and nowhere
/// else on purpose: the app used to decide this from a list of known
/// extensions, and a face image whose format could not be named came out as
/// `.image_bin`, which that list did not have, so a picture the decoder
/// handles perfectly well was never shown.
fn is_extracted_image(path: &std::path::Path) -> bool {
    return path
        .extension()
        .map_or(false, |extension| extension != "bin");
}

/// Gather the printed details from the data groups that carry them.
fn document(read: &DocumentRead) -> DocumentReport {
    let mut document = DocumentReport::default();

    if let Some(mrz) = read.mrz() {
        fill_from_mrz(&mut document, mrz);
    }

    if let Some(ParsedDataGroup::EFDG11(dg11)) =
        read.file("EF.DG11").and_then(|file| file.parsed.as_ref())
    {
        document.full_name = dg11_full_name(dg11);
        document.personal_details = personal_details(dg11);
    }

    if let Some(ParsedDataGroup::EFDG12(dg12)) =
        read.file("EF.DG12").and_then(|file| file.parsed.as_ref())
    {
        document.document_details = document_details(dg12);
    }

    return document;
}

fn fill_from_mrz(document: &mut DocumentReport, mrz: &types::MRZ) {
    // The two layouts hold the same fields in different places, so pull them
    // out once and fill the report the same way for both.
    let (
        format,
        raw,
        document_code,
        issuing_state,
        name_of_holder,
        document_number,
        nationality,
        date_of_birth,
        sex,
        date_of_expiry,
        optional_data,
    ) = match mrz {
        types::MRZ::TD1(td1) => (
            "TD1",
            &td1.raw_mrz,
            &td1.document_code,
            &td1.issuing_state,
            &td1.name_of_holder,
            &td1.document_number,
            &td1.nationality,
            &td1.date_of_birth,
            td1.sex,
            &td1.date_of_expiry,
            // TD1 splits its optional data across two lines, and the first is
            // where a long document number's tail lives, so join what is left.
            [
                td1.optional_data_elements_line_1.clone(),
                td1.optional_data_elements_line_2.clone(),
            ]
            .iter()
            .filter(|text| !text.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
        ),
        types::MRZ::TD3(td3) => (
            "TD3",
            &td3.raw_mrz,
            &td3.document_code,
            &td3.issuing_state,
            &td3.name_of_holder,
            &td3.document_number,
            &td3.nationality,
            &td3.date_of_birth,
            td3.sex,
            &td3.date_of_expiry,
            td3.personal_number_or_optional_data_elements.clone(),
        ),
    };

    let (given_names, surname) = dg_helpers::format_mrz_name(name_of_holder);

    document.mrz_format = Some(format.to_string());
    document.mrz_raw = Some(raw.clone());
    // Passing false keeps the check off the log; it has already run once with
    // the CLI's warnings during parsing.
    document.mrz_checksums_valid =
        Some(mrz.validate_check_digits(false).iter().all(|valid| *valid));
    document.document_code = Some(document_code.clone());
    document.document_type = Some(dg_helpers::parse_mrz_document_code(
        document_code,
        issuing_state,
    ));
    document.document_number = Some(document_number.clone());
    document.issuing_state = Some(issuing_state.clone());
    document.nationality = Some(nationality.clone());
    document.surname = Some(surname.trim().to_string());
    document.given_names = Some(given_names.trim().to_string());
    document.sex = Some(dg_helpers::parse_mrz_sex(sex));
    document.date_of_birth = iso_date_from_mrz(date_of_birth);
    document.date_of_expiry = iso_date_from_mrz(date_of_expiry);
    document.optional_data = Some(optional_data).filter(|text| !text.is_empty());
}

/// The holder's name as DG11 records it, given names first.
///
/// DG11 separates the family name the same way the MRZ does, with `<<`, so it
/// goes through the same splitter.
fn dg11_full_name(dg11: &types::EFDG11) -> Option<String> {
    return dg11
        .full_name
        .as_ref()
        .map(|name| {
            let (given_names, surname) = dg_helpers::format_mrz_name(name);
            format!("{} {}", given_names.trim(), surname.trim())
                .trim()
                .to_string()
        })
        .filter(|name| !name.is_empty());
}

fn personal_details(dg11: &types::EFDG11) -> Vec<Detail> {
    let mut details = vec![];
    details.extend(Detail::optional("Full name", &dg11_full_name(dg11)));
    if let Some(other_names) = dg11.other_names.as_ref().filter(|names| !names.is_empty()) {
        details.push(Detail::new("Other names", other_names.join(", ")));
    }
    details.extend(Detail::optional("Personal number", &dg11.personal_number));
    details.extend(Detail::optional(
        "Date of birth",
        &dg11
            .full_date_of_birth
            .as_ref()
            .and_then(iso_date_from_data_group),
    ));
    details.extend(Detail::optional("Place of birth", &dg11.place_of_birth));
    details.extend(Detail::optional("Address", &dg11.permanent_address));
    details.extend(Detail::optional("Telephone", &dg11.telephone));
    details.extend(Detail::optional("Profession", &dg11.profession));
    details.extend(Detail::optional("Title", &dg11.title));
    details.extend(Detail::optional("Personal summary", &dg11.personal_summary));
    details.extend(Detail::optional(
        "Other valid document numbers",
        &dg11.other_valid_td_numbers,
    ));
    details.extend(Detail::optional(
        "Custody information",
        &dg11.custody_information,
    ));
    if let Some(proof) = dg11.proof_of_citizenship.as_ref() {
        details.push(Detail::new(
            "Proof of citizenship",
            format!("image, {} bytes", proof.len()),
        ));
    }
    return details;
}

/// What the machine readable zone says, field by field.
///
/// The same fields the document block at the top of the app already carries, and
/// deliberately so: there they are the document's details, gathered from wherever they
/// came from. Here they are this file's contents, next to the rows they were read out
/// of, so EF.DG1 can be checked on its own terms — which of those forty-four characters
/// became the date of birth is not something anyone should have to count out by hand.
fn mrz_details(mrz: &types::MRZ) -> Vec<Detail> {
    let mut document = DocumentReport::default();
    fill_from_mrz(&mut document, mrz);

    let mut details = vec![];
    details.extend(Detail::optional("Format", &document.mrz_format));
    details.extend(Detail::optional("Document code", &document.document_code));
    details.extend(Detail::optional("Document type", &document.document_type));
    details.extend(Detail::optional(
        "Document number",
        &document.document_number,
    ));
    details.extend(Detail::optional("Issuing state", &document.issuing_state));
    details.extend(Detail::optional("Nationality", &document.nationality));
    details.extend(Detail::optional("Surname", &document.surname));
    details.extend(Detail::optional("Given names", &document.given_names));
    details.extend(Detail::optional("Legal Sex Marker", &document.sex));
    details.extend(Detail::optional("Date of birth", &document.date_of_birth));
    details.extend(Detail::optional("Date of expiry", &document.date_of_expiry));
    details.extend(Detail::optional("Optional data", &document.optional_data));

    // Which check digit failed, rather than only that one did: they cover different
    // fields, and a document number that does not add up means something quite
    // different from a composite that does not.
    let valid = mrz.validate_check_digits(false);
    let failed: Vec<&str> = mrz
        .check_digit_names()
        .iter()
        .zip(valid.iter())
        .filter(|(_, valid)| !**valid)
        .map(|(name, _)| *name)
        .collect();
    details.push(Detail::new(
        "Check digits",
        if failed.is_empty() {
            format!("All {} valid", valid.len())
        } else {
            format!("Wrong: {}", failed.join(", "))
        },
    ));

    return details;
}

fn document_details(dg12: &types::EFDG12) -> Vec<Detail> {
    let mut details = vec![];
    details.extend(Detail::optional(
        "Issuing authority",
        &dg12.issuing_authority,
    ));
    details.extend(Detail::optional(
        "Date of issue",
        &dg12
            .date_of_issue
            .as_ref()
            .and_then(iso_date_from_data_group),
    ));
    if let Some(other_persons) = dg12
        .other_persons
        .as_ref()
        .filter(|persons| !persons.is_empty())
    {
        details.push(Detail::new("Other persons", other_persons.join(", ")));
    }
    details.extend(Detail::optional(
        "Endorsements and observations",
        &dg12.endorsements_observations,
    ));
    details.extend(Detail::optional(
        "Tax and exit requirements",
        &dg12.tax_exit_requirements,
    ));
    details.extend(Detail::optional(
        "Personalized at",
        &dg12.personalization_timestamp,
    ));
    details.extend(Detail::optional(
        "Personalization device",
        &dg12.personalization_device_serial_number,
    ));
    for (label, image) in [
        ("Front of document", &dg12.image_of_front_of_emrtd),
        ("Rear of document", &dg12.image_of_rear_of_emrtd),
    ] {
        if let Some(image) = image {
            details.push(Detail::new(label, format!("image, {} bytes", image.len())));
        }
    }
    return details;
}

/// The rows to show for one file's parsed contents.
fn details(parsed: &ParsedDataGroup) -> Vec<Detail> {
    let mut details = vec![];
    match parsed {
        ParsedDataGroup::EFCom(ef_com) => {
            if let Some(version) = ef_com.lds_version {
                details.push(Detail::new(
                    "LDS version",
                    String::from_utf8_lossy(&version).into_owned(),
                ));
            }
            details.extend(Detail::optional("Unicode version", &ef_com.unicode_version));
            details.push(Detail::new(
                "Data groups listed",
                data_group_names(&ef_com.data_group_tag_list).join(", "),
            ));
        }
        ParsedDataGroup::EFSOD(security_object) => {
            details.push(Detail::new(
                "Hash algorithm",
                security_object.hash_algorithm.to_string(),
            ));
            for data_group_hash in security_object.data_group_hashes.iter() {
                details.push(Detail::new(
                    &format!("DG{}", data_group_hash.data_group_number),
                    session::hex(&data_group_hash.hash),
                ));
            }
        }
        ParsedDataGroup::EFDG1(dg1) => {
            // The zone laid out in the rows it is printed as rather than as one run of
            // characters, so it can be read against the document in someone's hand.
            details.push(Detail::new("MRZ", dg1.mrz.rows().join("\n")));
            details.extend(mrz_details(&dg1.mrz));
        }
        ParsedDataGroup::EFDG2_3_4(biometrics) => {
            for (index, biometric) in biometrics.biometrics.iter().enumerate() {
                details.push(Detail::new(
                    &format!("Biometric {}", index + 1),
                    format!(
                        "{}, {} bytes",
                        biometric.image_format.get_extension(),
                        biometric.data.len()
                    ),
                ));
            }
        }
        ParsedDataGroup::EFDG5(dg5) => {
            for (index, portrait) in dg5.displayed_portraits.iter().enumerate() {
                details.push(Detail::new(
                    &format!("Portrait {}", index + 1),
                    format!("jpeg, {} bytes", portrait.len()),
                ));
            }
        }
        ParsedDataGroup::EFDG7(dg7) => {
            for (index, signature) in dg7.displayed_signatures.iter().enumerate() {
                details.push(Detail::new(
                    &format!("Signature {}", index + 1),
                    format!("jpeg, {} bytes", signature.len()),
                ));
            }
        }
        ParsedDataGroup::EFDG11(dg11) => details = personal_details(dg11),
        ParsedDataGroup::EFDG12(dg12) => details = document_details(dg12),
        #[cfg(feature = "pace")]
        ParsedDataGroup::EFCardAccess(card_access) => {
            for security_info in card_access.security_infos.iter() {
                // The identifier is what each entry is; the label may as well say so.
                // "Other" carried nothing, and the name it was hiding was repeated
                // underneath it — one line per entry says the same thing in half the
                // room. "Other" is left for the ones we genuinely cannot name.
                match security_info {
                    types::ef_cardaccess::SecurityInfo::Pace(pace_info) => {
                        let oid =
                            types::ef_cardaccess::format_oid(&pace_info.algorithm.to_oid_bytes());
                        let mut value = oid.clone();
                        value.push_str(&format!(", version {}", pace_info.version));
                        if let Some(parameter_id) = pace_info.parameter_id {
                            value.push_str(&format!(", domain parameter {}", parameter_id));
                        }
                        let label = types::ef_cardaccess::describe_protocol_oid(&oid)
                            .unwrap_or_else(|| "PACE".to_string());
                        details.push(Detail::new(&label, value));
                    }
                    types::ef_cardaccess::SecurityInfo::Unknown(unknown) => {
                        let oid = types::ef_cardaccess::format_oid(&unknown.protocol);
                        let label = types::ef_cardaccess::describe_protocol_oid(&oid)
                            .unwrap_or_else(|| "Other".to_string());
                        details.push(Detail::new(&label, oid));
                    }
                }
            }
        }
        #[cfg(feature = "pace")]
        ParsedDataGroup::EFCardSecurity(card_security) => {
            details = chip_authentication_keys(&card_security.chip_authentication_public_keys)
        }
        #[cfg(feature = "pace")]
        ParsedDataGroup::EFDG14(dg14) => {
            details = chip_authentication_keys(&dg14.chip_authentication_public_keys)
        }
    }
    return details;
}

#[cfg(feature = "pace")]
fn chip_authentication_keys(
    keys: &[types::ef_cardaccess::ChipAuthenticationPublicKeyInfo],
) -> Vec<Detail> {
    return keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let label = match key.key_id {
                Some(key_id) => format!("Chip Authentication key {}", key_id),
                None => format!("Chip Authentication key {}", index + 1),
            };
            let parameters = match key.parameter_id {
                Some(parameter_id) => format!("domain parameter {}, ", parameter_id),
                None => String::new(),
            };
            return Detail::new(
                &label,
                format!("{}{} bytes", parameters, key.public_key.len()),
            );
        })
        .collect();
}

/// Name the data groups behind EF.COM's list of tags.
fn data_group_names(tags: &[u8]) -> Vec<String> {
    return tags
        .iter()
        .map(|tag| {
            types::DATA_GROUPS
                .iter()
                .find(|dg_info| dg_info.in_lds1 && dg_info.tag == *tag)
                .map_or_else(
                    || format!("0x{:02X}", tag),
                    |dg_info| dg_info.name.to_string(),
                )
        })
        .collect();
}

/// YYMMDD from an MRZ as YYYY-MM-DD.
fn iso_date_from_mrz(date: &String) -> Option<String> {
    let (day, month, year) = dg_helpers::parse_mrz_date(date)?;
    return Some(format!("{:04}-{:02}-{:02}", year, month, day));
}

/// YYYYMMDD from a data group as YYYY-MM-DD.
fn iso_date_from_data_group(date: &String) -> Option<String> {
    let (day, month, year) = dg_helpers::parse_dg_date(date)?;
    return Some(format!("{:04}-{:02}-{:02}", year, month, day));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact key names the Android app decodes. A rename on this side
    /// without one on that side leaves the app silently reading defaults,
    /// which is how readBinaryFiles went missing in the first place.
    /// What the app is actually handed for a read opened from a file.
    ///
    /// The library checks the data groups against the security object beside them and
    /// says so in the log, so anything the app fails to act on has gone missing between
    /// there and here.
    #[test]
    fn an_import_reports_its_integrity_check() {
        use sha2::Digest;
        let dg1 = b"\x61\x0BP<UTOTEST".to_vec();
        let digest = sha2::Sha256::digest(&dg1).to_vec();
        let files = vec![
            ("X-EF_DG1.bin".to_string(), dg1),
            (
                "X-EF_SOD.bin".to_string(),
                crate::session::import_tests::sod_over(&[(1, digest)]),
            ),
        ];
        let read = crate::session::read_from_files(&files, None);
        let json = serde_json::to_string(&build(&read, vec![])).unwrap();

        assert!(json.contains("\"securityObjectRead\":true"), "{}", json);
        assert!(json.contains("\"checked\":[1]"), "{}", json);
    }

    #[test]
    fn serializes_the_keys_the_app_expects() {
        let report = Report {
            ok: true,
            error_kind: None,
            authentication: Some(AuthenticationReport {
                method: "PACE".to_string(),
                algorithm: Some("PACE-ECDH-CAM-AES-CBC-CMAC-256".to_string()),
            }),
            chip_authentication: Some(ChipAuthenticationReport {
                status: "passed".to_string(),
                source: Some("EF.CardSecurity".to_string()),
                curve: Some("brainpoolP256r1".to_string()),
            }),
            integrity: Some(IntegrityReport {
                security_object_read: true,
                hash_algorithm: Some("SHA-256".to_string()),
                consistent: true,
                checked: vec![1, 2],
                mismatched: vec![],
                unchecked: vec![],
                missing_from_ef_com: vec![],
            }),
            document: Some(DocumentReport {
                surname: Some("MUSTERMANN".to_string()),
                ..Default::default()
            }),
            files: vec![FileReport {
                name: "EF.DG1".to_string(),
                description: "Details recorded in MRZ".to_string(),
                file_id: "0x0101".to_string(),
                present: true,
                size: 93,
                hash_status: "matches".to_string(),
                expected_hash: None,
                actual_hash: None,
                dumped: vec!["/tmp/x-EF_DG1.bin".to_string()],
                images: vec![],
                details: vec![Detail::new("MRZ", "P<UTO...")],
            }],
            portraits: vec!["/tmp/x-EF_DG2-pic1.jpeg".to_string()],
            warnings: vec![],
            log: vec!["INFO  Selecting EF.DG1".to_string()],
            error: None,
        };

        let json = serde_json::to_string(&report).unwrap();
        for key in [
            "\"ok\"",
            "\"authentication\"",
            "\"chipAuthentication\"",
            "\"integrity\"",
            "\"securityObjectRead\"",
            "\"hashAlgorithm\"",
            "\"missingFromEfCom\"",
            "\"document\"",
            "\"surname\"",
            "\"files\"",
            "\"fileId\"",
            "\"hashStatus\"",
            "\"dumped\"",
            "\"images\"",
            "\"details\"",
            "\"portraits\"",
            "\"warnings\"",
            "\"log\"",
        ] {
            assert!(json.contains(key), "{} missing from {}", key, json);
        }
        // Absent optionals are left out rather than sent as null.
        assert!(!json.contains("\"error\""));
        println!("{}", json);
    }

    /// A face image whose format the record failed to name is dumped as
    /// .image_bin, and calling that "not an image" is what hid it from the app.
    #[test]
    fn an_unnamed_image_format_is_still_an_image() {
        use std::path::Path;
        assert!(is_extracted_image(Path::new("/tmp/x-EF_DG2-pic1.jp2")));
        assert!(is_extracted_image(Path::new("/tmp/x-EF_DG2-pic1.jpeg")));
        assert!(is_extracted_image(Path::new(
            "/tmp/x-EF_DG2-pic1.image_bin"
        )));
        assert!(is_extracted_image(Path::new("/tmp/x-EF_DG12-front.jpeg")));
        // The file's own contents are not one of its images.
        assert!(!is_extracted_image(Path::new("/tmp/x-EF_DG2.bin")));
        assert!(!is_extracted_image(Path::new("/tmp/x-EF_DG1.bin")));
        assert!(!is_extracted_image(Path::new("/tmp/no-extension")));
    }

    /// The app shows dates as ISO and formats them itself, so a two-digit year
    /// has to have been resolved by the time it gets there.
    #[test]
    fn renders_dates_the_app_can_parse() {
        assert_eq!(
            iso_date_from_mrz(&"030201".to_string()),
            Some("2003-02-01".to_string())
        );
        assert_eq!(
            iso_date_from_mrz(&"850201".to_string()),
            Some("1985-02-01".to_string())
        );
        assert_eq!(
            iso_date_from_data_group(&"20030201".to_string()),
            Some("2003-02-01".to_string())
        );
        // A field the document filled with something else must not become a
        // wrong-looking date.
        assert_eq!(iso_date_from_mrz(&"".to_string()), None);
        assert_eq!(iso_date_from_mrz(&"AB0201".to_string()), None);
    }

    /// EF.COM lists tags, and a tag means nothing to someone reading the screen.
    #[test]
    fn names_the_data_groups_ef_com_lists() {
        assert_eq!(
            data_group_names(&[0x61, 0x75, 0x6e]),
            vec!["EF.DG1", "EF.DG2", "EF.DG14"]
        );
        // An unknown tag still has to show up rather than vanish.
        assert_eq!(data_group_names(&[0x01]), vec!["0x01"]);
    }

    /// The MRZ splits names on `<<`, which is not how anyone wants to read them.
    #[test]
    fn splits_the_holders_name() {
        let mut document = DocumentReport::default();
        // The specimen from ICAO 9303 p4, Appendix B.
        let mrz = types::MRZ::deserialize(
            &"P<UTOMUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<\
              L898902C36UTO7408122F1204159ZE184226B<<<<<10"
                .to_string(),
        )
        .unwrap();
        fill_from_mrz(&mut document, &mrz);

        assert_eq!(document.surname, Some("MUSTERMANN".to_string()));
        assert_eq!(document.given_names, Some("ERIKA".to_string()));
        assert_eq!(document.document_number, Some("L898902C3".to_string()));
        assert_eq!(document.date_of_birth, Some("1974-08-12".to_string()));
        assert_eq!(document.date_of_expiry, Some("2012-04-15".to_string()));
        assert_eq!(document.sex, Some("Female".to_string()));
        assert_eq!(document.mrz_format, Some("TD3".to_string()));
    }

    /// EF.DG1 shows the zone and what was read out of it, side by side.
    #[test]
    fn spells_out_what_the_zone_says() {
        let mrz = types::MRZ::deserialize(
            &"P<UTOMUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<\
              L898902C36UTO7408122F1204159ZE184226B<<<<<10"
                .to_string(),
        )
        .unwrap();
        let details = mrz_details(&mrz);
        let row = |label: &str| {
            details
                .iter()
                .find(|detail| detail.label == label)
                .map(|detail| detail.value.clone())
        };

        assert_eq!(row("Document number"), Some("L898902C3".to_string()));
        assert_eq!(row("Surname"), Some("MUSTERMANN".to_string()));
        assert_eq!(row("Given names"), Some("ERIKA".to_string()));
        assert_eq!(row("Date of birth"), Some("1974-08-12".to_string()));
        assert_eq!(row("Check digits"), Some("All 5 valid".to_string()));
        // The zone itself is not one of these rows; the caller adds it above them.
        assert_eq!(row("MRZ"), None);
    }

    /// EF.SOD hashes the LDS1 data groups and nothing else, so the files outside
    /// it are not "unchecked" — there was never a check for them to have missed.
    #[test]
    fn does_not_claim_a_check_was_skipped_for_files_it_never_covers() {
        let uncoverable = [
            "EF.COM",
            "EF.SOD",
            "EF.CardAccess",
            "EF.CardSecurity",
            "EF.DIR",
            "EF.ATR/INFO",
        ];
        for dg_info in types::DATA_GROUPS.iter() {
            let file = FileRead {
                name: dg_info.name,
                description: dg_info.description,
                file_id: dg_info.file_id,
                data: Some(vec![]),
                parsed: None,
                hash: HashCheck::NotCovered,
                dumped: vec![],
            };
            let expected = if uncoverable.contains(&dg_info.name) {
                "notApplicable"
            } else {
                "notCovered"
            };
            assert_eq!(
                super::file(&file).hash_status,
                expected,
                "{} reported the wrong hash status",
                dg_info.name
            );
        }
    }
}
