use asn1;
use phf::phf_map;
use simplelog::warn;
use strum::FromRepr;

use crate::{dg_parsers::helpers as dg_helpers, icao9303};

// handy: https://oid-rep.orange-labs.fr/get/0.4.0.127.0.7.2.2.2
pub static PACE_DOMAIN_PARAMETERS_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
    "DH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01),
    "ECDH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02),
    "DH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03),
    "ECDH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04),
    "ECDH_CAM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06),
};

pub static CHIP_AUTH_DOMAIN_PARAMETERS_OIDS: phf::Map<
    &'static str,
    &'static asn1::ObjectIdentifier,
> = phf_map! {
    "DH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01),
    "ECDH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02),
};

pub static PACEINFO_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
    "DH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01),
    "DH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02),
    "DH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03),
    "DH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04),
    "ECDH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01),
    "ECDH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02),
    "ECDH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03),
    "ECDH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04),
    "DH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01),
    "DH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02),
    "DH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03),
    "DH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04),
    "ECDH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01),
    "ECDH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02),
    "ECDH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03),
    "ECDH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04),
    "ECDH_CAM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x01),
    "ECDH_CAM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02),
    "ECDH_CAM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x03),
    "ECDH_CAM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04),
};

pub static CHIPAUTH_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
    "DH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01),
    "DH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x02),
    "DH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x03),
    "DH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x04),
    "ECDH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01),
    "ECDH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x02),
    "ECDH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x03),
    "ECDH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x04),
};

// Pseudonymous Signature Authentication
pub static PSA_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
    "ECDH_ECSCHNORR_SHA_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x03),
    "ECDH_ECSCHNORR_SHA_384" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x04),
    "ECDH_ECSCHNORR_SHA_512" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x05),
};

// Terminal Authentication
const TA_OID: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02);

// Privileged Terminal
const PT_OID: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x08);

// BSI TR-03110 addons
const CARD_INFO_OID: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x06);

// BSI TR-03111 stuff for AlgorithmIdentifier
const OID_EC_KEY_TYPE: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x01, 0x02);

#[derive(Debug)]
struct SecurityInfos {
    // #[defined_by(OID_TA)]
    pub terminal_authentication_info: Vec<TerminalAuthenticationInfo>,
    // #[defined_by(OID_PT)]
    pub privileged_terminal_info: Vec<PrivilegedTerminalInfo>,
    // #[defined_by(OID_CA_DH_3DES_CBC_CBC)]
    // #[defined_by(OID_CA_DH_AES_CBC_CMAC_128)]
    // #[defined_by(OID_CA_DH_AES_CBC_CMAC_192)]
    // #[defined_by(OID_CA_DH_AES_CBC_CMAC_256)]
    // #[defined_by(OID_CA_ECDH_3DES_CBC_CBC)]
    // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_128)]
    // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_192)]
    pub chip_authentication_info: Vec<ChipAuthenticationInfo>,
    // #[defined_by(OID_CA_DH)]
    // #[defined_by(OID_CA_ECDH)]
    pub chip_authentication_domain_parameter_info: Vec<ChipAuthenticationDomainParameterInfo>,
    // #[defined_by(OID_PACE_DH_GM)]
    // #[defined_by(OID_PACE_ECDH_GM)]
    // #[defined_by(OID_PACE_DH_IM)]
    // #[defined_by(OID_PACE_ECDH_IM)]
    // #[defined_by(OID_PACE_ECDH_CAM)]
    pub pace_domain_parameter_info: Vec<PACEDomainParameterInfo>,
    // #[defined_by(OID_PACE_ECDH_IM_AES_CBC_CMAC_256)]
    pub pace_info: Vec<PACEInfoParameters>,
    // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_256)]
    // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_384)]
    // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_512)]
    pub pseudonymous_signature_authentication_info: Vec<PSAInfo>,
    // #[defined_by(OID_CARD_INFO)]
    pub card_info: Vec<CardInfo>,
    // TODO: PasswordInfo (optional)
    // TODO: PSMInfo (conditional)
    // TODO: PSCInfo (conditional)
    // TODO: ChipAuthenticationPublicKeyInfo
    // TODO: PSPublicKeyInfo
    // TODO: RestrictedIdentificationInfo
    // TODO: RestrictedIdentificationDomainParameterInfo
    // TODO: EIDSecurityInfo
}

#[derive(Debug)]
struct FileID {
    // ICAO 9303 part 11
    pub fid: String,
    pub sfid: Option<String>,
}

#[derive(Debug)]
struct TerminalAuthenticationInfo {
    pub version: u64, // ICAO 9303: should be 1, BSI TR-03110-3: MUST be 1 or 2
    pub ef_cvca: Option<FileID>, // BSI TR-03110-3: MUST not be used for version 2
}

#[derive(Debug)]
struct ChipAuthenticationInfo {
    pub version: u64, // BSI TR-03110-3: MUST be 1, 2 or 3
    pub key_id: Option<u64>,
}

#[derive(Debug)]
pub struct PACEInfoParameters {
    pub version: u64, // BSI TR-03110-3: SHOULD be 2
    pub parameter_id: Option<u64>,
}

#[derive(Debug)]
struct PSAInfo {
    pub required_data: PSARequiredData, // BSI TR-03110-3: SHOULD be 2
    pub key_id: Option<u64>,
}

#[derive(Debug)]
struct PSARequiredData {
    pub version: u64,       // BSI TR-03110-3: MUST be 1
    pub ps1_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
    pub ps2_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
}

#[derive(Debug)]
struct PACEDomainParameterInfo {
    pub domain_parameter: AlgorithmIdentifier,
    pub parameter_id: Option<u64>,
}

#[derive(Debug)]
struct ChipAuthenticationDomainParameterInfo {
    pub domain_parameter: AlgorithmIdentifier,
    pub key_id: Option<u64>,
}

#[derive(Debug)]
struct AlgorithmIdentifier {
    pub algorithm: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    // TODO: parameters here are algorithm dependent.
    // Details on the parameters can be found in [X9.42] and [TR-03111]
    pub key_type: u64,
}

#[derive(Debug)]
struct PrivilegedTerminalInfo {
    pub privileged_terminal_infos: Vec<SecurityInfos>,
}

#[derive(Debug)]
struct CardInfo {
    pub url_card_info: String,
    pub optional_card_info_data: Option<ExtCardInfoData>,
}

#[derive(Debug)]
struct SupportedTerminalTypes {
    pub supported_terminal_type: asn1::ObjectIdentifier,
    pub supported_authorizations: Option<Vec<asn1::ObjectIdentifier>>,
}

#[derive(Debug)]
struct ExtCardInfoData {
    pub ef_card_info: Option<FileID>,
    pub supported_tr_version: Option<String>,
    pub supp_terminal_types: Option<Vec<SupportedTerminalTypes>>,
    pub max_sc_no: Option<u64>,
    pub env_info: Option<bool>,
}

#[derive(Debug)]
pub struct EFCom {
    // ICAO 9303 part 10, edition 8, 4.6.1
    pub lds_version: Option<[u8; 4]>,
    pub unicode_version: Option<String>,
    pub data_group_tag_list: Vec<u8>,
}

#[derive(Debug)]
pub struct EFDG1 {
    // ICAO 9303 part 10, edition 8, 4.7.1
    /// Can be parsed using MRZ/TD1Mrz/TD2Mrz/TD3Mrz.
    pub raw_mrz: String,
}

#[derive(Debug, FromRepr, PartialEq, Clone, Copy)]
pub enum BiometricImageFormat {
    // ISO/IEC 19794:5-2005, 5.7.2
    Jpeg = 0x00,
    Jpeg2000 = 0x01,
    Reserved = 0x02,
}

impl BiometricImageFormat {
    pub fn get_extension(&self) -> String {
        match &self {
            BiometricImageFormat::Jpeg => ".jpeg",
            BiometricImageFormat::Jpeg2000 => ".jp2",
            BiometricImageFormat::Reserved => ".image_bin",
        }
        .to_string()
    }
}

#[derive(Debug)]
pub struct Biometric {
    // ICAO 9303 part 10, edition 8, 4.7.2.1
    // Biometric Header Template (BHT) + Biometric data (encoded according to Format Owner)
    pub header_version: Option<Vec<u8>>,
    pub biometric_type: Option<Vec<u8>>,
    pub biometric_sub_type: Option<u8>,
    pub creation_timestamp: Option<Vec<u8>>,
    pub validity_period_from_through: Option<Vec<u8>>,
    pub creator_of_biometric_data: Option<Vec<u8>>,
    pub format_owner: Vec<u8>,
    pub format_type: Vec<u8>,
    pub data: Vec<u8>,
    pub image_format: BiometricImageFormat,
}

#[derive(Debug)]
pub struct EFDG2 {
    // ICAO 9303 part 10, edition 8, 4.7.2
    pub biometrics: Vec<Biometric>,
}

#[derive(Debug)]
pub struct EFDG11 {
    // ICAO 9303 part 10, edition 8, 4.7.11
    pub full_name: Option<String>,
    pub other_names: Option<Vec<String>>,
    pub personal_number: Option<String>,
    /// YYYYMMDD
    pub full_date_of_birth: Option<String>,
    pub place_of_birth: Option<String>,
    pub permanent_address: Option<String>,
    pub telephone: Option<String>,
    pub profession: Option<String>,
    pub title: Option<String>,
    pub personal_summary: Option<String>,
    /// JPEG
    pub proof_of_citizenship: Option<Vec<u8>>,
    pub other_valid_td_numbers: Option<String>,
    pub custody_information: Option<String>,
}

#[derive(Debug)]
pub struct EFDG12 {
    // ICAO 9303 part 10, edition 8, 4.7.12
    pub issuing_authority: Option<String>,
    /// YYYYMMDD
    pub date_of_issue: Option<String>,
    pub other_persons: Option<Vec<String>>,
    pub endorsements_observations: Option<String>,
    pub tax_exit_requirements: Option<String>,
    /// JPEG
    pub image_of_front_of_emrtd: Option<Vec<u8>>,
    /// JPEG
    pub image_of_rear_of_emrtd: Option<Vec<u8>>,
    /// yyyymmddhhmmss
    pub personalization_timestamp: Option<String>,
    pub personalization_device_serial_number: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ParsedDataGroup {
    EFCom(EFCom),
    EFDG1(EFDG1),
    EFDG2(EFDG2),
    EFDG11(EFDG11),
    EFDG12(EFDG12),
}

#[derive(Debug)]
pub enum MRZ {
    // TD1Mrz(TD1Mrz),
    // TD2Mrz(TD2Mrz),
    TD3Mrz(TD3Mrz),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TD3Mrz {
    // ICAO 9303 part 4, edition 8, 4.2.2
    pub raw_mrz: String,
    /// 2 characters. The first character shall be P to designate an MRP.
    /// The second character shall identify the MRP type, as detailed in Section 4.4.
    pub document_code: String,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    /// Spaces shall be replaced by filler characters (<).
    pub issuing_state: String,
    /// 39 characters.
    pub name_of_holder: String,
    /// 9 characters
    pub document_number: String,
    /// 1 character
    pub document_number_check_digit: char,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    /// Spaces shall be replaced by filler characters (<).
    pub nationality: String,
    /// 6 characters, YYMMDD
    pub date_of_birth: String,
    /// 1 character
    pub date_of_birth_check_digit: char,
    /// F = female; M = male; < = unspecified.
    pub sex: char,
    /// 6 characters, YYMMDD
    pub date_of_expiry: String,
    /// 1 character
    pub date_of_expiry_check_digit: char,
    /// 14 characters, padded with <
    pub personal_number_or_optional_data_elements: String,
    /// 1 character, can be 0 or < if personal_number_or_optional_data_elements is unused.
    pub personal_number_or_optional_data_elements_check_digit: char,
    /// 1 character
    pub composite_check_digit: char,
}

fn validate_field_check_digit(
    field: &String,
    check_digit: &char,
    verbose_as: Option<String>,
) -> bool {
    let calculated_check_digit = icao9303::calculate_check_digit(&field);
    let check_digit_valid = *check_digit == calculated_check_digit;
    if !check_digit_valid && verbose_as.is_some() {
        warn!(
            "{} checksum is invalid (doc={}, calculated={}).",
            verbose_as.unwrap(),
            check_digit,
            calculated_check_digit
        );
    }
    return check_digit_valid;
}

impl TD3Mrz {
    pub fn deserialize(input: &String) -> Option<TD3Mrz> {
        if input.len() != 88 {
            return None;
        }
        return Some(TD3Mrz {
            raw_mrz: input.to_string(),
            document_code: input[0..2].to_string(),
            issuing_state: dg_helpers::remove_mrz_padding(&input[2..5].to_string()),
            name_of_holder: dg_helpers::remove_mrz_padding(&input[5..44].to_string()),
            document_number: dg_helpers::remove_mrz_padding(&input[44..53].to_string()),
            document_number_check_digit: input.chars().nth(53)?,
            nationality: dg_helpers::remove_mrz_padding(&input[54..57].to_string()),
            date_of_birth: input[57..63].to_string(),
            date_of_birth_check_digit: input.chars().nth(63)?,
            sex: input.chars().nth(64)?,
            date_of_expiry: input[65..71].to_string(),
            date_of_expiry_check_digit: input.chars().nth(71)?,
            personal_number_or_optional_data_elements: dg_helpers::remove_mrz_padding(
                &input[72..86].to_string(),
            ),
            personal_number_or_optional_data_elements_check_digit: input.chars().nth(86)?,
            composite_check_digit: input.chars().nth(87)?,
        });
    }

    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        let document_number_valid = validate_field_check_digit(
            &self.document_number,
            &self.document_number_check_digit,
            Some("Document number".to_string()),
        );
        let date_of_birth_valid = validate_field_check_digit(
            &self.date_of_birth,
            &self.date_of_birth_check_digit,
            Some("Date of birth".to_string()),
        );
        let date_of_expiry_valid = validate_field_check_digit(
            &self.date_of_expiry,
            &self.date_of_expiry_check_digit,
            Some("Date of expiry".to_string()),
        );

        let mut personal_number_or_optional_data_elements_valid = true;
        // If it's empty, then the check digit can be empty.
        if self.personal_number_or_optional_data_elements.len() != 0 {
            personal_number_or_optional_data_elements_valid = validate_field_check_digit(
                &self.personal_number_or_optional_data_elements,
                &self.personal_number_or_optional_data_elements_check_digit,
                Some("Personal number or optional data elements".to_string()),
            );
        } else if verbose {
            warn!("Personal number or optional data elements is empty, ignoring check digit.");
        }

        // ICAO 9303 p4, edition 8, 4.2.2.2 says:
        // "Composite check digit for characters of machine readable data of the lower line
        // in positions 1 to 10, 14 to 20 and 22 to 43, including values for letters that are
        // a part of the number fields and their check digits."
        let composite_base = vec![
            &self.raw_mrz[44..44 + 10],
            &self.raw_mrz[44 + 13..44 + 20],
            &self.raw_mrz[44 + 21..44 + 43],
        ]
        .concat();
        let composite_valid = validate_field_check_digit(
            &composite_base,
            &self.composite_check_digit,
            Some("Composite".to_string()),
        );

        return vec![
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            personal_number_or_optional_data_elements_valid,
            composite_valid,
        ];
    }
}
