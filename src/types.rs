use simplelog::warn;
use std::{cmp::min, error::Error, fmt};
use strum::FromRepr;

use crate::{dg_parsers::helpers as dg_helpers, icao9303};

#[derive(Debug)]
pub struct ParseError {}

impl Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed to parse value from given String.")
    }
}

// handy: https://oid-rep.orange-labs.fr/get/0.4.0.127.0.7.2.2.2
// pub static PACE_DOMAIN_PARAMETERS_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01),
//     "ECDH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02),
//     "DH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03),
//     "ECDH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04),
//     "ECDH_CAM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06),
// };

// pub static CHIP_AUTH_DOMAIN_PARAMETERS_OIDS: phf::Map<
//     &'static str,
//     &'static asn1::ObjectIdentifier,
// > = phf_map! {
//     "DH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01),
//     "ECDH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02),
// };

// pub static PACEINFO_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01),
//     "DH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02),
//     "DH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03),
//     "DH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04),
//     "ECDH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01),
//     "ECDH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02),
//     "ECDH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03),
//     "ECDH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04),
//     "DH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01),
//     "DH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02),
//     "DH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03),
//     "DH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04),
//     "ECDH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01),
//     "ECDH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02),
//     "ECDH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03),
//     "ECDH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04),
//     "ECDH_CAM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x01),
//     "ECDH_CAM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02),
//     "ECDH_CAM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x03),
//     "ECDH_CAM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04),
// };

// pub static CHIPAUTH_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01),
//     "DH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x02),
//     "DH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x03),
//     "DH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x04),
//     "ECDH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01),
//     "ECDH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x02),
//     "ECDH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x03),
//     "ECDH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x04),
// };

// // Pseudonymous Signature Authentication
// pub static PSA_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "ECDH_ECSCHNORR_SHA_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x03),
//     "ECDH_ECSCHNORR_SHA_384" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x04),
//     "ECDH_ECSCHNORR_SHA_512" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x05),
// };

// // Terminal Authentication
// const TA_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02);

// // Privileged Terminal
// const PT_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x08);

// // BSI TR-03110 addons
// const CARD_INFO_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x06);

// // BSI TR-03111 stuff for AlgorithmIdentifier
// const OID_EC_KEY_TYPE: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x01, 0x02);

// #[derive(Debug)]
// struct SecurityInfos {
//     // #[defined_by(OID_TA)]
//     pub terminal_authentication_info: Vec<TerminalAuthenticationInfo>,
//     // #[defined_by(OID_PT)]
//     pub privileged_terminal_info: Vec<PrivilegedTerminalInfo>,
//     // #[defined_by(OID_CA_DH_3DES_CBC_CBC)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_128)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_192)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_256)]
//     // #[defined_by(OID_CA_ECDH_3DES_CBC_CBC)]
//     // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_128)]
//     // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_192)]
//     pub chip_authentication_info: Vec<ChipAuthenticationInfo>,
//     // #[defined_by(OID_CA_DH)]
//     // #[defined_by(OID_CA_ECDH)]
//     pub chip_authentication_domain_parameter_info: Vec<ChipAuthenticationDomainParameterInfo>,
//     // #[defined_by(OID_PACE_DH_GM)]
//     // #[defined_by(OID_PACE_ECDH_GM)]
//     // #[defined_by(OID_PACE_DH_IM)]
//     // #[defined_by(OID_PACE_ECDH_IM)]
//     // #[defined_by(OID_PACE_ECDH_CAM)]
//     pub pace_domain_parameter_info: Vec<PACEDomainParameterInfo>,
//     // #[defined_by(OID_PACE_ECDH_IM_AES_CBC_CMAC_256)]
//     pub pace_info: Vec<PACEInfoParameters>,
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_256)]
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_384)]
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_512)]
//     pub pseudonymous_signature_authentication_info: Vec<PSAInfo>,
//     // #[defined_by(OID_CARD_INFO)]
//     pub card_info: Vec<CardInfo>,
//     // TODO: PasswordInfo (optional)
//     // TODO: PSMInfo (conditional)
//     // TODO: PSCInfo (conditional)
//     // TODO: ChipAuthenticationPublicKeyInfo
//     // TODO: PSPublicKeyInfo
//     // TODO: RestrictedIdentificationInfo
//     // TODO: RestrictedIdentificationDomainParameterInfo
//     // TODO: EIDSecurityInfo
// }

// #[derive(Debug)]
// struct FileID {
//     // ICAO 9303 part 11
//     pub fid: String,
//     pub sfid: Option<String>,
// }

// #[derive(Debug)]
// struct TerminalAuthenticationInfo {
//     pub version: u64, // ICAO 9303: should be 1, BSI TR-03110-3: MUST be 1 or 2
//     pub ef_cvca: Option<FileID>, // BSI TR-03110-3: MUST not be used for version 2
// }

// #[derive(Debug)]
// struct ChipAuthenticationInfo {
//     pub version: u64, // BSI TR-03110-3: MUST be 1, 2 or 3
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// pub struct PACEInfoParameters {
//     pub version: u64, // BSI TR-03110-3: SHOULD be 2
//     pub parameter_id: Option<u64>,
// }

// #[derive(Debug)]
// struct PSAInfo {
//     pub required_data: PSARequiredData, // BSI TR-03110-3: SHOULD be 2
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// struct PSARequiredData {
//     pub version: u64,       // BSI TR-03110-3: MUST be 1
//     pub ps1_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
//     pub ps2_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
// }

// #[derive(Debug)]
// struct PACEDomainParameterInfo {
//     pub domain_parameter: AlgorithmIdentifier,
//     pub parameter_id: Option<u64>,
// }

// #[derive(Debug)]
// struct ChipAuthenticationDomainParameterInfo {
//     pub domain_parameter: AlgorithmIdentifier,
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// struct AlgorithmIdentifier {
//     pub algorithm: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
//     // TODO: parameters here are algorithm dependent.
//     // Details on the parameters can be found in [X9.42] and [TR-03111]
//     pub key_type: u64,
// }

// #[derive(Debug)]
// struct PrivilegedTerminalInfo {
//     pub privileged_terminal_infos: Vec<SecurityInfos>,
// }

// #[derive(Debug)]
// struct CardInfo {
//     pub url_card_info: String,
//     pub optional_card_info_data: Option<ExtCardInfoData>,
// }

// #[derive(Debug)]
// struct SupportedTerminalTypes {
//     pub supported_terminal_type: asn1::ObjectIdentifier,
//     pub supported_authorizations: Option<Vec<asn1::ObjectIdentifier>>,
// }

// #[derive(Debug)]
// struct ExtCardInfoData {
//     pub ef_card_info: Option<FileID>,
//     pub supported_tr_version: Option<String>,
//     pub supp_terminal_types: Option<Vec<SupportedTerminalTypes>>,
//     pub max_sc_no: Option<u64>,
//     pub env_info: Option<bool>,
// }

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
    pub mrz: MRZ,
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
            BiometricImageFormat::Jpeg => "jpeg",
            BiometricImageFormat::Jpeg2000 => "jp2",
            BiometricImageFormat::Reserved => "image_bin",
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
pub struct EFDG5 {
    // ICAO 9303 part 10, edition 8, 4.7.5
    /// Vector of JPEG files (as Vec<u8>)
    pub displayed_portraits: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct EFDG7 {
    // ICAO 9303 part 10, edition 8, 4.7.7
    /// Displayed Signatures or Usual Mark
    /// Vector of JPEG files (as Vec<u8>)
    pub displayed_signatures: Vec<Vec<u8>>,
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
    EFDG5(EFDG5),
    EFDG7(EFDG7),
    EFDG11(EFDG11),
    EFDG12(EFDG12),
}

fn validate_mrz_field_check_digit(
    field: &String,
    check_digit: &char,
    verbose: bool,
    verbose_as: Option<String>,
) -> bool {
    let calculated_check_digit = icao9303::calculate_check_digit(&field);
    let check_digit_valid = *check_digit == calculated_check_digit;
    if !check_digit_valid && verbose && verbose_as.is_some() {
        warn!(
            "{} checksum is invalid (doc={}, calculated={}).",
            verbose_as.unwrap(),
            check_digit,
            calculated_check_digit
        );
    }
    return check_digit_valid;
}

#[derive(Debug)]
pub enum MRZ {
    TD1(TD1Mrz),
    // TD2(TD2Mrz),
    TD3(TD3Mrz),
}

impl MRZ {
    pub fn deserialize(input: &String) -> Option<MRZ> {
        match input.len() {
            90 => Some(MRZ::TD1(TD1Mrz::deserialize(input)?)),
            88 => Some(MRZ::TD3(TD3Mrz::deserialize(input)?)),
            _ => None,
        }
    }

    // allowing dead code here because I think this is a useful API as a library
    #[allow(dead_code)]
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        match self {
            Self::TD1(mrzobj) => mrzobj.validate_check_digits(verbose),
            Self::TD3(mrzobj) => mrzobj.validate_check_digits(verbose),
        }
    }

    #[cfg(feature = "cli")]
    pub fn fancy_print(&self) {
        match self {
            Self::TD1(mrzobj) => mrzobj.fancy_print(),
            Self::TD3(mrzobj) => mrzobj.fancy_print(),
        }
    }
}

pub trait MRZChecksum {
    /// Internal function for use with traits, as one cannot define fields in a trait.
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    );

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid)
    fn calculate_common_checksums(&self, verbose: bool) -> (bool, bool, bool, bool) {
        // cd = check digit
        let (
            document_number,
            document_number_cd,
            date_of_birth,
            date_of_birth_cd,
            date_of_expiry,
            date_of_expiry_cd,
            composite_base,
            composite_cd,
        ) = self.get_checksum_variables();

        let document_number_valid = validate_mrz_field_check_digit(
            document_number,
            document_number_cd,
            verbose,
            Some("Document number".to_string()),
        );
        let date_of_birth_valid = validate_mrz_field_check_digit(
            date_of_birth,
            date_of_birth_cd,
            verbose,
            Some("Date of birth".to_string()),
        );
        let date_of_expiry_valid = validate_mrz_field_check_digit(
            date_of_expiry,
            date_of_expiry_cd,
            verbose,
            Some("Date of expiry".to_string()),
        );
        let composite_valid = validate_mrz_field_check_digit(
            &composite_base,
            composite_cd,
            verbose,
            Some("Composite".to_string()),
        );

        return (
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            composite_valid,
        );
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TD1Mrz {
    // ICAO 9303 part 5, edition 8, 4.2.2
    /// 90 characters of MRZ (physically shown as 3 lines)
    pub raw_mrz: String,
    // Line 1
    /// 2 characters. The first character shall be P to designate an MRP.
    /// The second character shall be as specified in ICAO 9303 part 5,
    /// edition 8, 4.2.2.3 Note k.
    pub document_code: String,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    pub issuing_state: String,
    /// 9 characters
    pub document_number: String,
    /// 1 character
    pub document_number_check_digit: char,
    /// up to 15 characters
    pub optional_data_elements_line_1: String,
    // Line 2
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
    /// The three-letter code specified in Doc 9303-3 shall be used.
    pub nationality: String,
    /// up to 11 characters
    pub optional_data_elements_line_2: String,
    /// 1 character
    pub composite_check_digit: char,
    // line 3
    /// 30 characters
    pub name_of_holder: String,
}

impl MRZChecksum for TD1Mrz {
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    ) {
        // ICAO 9303 p5, edition 8, 4.2.4 says:
        // Character positions (upper/middle MRZ line)
        // used to calculate check digit
        // 6 – 30 (upper line),
        // 1 – 7, 9 – 15, 19 – 29 (middle line)
        let composite_base = vec![
            &self.raw_mrz[5..30],
            &self.raw_mrz[30..30 + 7],
            &self.raw_mrz[30 + 8..30 + 15],
            &self.raw_mrz[30 + 18..30 + 29],
        ]
        .concat();

        return (
            &self.document_number,
            &self.document_number_check_digit,
            &self.date_of_birth,
            &self.date_of_birth_check_digit,
            &self.date_of_expiry,
            &self.date_of_expiry_check_digit,
            composite_base,
            &self.composite_check_digit,
        );
    }
}

impl TD1Mrz {
    pub fn deserialize(input: &String) -> Option<TD1Mrz> {
        if input.len() != 90 {
            return None;
        }
        // ICAO 9303 p5, Edition 8, 4.2.2.3, Note j says:
        // "The number of characters in the VIZ may be variable; however, if the document number has more than 9
        // characters, the 9 principal characters shall be shown in the MRZ in character positions 6 to 14. They shall be
        // followed by a filler character instead of a check digit to indicate a truncated number. The remaining characters
        // of the document number shall be shown at the beginning of the field reserved for optional data elements
        // (character positions 16 to 30 of the upper machine readable line) followed by a check digit and a filler character."
        let mut document_number = dg_helpers::remove_mrz_padding(&input[5..14].to_string());
        let mut document_number_check_digit = input.chars().nth(14)?;
        let mut optional_data_elements_line_1 =
            dg_helpers::remove_mrz_padding(&input[15..30].to_string());
        // Check if this is truncated document number
        if document_number_check_digit == '<' {
            // Find the < separating the rest of document number from optional data elements
            let end_of_doc_number = optional_data_elements_line_1
                .find('<')
                .unwrap_or(optional_data_elements_line_1.len());
            // Add the rest of the document number into the document number field and set new check digit
            document_number.push_str(&optional_data_elements_line_1[..end_of_doc_number - 1]);
            document_number_check_digit = optional_data_elements_line_1
                .chars()
                .nth(end_of_doc_number - 1)?;
            // Cut off rest of the document number from optional data elements.
            // Ensure we don't go over the size. Normally this shouldn't happen if the document number
            // follows the standard (the filler character is present), but this implementation assumes
            // that some implementations may max out the size of optional elements.
            optional_data_elements_line_1 = optional_data_elements_line_1
                [min(end_of_doc_number + 1, optional_data_elements_line_1.len())..]
                .to_string();
        }
        return Some(TD1Mrz {
            raw_mrz: input.to_string(),
            // Line 1
            document_code: input[0..2].to_string(),
            issuing_state: dg_helpers::remove_mrz_padding(&input[2..5].to_string()),
            document_number: document_number,
            document_number_check_digit: document_number_check_digit,
            optional_data_elements_line_1: optional_data_elements_line_1,
            // Line 2
            date_of_birth: input[30..36].to_string(),
            date_of_birth_check_digit: input.chars().nth(36)?,
            sex: input.chars().nth(37)?,
            date_of_expiry: input[38..44].to_string(),
            date_of_expiry_check_digit: input.chars().nth(44)?,
            nationality: dg_helpers::remove_mrz_padding(&input[45..48].to_string()),
            optional_data_elements_line_2: dg_helpers::remove_mrz_padding(
                &input[48..59].to_string(),
            ),
            composite_check_digit: input.chars().nth(59)?,
            // Line 3
            name_of_holder: dg_helpers::remove_mrz_padding(&input[60..89].to_string()),
        });
    }

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid,
    /// composite_valid)
    ///
    /// verbose argument makes invalid check digits to log as warn.
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        // Converting tuples to Vectors is hard.
        let (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid) =
            self.calculate_common_checksums(verbose);

        return vec![
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            composite_valid,
        ];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn td1_short_document_number_parsing() {
        let mrz = &"I<UTO1234567897ABCDEFGH<<<<<<<0001029<3001020UTO<<<<<<<<<<<8MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789");
        assert_eq!(result.document_number_check_digit, '7');
        assert_eq!(result.optional_data_elements_line_1, "ABCDEFGH");
    }

    #[test]
    fn td1_long_document_number_parsing() {
        let mrz = &"I<UTO123456789<ABCD3<TEST<<<<<0001029<3001020UTO<<<<<<<<<<<2MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789ABCD");
        assert_eq!(result.document_number_check_digit, '3');
        assert_eq!(result.optional_data_elements_line_1, "TEST");
    }

    #[test]
    fn td1_full_length_document_number_parsing() {
        let mrz = &"I<UTO123456789<ABCDABCDABCDAB60001029<3001020UTO<<<<<<<<<<<0MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789ABCDABCDABCDAB");
        assert_eq!(result.document_number_check_digit, '6');
        assert_eq!(result.optional_data_elements_line_1, "");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TD3Mrz {
    // ICAO 9303 part 4, edition 8, 4.2.2
    /// 88 characters of MRZ (physically shown as 2 lines)
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

impl MRZChecksum for TD3Mrz {
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    ) {
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

        return (
            &self.document_number,
            &self.document_number_check_digit,
            &self.date_of_birth,
            &self.date_of_birth_check_digit,
            &self.date_of_expiry,
            &self.date_of_expiry_check_digit,
            composite_base,
            &self.composite_check_digit,
        );
    }
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

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid,
    /// personal_number_or_optional_data_elements_valid, composite_valid)
    ///
    /// verbose argument makes invalid check digits to log as warn.
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        let mut personal_number_or_optional_data_elements_valid = true;
        // If it's empty, then the check digit can be empty.
        if self.personal_number_or_optional_data_elements.len() != 0 {
            personal_number_or_optional_data_elements_valid = validate_mrz_field_check_digit(
                &self.personal_number_or_optional_data_elements,
                &self.personal_number_or_optional_data_elements_check_digit,
                verbose,
                Some("Personal number or optional data elements".to_string()),
            );
        } else if verbose {
            warn!("Personal number or optional data elements is empty, ignoring check digit.");
        }

        let (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid) =
            self.calculate_common_checksums(verbose);

        return vec![
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            personal_number_or_optional_data_elements_valid,
            composite_valid,
        ];
    }
}
