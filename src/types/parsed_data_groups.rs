use crate::types::MRZ;
use strum::FromRepr;

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
pub struct EFDG2_3_4 {
    // ICAO 9303 part 10, edition 8, 4.7.2/3/4
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
    EFDG2_3_4(EFDG2_3_4),
    EFDG5(EFDG5),
    EFDG7(EFDG7),
    EFDG11(EFDG11),
    EFDG12(EFDG12),
}
