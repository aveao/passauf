use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::{cmp::max, collections::HashMap};

use crate::{helpers, types};

pub(crate) const SECTION_TITLE_PAD_TO_LEN: usize = 56;
const PRINT_TITLE_PAD_TO_LEN: usize = 25;

pub(crate) fn tlv_get_string_value(tlvs: &HashMap<u16, &ber::Tlv>, tag: &u16) -> Option<String> {
    match tlvs.get(tag) {
        Some(data) => {
            let value_bytes = helpers::get_tlv_value_bytes(data);
            Some(String::from_utf8(value_bytes).unwrap())
        }
        None => None,
    }
}

pub(crate) fn tlv_get_bytes(tlvs: &HashMap<u16, &ber::Tlv>, tag: &u16) -> Option<Vec<u8>> {
    match tlvs.get(tag) {
        Some(data) => Some(helpers::get_tlv_value_bytes(data)),
        None => None,
    }
}

pub(crate) fn tlv_get_byte(tlvs: &HashMap<u16, &ber::Tlv>, tag: &u16) -> Option<u8> {
    match tlvs.get(tag) {
        Some(data) => Some(helpers::get_tlv_value_bytes(data)[0]),
        None => None,
    }
}

pub(crate) fn parse_biometric_info_template_group_template(
    biometric_info_template_group_template_tlv: &ber::Tlv,
) -> Vec<types::Biometric> {
    let mut biometrics: Vec<types::Biometric> = vec![];

    // 7F61 -> 02 (number of biometrics), 7F60 (template) -> A1 (header template), 5F2E (19794) / 7F2E (39794)
    // if 7F2E -> A1 -> 64 (finger)/65 (face)/66 (iris)

    let biometric_info_template_group_template_tlv_value =
        helpers::get_tlv_constructed_value(&biometric_info_template_group_template_tlv);
    let biometric_info_template_tlvs =
        helpers::get_tlvs_by_tag(&biometric_info_template_group_template_tlv_value, 0x7F60);
    debug!(
        "biometric_info_template_tlvs: {:02x?}",
        biometric_info_template_tlvs
    );
    for biometric_info_template in biometric_info_template_tlvs {
        let tlv_value = helpers::get_tlv_constructed_value(&biometric_info_template);
        let biometric_info_tlvs = helpers::sort_tlvs_by_tag(&tlv_value);
        // Here should be 0xA1 (header template), plus data: 0x5F2E (ISO/IEC 19794-5) or 0x7F2E (ISO/IEC 39794)
        let image_data: Vec<u8>;
        let mut image_format: types::BiometricImageFormat = types::BiometricImageFormat::Reserved;
        if biometric_info_tlvs.contains_key(&0x5F2E) {
            let iso_19794_data =
                helpers::get_tlv_value_bytes(biometric_info_tlvs.get(&0x5F2E).unwrap());
            // quick lazy implementation of ISO/IEC 19794
            // Only allow 2005 variant (this is what ICAO 9303 requires for first biometric)
            if iso_19794_data[4..8] != [0x30, 0x31, 0x30, 00] {
                warn!(
                    "Biometric has unsupported version, skipping: {:02x?}",
                    &iso_19794_data[4..8]
                );
                continue;
            }

            let number_of_representations =
                u16::from_be_bytes(iso_19794_data[12..14].try_into().unwrap());
            if number_of_representations != 1 {
                warn!("Expected one representation of biometric, but found {}. We can only dump the first one.", number_of_representations)
            }
            let rep_1_start = 14; // size of general header on ISO/IEC 19794-1:2006
            let rep_1_length = u32::from_be_bytes(
                iso_19794_data[rep_1_start..rep_1_start + 4]
                    .try_into()
                    .unwrap(),
            );
            let rep_1_feature_point_count = u16::from_be_bytes(
                iso_19794_data[rep_1_start + 4..rep_1_start + 6]
                    .try_into()
                    .unwrap(),
            );
            let rep_1_header_length: u16 = 20 + (8 * rep_1_feature_point_count) + 12;
            let rep_1_data = &iso_19794_data
                [rep_1_start + rep_1_header_length as usize..rep_1_start + rep_1_length as usize];
            let rep_1_image_format = iso_19794_data[36 + (8 * rep_1_feature_point_count as usize)];

            match types::BiometricImageFormat::from_repr(rep_1_image_format as usize) {
                Some(format) => {
                    image_format = format;
                }
                None => {}
            }
            // 36 + (8 * rep_1_feature_point_count)
            image_data = rep_1_data.to_vec();
        } else if biometric_info_tlvs.contains_key(&0x7F2E) {
            // ICAO 9303 requires ISO/IEC 19794 for first biometric so this is low-priority
            todo!();
        } else {
            warn!("Biometric info template does not contain data.");
            continue;
        }

        let biometric_header_template =
            helpers::get_tlv_constructed_value(biometric_info_tlvs.get(&0xA1).unwrap());
        let biometric_header_tlvs = helpers::sort_tlvs_by_tag(&biometric_header_template);

        let biometric = types::Biometric {
            header_version: tlv_get_bytes(&biometric_header_tlvs, &0x80),
            biometric_type: tlv_get_bytes(&biometric_header_tlvs, &0x81),
            biometric_sub_type: tlv_get_byte(&biometric_header_tlvs, &0x82),
            creation_timestamp: tlv_get_bytes(&biometric_header_tlvs, &0x83),
            validity_period_from_through: tlv_get_bytes(&biometric_header_tlvs, &0x85),
            creator_of_biometric_data: tlv_get_bytes(&biometric_header_tlvs, &0x86),
            format_owner: tlv_get_bytes(&biometric_header_tlvs, &0x87).unwrap(),
            format_type: tlv_get_bytes(&biometric_header_tlvs, &0x88).unwrap(),
            data: image_data.clone(),
            image_format: image_format,
        };
        biometrics.push(biometric);
    }
    return biometrics;
}

/// Remove the < characters at the end of the given string.
pub fn remove_mrz_padding(text: &String) -> String {
    let mut last_padding_index: usize = 0;
    for (index, character) in text.chars().rev().enumerate() {
        if character != '<' {
            // as the index is reversed, we set this to total_len - index
            last_padding_index = text.len() - index;
            break;
        }
    }
    return text[..last_padding_index].to_string();
}

/// Formats a name from an MRZ.
///
/// Returns (first_name, last_name).
/// If no last name is present, returns (full_name, empty).
pub fn format_mrz_name(text: &String) -> (String, String) {
    let name_with_spaces = text.replace("<", " ");
    // Last name is separated by <<.
    let last_name_index = text.find("<<");
    match last_name_index {
        Some(index) => {
            return (
                // + 2 here for the length of <<
                name_with_spaces[index + 2..].to_string(),
                name_with_spaces[0..index].to_string(),
            );
        }
        None => {
            return (name_with_spaces.to_string(), "".to_string());
        }
    }
}

/// Converts an UTF-8/ASCII text to its number representations.
///
/// All values in text must be in ASCII 0-9 range (48-57), else it returns None.
pub fn text_to_numeric(text: &String) -> Option<Vec<u8>> {
    let mut result_vec: Vec<u8> = vec![];
    for character in text.as_bytes() {
        match character {
            b'0'..=b'9' => {
                result_vec.push(character - b'0');
            }
            _ => {
                return None;
            }
        }
    }
    return Some(result_vec);
}

/// Parses a date from a DG. Must be in YYYYMMDD format.
///
/// Returns (DD, MM, YYYY) if it is in correct format, else None.
pub fn parse_dg_date(text: &String) -> Option<(u8, u8, u16)> {
    if text.len() != 8 {
        return None;
    }
    let date_numbers = text_to_numeric(text)?;
    return Some((
        date_numbers[6] * 10 + date_numbers[7],
        date_numbers[4] * 10 + date_numbers[5],
        (date_numbers[0] as u16 * 1000)
            + (date_numbers[1] as u16 * 100)
            + (date_numbers[2] as u16 * 10)
            + (date_numbers[3] as u16),
    ));
}

/// Parses a date from MRZ. Must be in YYMMDD format.
///
/// Returns (DD, MM, YYYY) if it is in correct format, else None.
pub fn parse_mrz_date(text: &String) -> Option<(u8, u8, u16)> {
    // If this is 40, then < 40 is assumed to be 2000s, and > 40 is assumed to be 1900s
    // This should account for expiry date, so current year + 10 is lowest safeish amount.
    const CENTURY_CUTOFF: u8 = 40;
    if text.len() != 6 {
        return None;
    }
    let date_numbers = text_to_numeric(text)?;
    let year_last_two_digits = (date_numbers[0] * 10) + date_numbers[1];
    let year: u16 = if year_last_two_digits < CENTURY_CUTOFF {
        2000 + year_last_two_digits as u16
    } else {
        1900 + year_last_two_digits as u16
    };
    return Some((
        date_numbers[4] * 10 + date_numbers[5],
        date_numbers[2] * 10 + date_numbers[3],
        year,
    ));
}

/// Formats a date. Must be in (DD, MM, YYYY) format.
///
/// Returns "DD.MM.YYYY (YYYY-MM-DD)".
pub fn format_date(dd: u8, mm: u8, yyyy: u16) -> String {
    return format!(
        "{dd:02}.{mm:02}.{yyyy:04} ({yyyy:04}-{mm:02}-{dd:02})",
        dd = dd,
        mm = mm,
        yyyy = yyyy
    );
}

pub(crate) fn print_section_intro(datagroup: &types::DataGroup) {
    info!("");
    info!("{}", pad_section_title(datagroup.name));
    info!("{}", pad_section_subtitle(datagroup.description));
    info!("");
}

/// Pads a section title with =s up to 56 characters.
pub(crate) fn pad_section_title(text: &str) -> String {
    let text_to_pad = format!(" <blue>{}</> ", text);
    // + 9 here to account for the color tags
    return format!(
        "<b>{:=^pad_len$}</>",
        text_to_pad,
        pad_len = SECTION_TITLE_PAD_TO_LEN + 9
    );
}

/// Pads a section subtitle with spaces up to 56 characters.
pub(crate) fn pad_section_subtitle(text: &str) -> String {
    let text_to_pad = format!("({})", text);
    return format!(
        "{:^pad_len$}",
        text_to_pad,
        pad_len = SECTION_TITLE_PAD_TO_LEN
    );
}

fn pad_with_ellipses(text: &str) -> String {
    // max here is to avoid overflowing
    let pad_len = max(PRINT_TITLE_PAD_TO_LEN, text.len()) - text.len();
    return format!("<b>{}</>{:.<pad_len$}", text, "");
}

pub(crate) fn parse_mrz_sex(sex: char) -> String {
    // https://www.youtube.com/watch?v=HNy_retSME0
    return match sex {
        'M' => "Male".to_string(),
        'F' => "Female".to_string(),
        '<' => "X".to_string(),
        _ => sex.to_string(),
    };
}

pub(crate) fn parse_mrz_document_code(document_code: &String, country_code: &String) -> String {
    // https://wf.lavatech.top/aves-tech-notes/emrtd-data-quirks see document type codes
    if document_code.len() != 2 {
        return document_code.to_string();
    }
    // ICAO 9303 part 5, edition 8, 4.2.2.3 Note k:
    // "The first character shall be A, C or I. Historically these three characters were chosen for their ease of
    // recognition in the OCR-B character set. The second character shall be at the discretion of the issuing State or
    // organization except that i) V shall not be used, ii) I shall not be used after A (i.e. AI), and iii) C shall not be used
    // after A (i.e. AC) except in the crew member certificate."

    match document_code.as_str() {
        "C<" => {
            if country_code == "ITA" {
                return "ID Card".to_string();
            }
        }
        "I<" => {
            return "ID Card".to_string();
        }
        "ID" => {
            if ["DNK", "BEL", "PLN"].contains(&country_code.as_str()) {
                return "ID or Residence Permit Card".to_string();
            }
            return "ID Card".to_string();
        }
        "IP" => {
            return "Passport Card".to_string();
        }
        "AD" | "AR" | "CR" | "IR" | "IT" | "RP" | "RT" => {
            return "Residence Permit Card".to_string();
        }
        "IB" | "IW" | "IK" | "IE" | "IO" | "IF" | "IZ" => {
            if country_code == "PLN" {
                return "Residence Permit Card".to_string();
            }
        }
        "AI" | "CV" | "AC" => {
            return format!("{} (Disallowed by ICAO 9303, Part 5)", document_code);
        }
        _ => {}
    }

    match document_code.chars().nth(0).unwrap() {
        'P' => {
            return "Passport".to_string();
        }
        'I' | 'C' => {
            return "ID Card (likely)".to_string();
        }
        'V' => {
            return format!("{} (Disallowed by ICAO 9303, Part 5)", document_code);
        }
        _ => {}
    }
    return format!(
        "Unknown document {} (please open an issue on https://github.com/aveao/passauf )",
        document_code
    );
}

#[cfg(feature = "cli")]
pub(crate) fn print_string_element(title: &str, value: &String) {
    info!("{} <yellow>{}</>", pad_with_ellipses(title), value.clone());
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element(title: &str, value: &Option<String>) {
    if value.is_none() {
        return;
    }
    info!(
        "{} <yellow>{}</>",
        pad_with_ellipses(title),
        value.clone().unwrap()
    );
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element_as_name(title: &str, value: &Option<String>) {
    if value.is_none() {
        return;
    }
    let text = value.clone().unwrap();
    let (first_name, last_name) = format_mrz_name(&text);
    info!(
        "{} <yellow>{} {}</>",
        pad_with_ellipses(title),
        &first_name,
        &last_name
    );
}

#[cfg(feature = "cli")]
pub(crate) fn print_string_element_as_name(title: &str, value: &String) {
    let (first_name, last_name) = format_mrz_name(value);
    info!(
        "{} <yellow>{} {}</>",
        pad_with_ellipses(title),
        &first_name,
        &last_name
    );
}

#[cfg(feature = "cli")]
pub(crate) fn print_string_element_as_mrz_date(title: &str, value: &String) {
    let (dd, mm, yyyy) = parse_mrz_date(&value).unwrap();
    let date_str = format_date(dd, mm, yyyy);
    info!("{} <yellow>{}</>", pad_with_ellipses(title), date_str);
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element_as_dg_date(title: &str, value: &Option<String>) {
    if value.is_none() {
        return;
    }
    let text = value.clone().unwrap();
    let (dd, mm, yyyy) = parse_dg_date(&text).unwrap();
    let date_str = format_date(dd, mm, yyyy);
    info!("{} <yellow>{}</>", pad_with_ellipses(title), date_str);
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_binary_element<T>(title: &str, value: &Option<T>)
where
    T: IntoIterator + Clone + std::fmt::Debug,
    T::IntoIter: ExactSizeIterator,
{
    // "baby's first generic"
    if value.is_none() {
        return;
    }
    // needing to clone sucks here, can we do better?
    let data = value.clone().unwrap();
    let data_iter = data.clone().into_iter();
    // magic number
    if data_iter.len() > 128 {
        info!(
            "{} <yellow>[Binary File of {} bytes]</>",
            pad_with_ellipses(title),
            data_iter.len()
        );
    } else {
        info!("{} <yellow>{:02x?}</>", pad_with_ellipses(title), data);
    }
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_debug_element<T>(title: &str, value: &Option<T>)
where
    T: std::fmt::Debug + Clone,
{
    // "baby's second generic"
    if value.is_none() {
        return;
    }
    info!(
        "{} <yellow>{:02x?}</>",
        pad_with_ellipses(title),
        value.clone().unwrap()
    );
}
