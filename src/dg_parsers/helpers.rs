use iso7816_tlv::ber;
#[cfg(feature = "cli")]
use simplelog::info;
use simplelog::{debug, warn};
#[cfg(feature = "cli")]
use std::cmp::max;
use std::collections::HashMap;

use crate::{helpers, types};

#[cfg(feature = "cli")]
pub(crate) const SECTION_TITLE_PAD_TO_LEN: usize = 56;
#[cfg(feature = "cli")]
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
        let image_format: types::BiometricImageFormat;
        if biometric_info_tlvs.contains_key(&0x5F2E) {
            let iso_19794_data =
                helpers::get_tlv_value_bytes(biometric_info_tlvs.get(&0x5F2E).unwrap());
            let (data, declared) = match parse_iso_19794_5(&iso_19794_data) {
                Some(parsed) => parsed,
                None => continue,
            };
            // What the record says and what the bytes are can disagree, and
            // the bytes are what any decoder acts on.
            image_format = resolve_image_format(declared, &data);
            image_data = data;
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

/// Field sizes in an ISO/IEC 19794-5:2005 face record, in bytes.
///
/// The record is a Facial Record Header, then one representation per image.
/// Each representation is a Facial Information block, then a Feature Point
/// block per feature point, then an Image Information block, then the image.
const FACIAL_RECORD_HEADER_LEN: usize = 14;
const FACIAL_INFORMATION_LEN: usize = 20;
const FEATURE_POINT_LEN: usize = 8;
const IMAGE_INFORMATION_LEN: usize = 12;
/// Where the image data type sits inside the Image Information block: after
/// the face image type, and *before* the width. Reading one byte further
/// along gives the high byte of the width instead, which for any image 512 or
/// more pixels wide is not a format anyone has heard of.
const IMAGE_DATA_TYPE_OFFSET: usize = 1;

/// Pull the first image and its declared format out of a face record.
///
/// Only the 2005 variant of ISO/IEC 19794-5, which is what ICAO 9303 requires
/// for the first biometric. Returns None for anything malformed: a data group
/// read off a card that left the field mid-transfer is truncated, and this
/// would otherwise index past the end of it.
fn parse_iso_19794_5(data: &[u8]) -> Option<(Vec<u8>, Option<types::BiometricImageFormat>)> {
    if data.len() < FACIAL_RECORD_HEADER_LEN {
        warn!(
            "Biometric is {} bytes, too short to hold a face record header.",
            data.len()
        );
        return None;
    }
    if data[4..8] != [0x30, 0x31, 0x30, 0x00] {
        warn!(
            "Biometric has unsupported version, skipping: {:02x?}",
            &data[4..8]
        );
        return None;
    }

    let number_of_representations = u16::from_be_bytes(data[12..14].try_into().ok()?);
    if number_of_representations != 1 {
        warn!(
            "Expected one representation of biometric, but found {}. We can only dump the \
             first one.",
            number_of_representations
        );
    }

    let representation = FACIAL_RECORD_HEADER_LEN;
    if data.len() < representation + FACIAL_INFORMATION_LEN {
        warn!("Biometric ends before its facial information block.");
        return None;
    }
    let representation_len =
        u32::from_be_bytes(data[representation..representation + 4].try_into().ok()?) as usize;
    let feature_points = u16::from_be_bytes(
        data[representation + 4..representation + 6]
            .try_into()
            .ok()?,
    ) as usize;

    let image_information =
        representation + FACIAL_INFORMATION_LEN + (feature_points * FEATURE_POINT_LEN);
    let image_start = image_information + IMAGE_INFORMATION_LEN;
    let image_end = representation + representation_len;
    if image_start > image_end || image_end > data.len() {
        warn!(
            "Biometric says its image runs to byte {}, but it is only {} bytes long.",
            image_end,
            data.len()
        );
        return None;
    }

    let declared = data
        .get(image_information + IMAGE_DATA_TYPE_OFFSET)
        .and_then(|byte| types::BiometricImageFormat::from_repr(*byte as usize));

    return Some((data[image_start..image_end].to_vec(), declared));
}

/// Settle on an image's format from what the record declares and what the
/// bytes actually are.
///
/// The bytes win. A face record states its format in one byte in the middle of
/// a header, and getting that byte wrong names the dumped file something no
/// viewer will open, whereas the leading bytes of a JPEG or JPEG 2000 are
/// unambiguous and are what a decoder acts on regardless.
fn resolve_image_format(
    declared: Option<types::BiometricImageFormat>,
    data: &[u8],
) -> types::BiometricImageFormat {
    let sniffed = if crate::images::looks_like_jpeg2000(data) {
        Some(types::BiometricImageFormat::Jpeg2000)
    } else if crate::images::looks_like_jpeg(data) {
        Some(types::BiometricImageFormat::Jpeg)
    } else {
        None
    };

    return match (sniffed, declared) {
        (Some(sniffed), Some(declared)) if sniffed != declared => {
            debug!(
                "Biometric declares itself {:?} but its bytes are {:?}. Going with the bytes.",
                declared, sniffed
            );
            sniffed
        }
        (Some(sniffed), _) => sniffed,
        // Not something we recognize, so the record's word is all there is.
        (None, Some(declared)) => declared,
        (None, None) => types::BiometricImageFormat::Reserved,
    };
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

#[cfg(feature = "cli")]
pub(crate) fn print_section_intro(datagroup: &types::DataGroup) {
    info!("");
    info!("{}", pad_section_title(datagroup.name));
    info!("{}", pad_section_subtitle(datagroup.description));
    info!("");
}

#[cfg(feature = "cli")]
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

#[cfg(feature = "cli")]
/// Pads a section subtitle with spaces up to 56 characters.
pub(crate) fn pad_section_subtitle(text: &str) -> String {
    let text_to_pad = format!("({})", text);
    return format!(
        "{:^pad_len$}",
        text_to_pad,
        pad_len = SECTION_TITLE_PAD_TO_LEN
    );
}

#[cfg(feature = "cli")]
fn pad_with_ellipses(text: &str) -> String {
    // max here is to avoid overflowing
    let pad_len = max(PRINT_TITLE_PAD_TO_LEN, text.len()) - text.len();
    return format!("<b>{}</>{:.<pad_len$}", text, "");
}

pub fn parse_mrz_sex(sex: char) -> String {
    // https://www.youtube.com/watch?v=HNy_retSME0
    return match sex {
        'M' => "Male".to_string(),
        'F' => "Female".to_string(),
        // ICAO gives the filler for "unspecified", and issuers that print a marker for
        // it print X. The two are not distinguishable here and do not always mean the
        // same thing, so neither reading is asserted over the other.
        'X' | '<' => "X (or unspecified)".to_string(),
        _ => sex.to_string(),
    };
}

pub fn parse_mrz_document_code(document_code: &String, country_code: &String) -> String {
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
            if ["DNK", "BEL", "POL"].contains(&country_code.as_str()) {
                return "ID or Residence Permit Card".to_string();
            }
            return "ID Card".to_string();
        }
        "IP" => {
            return "Passport Card".to_string();
        }
        "PT" => {
            if country_code == "D" {
                return "Travel Document".to_string();
            }
        }
        "AD" | "AR" | "CR" | "IR" | "IT" | "RP" | "RT" => {
            return "Residence Permit Card".to_string();
        }
        "IB" | "IW" | "IK" | "IE" | "IO" | "IF" | "IZ" => {
            if country_code == "POL" {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Germany writes its issuing state as one letter where the field holds three, and
    /// the caller strips the filler before this sees it, so the code to match is "D".
    #[test]
    fn a_german_pt_is_a_travel_document() {
        assert_eq!(
            parse_mrz_document_code(&"PT".to_string(), &"D".to_string()),
            "Travel Document"
        );
        assert_eq!(
            parse_mrz_document_code(&"P<".to_string(), &"D".to_string()),
            "Passport"
        );
        assert_eq!(
            parse_mrz_document_code(&"PT".to_string(), &"UTO".to_string()),
            "Passport"
        );
    }

    /// A marker of X and an unfilled field arrive as different characters and mean
    /// different things, but neither can be told apart from the other here.
    #[test]
    fn an_unfilled_sex_field_reads_the_same_as_an_x() {
        assert_eq!(parse_mrz_sex('M'), "Male");
        assert_eq!(parse_mrz_sex('F'), "Female");
        assert_eq!(parse_mrz_sex('<'), "X (or unspecified)");
        assert_eq!(parse_mrz_sex('X'), "X (or unspecified)");
    }

    /// Poland is POL. PLN is the currency, and while it was in here these two branches
    /// could not be reached by any document.
    #[test]
    fn polish_codes_use_the_country_not_the_currency() {
        assert_eq!(
            parse_mrz_document_code(&"ID".to_string(), &"POL".to_string()),
            "ID or Residence Permit Card"
        );
        assert_eq!(
            parse_mrz_document_code(&"IB".to_string(), &"POL".to_string()),
            "Residence Permit Card"
        );
        // Elsewhere the same codes mean what they meant before.
        assert_eq!(
            parse_mrz_document_code(&"ID".to_string(), &"UTO".to_string()),
            "ID Card"
        );
        assert_eq!(
            parse_mrz_document_code(&"IB".to_string(), &"UTO".to_string()),
            "ID Card (likely)"
        );
    }

    /// Build the ISO/IEC 19794-5:2005 face record around some image bytes.
    ///
    /// `width` matters: the byte after the image data type is the high half of
    /// it, and reading that one instead is exactly the mistake this guards.
    fn face_record(image: &[u8], declared_type: u8, width: u16, feature_points: u16) -> Vec<u8> {
        let mut representation: Vec<u8> = vec![];
        // Facial Information: length and feature point count, then fields we
        // do not read.
        representation.extend_from_slice(&[0u8; 4]); // length, filled in below
        representation.extend_from_slice(&feature_points.to_be_bytes());
        representation.extend_from_slice(&[0u8; 14]);
        // One Feature Point block each.
        representation.extend(std::iter::repeat(0u8).take(usize::from(feature_points) * 8));
        // Image Information: face image type, image data type, width, height,
        // then colour space, source, device and quality.
        representation.push(0x01);
        representation.push(declared_type);
        representation.extend_from_slice(&width.to_be_bytes());
        representation.extend_from_slice(&800u16.to_be_bytes());
        representation.extend_from_slice(&[0u8; 6]);
        representation.extend_from_slice(image);

        let length = (representation.len() as u32).to_be_bytes();
        representation[0..4].copy_from_slice(&length);

        let mut record: Vec<u8> = b"FAC\0010\0".to_vec();
        record.extend_from_slice(&((14 + representation.len()) as u32).to_be_bytes());
        record.extend_from_slice(&1u16.to_be_bytes());
        record.extend_from_slice(&representation);
        return record;
    }

    const JP2: &[u8] = include_bytes!("../../tests/fixtures/gradient.jp2");

    /// A face image 512 or more pixels wide put the high byte of the width
    /// where the image data type belongs, so a perfectly ordinary JPEG 2000
    /// portrait came out as "reserved" and was dumped as .image_bin.
    #[test]
    fn a_wide_image_does_not_confuse_the_format() {
        // 622 pixels wide, as one real document is: the high byte is 0x02,
        // which read as a format means "reserved".
        let record = face_record(JP2, 0x01, 622, 0);
        let (data, declared) = parse_iso_19794_5(&record).unwrap();

        assert_eq!(declared, Some(types::BiometricImageFormat::Jpeg2000));
        assert_eq!(data, JP2);
        assert_eq!(
            resolve_image_format(declared, &data),
            types::BiometricImageFormat::Jpeg2000
        );
    }

    /// Feature points shift everything after them along, so the offset has to
    /// move with them.
    #[test]
    fn finds_the_format_past_the_feature_points() {
        let record = face_record(JP2, 0x01, 622, 5);
        let (data, declared) = parse_iso_19794_5(&record).unwrap();
        assert_eq!(declared, Some(types::BiometricImageFormat::Jpeg2000));
        assert_eq!(data, JP2);
    }

    /// When the record and the bytes disagree, the bytes decide: they are what
    /// a decoder will act on, and the name the file gets has to match.
    #[test]
    fn the_bytes_outrank_the_declaration() {
        // Declared JPEG, actually JPEG 2000.
        assert_eq!(
            resolve_image_format(Some(types::BiometricImageFormat::Jpeg), JP2),
            types::BiometricImageFormat::Jpeg2000
        );
        // Declared reserved, actually a JPEG.
        assert_eq!(
            resolve_image_format(
                Some(types::BiometricImageFormat::Reserved),
                &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]
            ),
            types::BiometricImageFormat::Jpeg
        );
        // Nothing recognizable, so the record's word is all there is.
        assert_eq!(
            resolve_image_format(Some(types::BiometricImageFormat::Jpeg), b"something else"),
            types::BiometricImageFormat::Jpeg
        );
        assert_eq!(
            resolve_image_format(None, b"something else"),
            types::BiometricImageFormat::Reserved
        );
    }

    /// A card pulled out of the field mid-read leaves a truncated data group,
    /// which used to index off the end of the buffer.
    #[test]
    fn a_truncated_record_is_refused_rather_than_panicking() {
        let record = face_record(JP2, 0x01, 622, 0);
        for length in [0, 1, 8, 13, 14, 20, 34, 45, record.len() / 2] {
            assert_eq!(parse_iso_19794_5(&record[..length]), None, "at {}", length);
        }
        // A record claiming more than it carries.
        let mut lying = face_record(JP2, 0x01, 622, 0);
        lying[14..18].copy_from_slice(&0xFFFF_u32.to_be_bytes());
        assert_eq!(parse_iso_19794_5(&lying), None);
        // Feature points that run past the end.
        let overrun = face_record(JP2, 0x01, 622, 0xFFFF);
        assert_eq!(parse_iso_19794_5(&overrun[..60]), None);
    }
}
