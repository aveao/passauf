use iso7816_tlv::ber;
use simplelog::info;
use std::collections::HashMap;

use crate::helpers;

const SECTION_TITLE_PAD_TO_LEN: usize = 56;
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

pub(crate) fn print_section_intro(filename: &str, subtitle: &str) {
    info!("");
    info!("{}", pad_section_title(filename));
    info!("{}", pad_section_subtitle(subtitle));
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
    let pad_len = PRINT_TITLE_PAD_TO_LEN - text.len();
    return format!("<b>{}</>{:.<pad_len$}", text, "");
}

#[cfg(feature = "cli")]
pub(crate) fn print_string_element(title: &str, value: &String) {
    info!("{} <yellow>{}</>", pad_with_ellipses(title), value.clone());
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element(title: &str, value: &Option<String>) {
    if *value == None {
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
    if *value == None {
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
pub(crate) fn print_option_string_element_as_date(title: &str, value: &Option<String>) {
    if *value == None {
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
    T: IntoIterator + PartialEq + Clone + std::fmt::Debug,
    T::IntoIter: ExactSizeIterator,
{
    // "baby's first generic"
    if *value == None {
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
    T: std::fmt::Debug + Clone + PartialEq,
{
    // "baby's second generic"
    if *value == None {
        return;
    }
    info!(
        "{} <yellow>{:02x?}</>",
        pad_with_ellipses(title),
        value.clone().unwrap()
    );
}
