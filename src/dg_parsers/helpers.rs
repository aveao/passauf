use iso7816_tlv::ber;
use simplelog::info;
use std::collections::HashMap;

use crate::helpers;

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

#[cfg(feature = "cli")]
pub(crate) fn print_string_element(name: &str, value: &String) {
    // TODO: ellipses
    info!("<b>{}</b>: {}", name, value.clone());
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element(name: &str, value: &Option<String>) {
    if *value == None {
        return;
    }
    // TODO: ellipses
    info!("<b>{}</b>: {}", name, value.clone().unwrap());
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

#[cfg(feature = "cli")]
pub(crate) fn print_option_string_element_as_name(title: &str, value: &Option<String>) {
    if *value == None {
        return;
    }
    let text = value.clone().unwrap();
    let (first_name, last_name) = format_mrz_name(&text);
    // TODO: ellipses
    info!("<b>{}</b>: {} {}", title, &first_name, &last_name);
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_binary_element<T>(name: &str, value: &Option<T>)
where
    T: IntoIterator + PartialEq + Clone + std::fmt::Debug,
    T::IntoIter: ExactSizeIterator,
{
    // "baby's first generic"
    if *value == None {
        return;
    }
    // TODO: ellipses
    // needing to clone sucks here, can we do better?
    let data = value.clone().unwrap();
    let data_iter = data.clone().into_iter();
    // magic number
    if data_iter.len() > 128 {
        info!(
            "<b>{}</b>: [Binary File of {} bytes]",
            name,
            data_iter.len()
        );
    } else {
        info!("<b>{}</b>: {:02x?}", name, data);
    }
}

#[cfg(feature = "cli")]
pub(crate) fn print_option_debug_element<T>(name: &str, value: &Option<T>)
where
    T: std::fmt::Debug + Clone + PartialEq,
{
    // "baby's second generic"
    if *value == None {
        return;
    }
    // TODO: ellipses
    info!("<b>{}</b>: {:02x?}", name, value.clone().unwrap());
}
