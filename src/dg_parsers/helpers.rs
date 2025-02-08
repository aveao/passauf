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
