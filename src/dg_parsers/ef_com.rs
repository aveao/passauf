use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::warn;
use simplelog::{debug, info};

impl types::EFCom {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        dg_helpers::print_section_intro(data_group);
        dg_helpers::print_option_binary_element("LDS Version", &self.lds_version);
        dg_helpers::print_option_string_element("Unicode Version", &self.unicode_version);
        info!("");
        info!(
            "{:^pad_len$}",
            "<b><u>Files on this document</>",
            pad_len = 56
        );

        for dg_info in icao9303::DATA_GROUPS.iter() {
            if self.data_group_tag_list.contains(&dg_info.tag) {
                info!(
                    "{:>pad_len$} <yellow>{}</>",
                    dg_info.name,
                    dg_info.description,
                    pad_len = 15
                );
            }
        }
        info!("");
    }
}

pub fn parser(
    data: &Vec<u8>,
    data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_tag = helpers::get_tlv_tag(&base_tlv);
    if base_tlv_tag != data_group.tag.into() {
        warn!(
            "Found {}'s TLV tag as 0x{} (expected 0x{}), skipping parsing.",
            data_group.name, base_tlv_tag, data_group.tag
        );
        return None;
    };

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    let result = types::EFCom {
        lds_version: match tlvs.get(&0x5F01) {
            Some(data) => {
                let value_bytes = helpers::get_tlv_value_bytes(data);
                if value_bytes.len() != 4 {
                    None
                } else {
                    Some(value_bytes.try_into().unwrap())
                }
            }
            None => None,
        },
        unicode_version: match tlvs.get(&0x5F36) {
            Some(data) => {
                let mut value_bytes = helpers::get_tlv_value_bytes(data);
                if value_bytes.len() != 6 {
                    None
                } else {
                    // Add dots to the unicode version string.
                    value_bytes.insert(4, b'.');
                    value_bytes.insert(2, b'.');
                    Some(String::from_utf8(value_bytes).unwrap())
                }
            }
            None => None,
        },
        data_group_tag_list: dg_helpers::tlv_get_bytes(&tlvs, &0x5C)
            .expect("EF.COM does not have a tag list."),
    };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFCom(result));
}
