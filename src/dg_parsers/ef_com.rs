use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info};

impl types::EFCom {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        // TODO: smth for easier dashes
        info!("------------------------ <blue>EF_COM</> ------------------------");
        info!("({})", data_group.description);
        dg_helpers::print_option_binary_element("LDS Version", &self.lds_version);
        dg_helpers::print_option_string_element("Unicode Version", &self.unicode_version);
        info!("<b><u>Files on this document</b>:</u>");

        // TODO: sorting would be nice, somehow.
        for (_, (dg_name, dg_info)) in icao9303::DATA_GROUPS.entries.iter().enumerate() {
            if self.data_group_tag_list.contains(&dg_info.tag) {
                // TODO: smth for easier dots
                info!("<b>{}</b>: <yellow>{}</>", dg_name, dg_info.description);
            }
        }
    }
}

pub fn parser(
    data: Vec<u8>,
    data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    debug!("Read file ({:?}b): {:x?}", data.len(), data);

    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(&data).0.unwrap();
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x60);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    let result = types::EFCom {
        lds_version: match tlvs.get(&0x5F01) {
            Some(data) => {
                let value_bytes = helpers::get_tlv_value_bytes(data);
                assert!(value_bytes.len() == 4);
                Some(value_bytes.try_into().unwrap())
            }
            None => None,
        },
        unicode_version: match tlvs.get(&0x5F36) {
            Some(data) => {
                let mut value_bytes = helpers::get_tlv_value_bytes(data);
                assert!(value_bytes.len() == 6);
                // Add dots to the unicode version string.
                value_bytes.insert(4, b'.');
                value_bytes.insert(2, b'.');
                Some(String::from_utf8(value_bytes).unwrap())
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
