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
        if self.lds_version != None {
            info!("<b>LDS Version</b>: {:02x?}", &self.lds_version.unwrap())
        };
        if self.unicode_version != None {
            info!(
                "<b>Unicode Version</b>: {}",
                &self.unicode_version.clone().unwrap()
            )
        };
        info!("<b><u>Files on this document</b>:</u>");

        // TODO: sorting would be nice, somehow.
        for (_, (dg_name, dg_info)) in icao9303::DATA_GROUPS.entries.iter().enumerate() {
            if self.data_group_tag_list.contains(&dg_info.tag) {
                // TODO: smth for easier dots
                info!("<b>{}</b>: <yellow>{}</>", dg_name, dg_info.description)
            }
        }
    }
}

pub fn parser(
    data: Vec<u8>,
    data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    debug!("Read EF.COM ({:?}b): {:x?}", data.len(), data);

    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(&data).0.unwrap();
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x60);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the EFCom file from the given TLV data.
    let efcom_file = types::EFCom {
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
        data_group_tag_list: helpers::get_tlv_value_bytes(tlvs.get(&0x5C).unwrap()),
    };
    if print_data {
        #[cfg(feature = "cli")]
        efcom_file.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFCom(efcom_file));
}
