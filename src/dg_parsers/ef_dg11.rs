use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info};

impl types::EFDG11 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        dg_helpers::print_section_intro(data_group);
        dg_helpers::print_option_string_element_as_name("Full name of holder", &self.full_name);
        dg_helpers::print_option_debug_element("Other names", &self.other_names);
        dg_helpers::print_option_string_element("Personal number", &self.personal_number);
        dg_helpers::print_option_string_element_as_dg_date(
            "Full date of birth",
            &self.full_date_of_birth,
        );
        dg_helpers::print_option_string_element("Place of birth", &self.place_of_birth);
        dg_helpers::print_option_string_element("Permanent address", &self.permanent_address);
        dg_helpers::print_option_string_element("Telephone", &self.telephone);
        dg_helpers::print_option_string_element("Profession", &self.profession);
        dg_helpers::print_option_string_element("Title", &self.title);
        dg_helpers::print_option_string_element("Personal summary", &self.personal_summary);
        dg_helpers::print_option_binary_element("Proof of citizenship", &self.proof_of_citizenship);
        dg_helpers::print_option_string_element(
            "Other valid travel document numbers",
            &self.other_valid_td_numbers,
        );
        dg_helpers::print_option_string_element("Custody information", &self.custody_information);
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
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x6B);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    let result = types::EFDG11 {
        full_name: dg_helpers::tlv_get_string_value(&tlvs, &0x5F0E),
        other_names: None, // TODO: impl this
        personal_number: dg_helpers::tlv_get_string_value(&tlvs, &0x5F10),
        full_date_of_birth: dg_helpers::tlv_get_string_value(&tlvs, &0x5F2B),
        place_of_birth: dg_helpers::tlv_get_string_value(&tlvs, &0x5F11),
        permanent_address: dg_helpers::tlv_get_string_value(&tlvs, &0x5F42),
        telephone: dg_helpers::tlv_get_string_value(&tlvs, &0x5F12),
        profession: dg_helpers::tlv_get_string_value(&tlvs, &0x5F13),
        title: dg_helpers::tlv_get_string_value(&tlvs, &0x5F14),
        personal_summary: dg_helpers::tlv_get_string_value(&tlvs, &0x5F15),
        proof_of_citizenship: dg_helpers::tlv_get_bytes(&tlvs, &0x5F16),
        other_valid_td_numbers: dg_helpers::tlv_get_string_value(&tlvs, &0x5F17),
        custody_information: dg_helpers::tlv_get_string_value(&tlvs, &0x5F18),
    };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG11(result));
}
