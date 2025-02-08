use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info};

impl types::EFDG12 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        info!("");
        // TODO: smth for easier dashes
        info!("------------------------ <blue>EF_DG12</> -----------------------");
        info!("({})", data_group.description);
        dg_helpers::print_option_string_element("Issuing Authority", &self.issuing_authority);
        dg_helpers::print_option_string_element_as_date("Date of issue", &self.date_of_issue);
        dg_helpers::print_option_debug_element("Other persons", &self.other_persons);
        dg_helpers::print_option_string_element(
            "Endorsements/Observations",
            &self.endorsements_observations,
        );
        dg_helpers::print_option_string_element(
            "Tax/Exit Requirements",
            &self.tax_exit_requirements,
        );
        dg_helpers::print_option_binary_element(
            "Image of front of eMRTD",
            &self.image_of_front_of_emrtd,
        );
        dg_helpers::print_option_binary_element(
            "Image of rear of eMRTD",
            &self.image_of_rear_of_emrtd,
        );
        dg_helpers::print_option_string_element(
            "Personalization Timestamp",
            &self.personalization_timestamp,
        );
        dg_helpers::print_option_string_element(
            "Personalization Device Serial Number",
            &self.personalization_device_serial_number,
        );
        info!("");
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
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x6C);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    let result = types::EFDG12 {
        issuing_authority: dg_helpers::tlv_get_string_value(&tlvs, &0x5F19),
        date_of_issue: dg_helpers::tlv_get_string_value(&tlvs, &0x5F26),
        endorsements_observations: dg_helpers::tlv_get_string_value(&tlvs, &0x5F1B),
        tax_exit_requirements: dg_helpers::tlv_get_string_value(&tlvs, &0x5F1C),
        personalization_timestamp: dg_helpers::tlv_get_string_value(&tlvs, &0x5F55),
        personalization_device_serial_number: dg_helpers::tlv_get_string_value(&tlvs, &0x5F56),
        image_of_front_of_emrtd: dg_helpers::tlv_get_bytes(&tlvs, &0x5F1D),
        image_of_rear_of_emrtd: dg_helpers::tlv_get_bytes(&tlvs, &0x5F1D),
        other_persons: None, // TODO: impl this
    };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG12(result));
}
