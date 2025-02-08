use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info};

impl types::EFDG1 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        info!("");
        // TODO: smth for easier dashes
        info!("------------------------ <blue>EF_DG1</> ------------------------");
        info!("({})", data_group.description);
        dg_helpers::print_string_element("MRZ", &self.raw_mrz);
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
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x61);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    // TODO: parse DG1 further
    let result = types::EFDG1 {
        raw_mrz: dg_helpers::tlv_get_string_value(&tlvs, &0x5F1F)
            .expect("MRZ field (0x5F1F) not in DG1"),
    };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG1(result));
}
