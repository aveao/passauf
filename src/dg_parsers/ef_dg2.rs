use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::debug;

pub fn parser(
    data: Vec<u8>,
    _data_group: &icao9303::DataGroup,
    _print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(&data).0.unwrap();
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x75);
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let biometric_info_template_group_template_tlv =
        helpers::get_tlv_by_tag(&base_tlv_value, 0x7F61).unwrap();
    let biometrics = dg_helpers::parse_biometric_info_template_group_template(
        biometric_info_template_group_template_tlv,
    );

    // Deserialize the file from the given TLV data.
    let result = types::EFDG2 {
        biometrics: biometrics,
    };
    // if print_data {
    //     #[cfg(feature = "cli")]
    //     result.fancy_print(data_group);
    // }
    return Some(types::ParsedDataGroup::EFDG2(result));
}
