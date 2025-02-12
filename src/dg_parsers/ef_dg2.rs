use crate::dg_parsers::generic::dumper as generic_dumper;
use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::warn;
use simplelog::{debug, info};
use std::{fs, io, path::Path};

pub fn parser(
    data: &Vec<u8>,
    _data_group: &icao9303::DataGroup,
    _print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x75);
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let biometric_info_template_group_template_tlv =
        helpers::get_tlv_by_tag(&base_tlv_value, 0x7F61)?;
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

pub fn dumper(
    file_data: &Vec<u8>,
    parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<(), io::Error> {
    generic_dumper(file_data, parsed_data, base_path, &base_filename)?;

    if parsed_data.is_none() {
        warn!("Could not dump EF_DG2 pictures, parsed data is empty.");
        return Ok(());
    }

    let ef_dg2_file: &types::EFDG2 = match parsed_data.as_ref().unwrap() {
        types::ParsedDataGroup::EFDG2(file) => file,
        _ => {
            panic!("Expected EFDG2 but got {:x?}", parsed_data);
        }
    };

    // Dump all biometrics
    for (i, biometric) in ef_dg2_file.biometrics.iter().enumerate() {
        let image_filename = format!("{}-pic_{}", base_filename, i + 1);
        let mut file_path = base_path.join(image_filename);
        file_path.set_extension(biometric.image_format.get_extension());

        // Create, write to and sync file.
        let mut f = fs::File::create(&file_path)?;
        io::Write::write_all(&mut f, &biometric.data)?;
        f.sync_all()?;

        info!("<magenta>Saved image to {}</>", &file_path.to_string_lossy());
    }
    return Ok(());
}
