use crate::dg_parsers::generic::dumper as generic_dumper;
use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::{fs, io, path::Path};

impl types::EFDG2 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        dg_helpers::print_section_intro(data_group);
        for (i, biometric) in self.biometrics.iter().enumerate() {
            info!("<b><u>Biometric #{}</>", i);

            dg_helpers::print_option_binary_element("Header version", &biometric.header_version);
            dg_helpers::print_option_binary_element("Biometric type", &biometric.biometric_type);
            dg_helpers::print_option_debug_element(
                "Biometric subtype",
                &biometric.biometric_sub_type,
            );
            dg_helpers::print_option_binary_element(
                "Creation timestamp",
                &biometric.creation_timestamp,
            );
            dg_helpers::print_option_binary_element(
                "Validity period",
                &biometric.validity_period_from_through,
            );
            dg_helpers::print_option_binary_element(
                "Creator of biometric data",
                &biometric.creator_of_biometric_data,
            );
            dg_helpers::print_option_binary_element("Format owner", &Some(&biometric.format_owner));
            dg_helpers::print_option_binary_element("Format type", &Some(&biometric.format_type));
            dg_helpers::print_string_element(
                "Image format",
                &biometric.image_format.get_extension(),
            );
            dg_helpers::print_option_binary_element("Image Data", &Some(&biometric.data));
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
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
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
        let image_filename = format!("{}-pic{}", base_filename, i + 1);
        let mut file_path = base_path.join(image_filename);
        file_path.set_extension(biometric.image_format.get_extension());

        // Create, write to and sync file.
        let mut f = fs::File::create(&file_path)?;
        io::Write::write_all(&mut f, &biometric.data)?;
        f.sync_all()?;

        info!(
            "<magenta>Saved image to {}</>",
            &file_path.to_string_lossy()
        );
    }
    return Ok(());
}
