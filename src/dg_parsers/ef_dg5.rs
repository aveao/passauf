use crate::dg_parsers::generic::dumper as generic_dumper;
use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::{fs, io, path::Path};

impl types::EFDG5 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        dg_helpers::print_section_intro(data_group);
        for (i, displayed_portrait) in self.displayed_portraits.iter().enumerate() {
            dg_helpers::print_option_binary_element(
                &format!("Displayed portrait (#{})", i + 1),
                &Some(displayed_portrait),
            );
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

    // Get the TLVs stored inside the base tag
    let tlvs = helpers::get_tlv_constructed_value(&base_tlv);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data and parse the pictures out
    let mut displayed_portraits: Vec<Vec<u8>> = vec![];
    for displayed_portrait_tlv in helpers::get_tlvs_by_tag(&tlvs, 0x5F40).iter() {
        displayed_portraits.push(helpers::get_tlv_value_bytes(&displayed_portrait_tlv));
    }
    let result = types::EFDG5 {
        displayed_portraits: displayed_portraits,
    };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG5(result));
}

pub fn dumper(
    file_data: &Vec<u8>,
    parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<(), io::Error> {
    generic_dumper(file_data, parsed_data, base_path, &base_filename)?;

    if parsed_data.is_none() {
        warn!("Could not dump EF_DG5 pictures, parsed data is empty.");
        return Ok(());
    }

    let ef_dg5_file: &types::EFDG5 = match parsed_data.as_ref().unwrap() {
        types::ParsedDataGroup::EFDG5(file) => file,
        _ => {
            panic!("Expected EFDG5 but got {:x?}", parsed_data);
        }
    };

    // Dump all pictures
    for (i, picture_data) in ef_dg5_file.displayed_portraits.iter().enumerate() {
        let image_filename = format!("{}-pic{}", base_filename, i + 1);
        let mut file_path = base_path.join(image_filename);
        file_path.set_extension("jpeg");

        // Create, write to and sync file.
        let mut f = fs::File::create(&file_path)?;
        io::Write::write_all(&mut f, &picture_data)?;
        f.sync_all()?;

        info!(
            "<magenta>Saved image to {}</>",
            &file_path.to_string_lossy()
        );
    }
    return Ok(());
}
