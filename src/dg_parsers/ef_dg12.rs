use crate::dg_parsers::generic::dumper as generic_dumper;
use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::{
    io,
    path::{Path, PathBuf},
};

impl types::EFDG12 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);
        dg_helpers::print_option_string_element("Issuing Authority", &self.issuing_authority);
        dg_helpers::print_option_string_element_as_dg_date("Date of issue", &self.date_of_issue);
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
    data: &Vec<u8>,
    data_group: &types::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_tag = helpers::get_tlv_tag(&base_tlv);
    if base_tlv_tag != u16::from(data_group.tag) {
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

/// Write the file out, plus any image it carries.
///
/// DG12 can carry scans of the document itself, front and back.
pub fn dumper(
    file_data: &Vec<u8>,
    parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<Vec<PathBuf>, io::Error> {
    let mut written = generic_dumper(file_data, parsed_data, base_path, &base_filename)?;

    let parsed = match parsed_data {
        Some(types::ParsedDataGroup::EFDG12(parsed)) => parsed,
        // Nothing parsed, so there is nothing to pull an image out of.
        _ => return Ok(written),
    };

    for (name, image) in [
        ("front", &parsed.image_of_front_of_emrtd),
        ("rear", &parsed.image_of_rear_of_emrtd),
    ] {
        let image = match image {
            Some(image) => image,
            None => continue,
        };
        let mut file_path = base_path.join(format!("{}-{}", base_filename, name));
        // ICAO 9303 p10 has these as JPEG.
        file_path.set_extension("jpeg");

        crate::dg_parsers::generic::write_file(&file_path, image)?;

        info!(
            "<magenta>Saved image to {}</>",
            &file_path.to_string_lossy()
        );
        written.push(file_path);
    }
    return Ok(written);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The images DG12 carries have to reach disk and be reported, or the app
    /// shows a byte count for a picture it cannot display.
    #[test]
    fn writes_out_the_document_scans() {
        let directory = std::env::temp_dir().join(format!(
            "passauf-dg12-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();

        let parsed = Some(types::ParsedDataGroup::EFDG12(types::EFDG12 {
            issuing_authority: None,
            date_of_issue: None,
            other_persons: None,
            endorsements_observations: None,
            tax_exit_requirements: None,
            image_of_front_of_emrtd: Some(b"front of the card".to_vec()),
            image_of_rear_of_emrtd: Some(b"rear of the card".to_vec()),
            personalization_timestamp: None,
            personalization_device_serial_number: None,
        }));

        let written = dumper(
            &b"the raw file".to_vec(),
            &parsed,
            &directory,
            &"doc-EF_DG12".to_string(),
        )
        .unwrap();

        // The raw file, then one path per image, in the order they are listed.
        let names: Vec<String> = written
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "doc-EF_DG12.bin",
                "doc-EF_DG12-front.jpeg",
                "doc-EF_DG12-rear.jpeg",
            ]
        );
        assert_eq!(
            std::fs::read(&written[1]).unwrap(),
            b"front of the card".to_vec()
        );
        assert_eq!(
            std::fs::read(&written[2]).unwrap(),
            b"rear of the card".to_vec()
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A document that fills in neither image writes only the raw file, rather
    /// than an empty one per missing field.
    #[test]
    fn writes_nothing_extra_when_there_are_no_images() {
        let directory = std::env::temp_dir().join(format!(
            "passauf-dg12-empty-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();

        let parsed = Some(types::ParsedDataGroup::EFDG12(types::EFDG12 {
            issuing_authority: Some("Some Authority".to_string()),
            date_of_issue: None,
            other_persons: None,
            endorsements_observations: None,
            tax_exit_requirements: None,
            image_of_front_of_emrtd: None,
            image_of_rear_of_emrtd: None,
            personalization_timestamp: None,
            personalization_device_serial_number: None,
        }));

        let written = dumper(
            &b"the raw file".to_vec(),
            &parsed,
            &directory,
            &"doc-EF_DG12".to_string(),
        )
        .unwrap();
        assert_eq!(written.len(), 1);

        let _ = std::fs::remove_dir_all(&directory);
    }
}
