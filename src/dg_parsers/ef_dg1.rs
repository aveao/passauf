use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::icao9303;
use crate::types;
use iso7816_tlv::ber;
use simplelog::{debug, info};

impl types::TD1Mrz {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self) {
        dg_helpers::print_string_element("Document Size", &"TD1 (ID-size)".to_string());
        dg_helpers::print_string_element(
            "Document Type",
            &dg_helpers::parse_mrz_document_code(&self.document_code, &self.issuing_state),
        );
        dg_helpers::print_string_element("Issuing State", &self.issuing_state);
        dg_helpers::print_string_element_as_name("Name of Holder", &self.name_of_holder);
        dg_helpers::print_string_element("Document Number", &self.document_number);
        dg_helpers::print_string_element("Nationality", &self.nationality);
        dg_helpers::print_string_element_as_mrz_date("Date of Birth", &self.date_of_birth);
        dg_helpers::print_string_element("Legal Sex Marker", &dg_helpers::parse_mrz_sex(self.sex));
        dg_helpers::print_string_element_as_mrz_date("Date of Expiry", &self.date_of_expiry);
        if self.optional_data_elements_line_1.len() != 0 {
            dg_helpers::print_string_element(
                "Optional elements (Line 1)",
                &self.optional_data_elements_line_1,
            );
        }
        if self.optional_data_elements_line_2.len() != 0 {
            dg_helpers::print_string_element(
                "Optional elements (Line 2)",
                &self.optional_data_elements_line_2,
            );
        }
        let checksum_result = self.validate_check_digits(true);
        let checksum_text = match checksum_result.iter().all(|&val| val == true) {
            true => "</><green>All valid!</>",
            false => "</><red>Mismatches found!</>",
        }
        .to_string();
        dg_helpers::print_string_element("MRZ Checksums", &checksum_text);
    }
}

impl types::TD3Mrz {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self) {
        dg_helpers::print_string_element("Document Size", &"TD3 (Passport-size)".to_string());
        dg_helpers::print_string_element(
            "Document Type",
            &dg_helpers::parse_mrz_document_code(&self.document_code, &self.issuing_state),
        );
        dg_helpers::print_string_element("Issuing State", &self.issuing_state);
        dg_helpers::print_string_element_as_name("Name of Holder", &self.name_of_holder);
        dg_helpers::print_string_element("Document Number", &self.document_number);
        dg_helpers::print_string_element("Nationality", &self.nationality);
        dg_helpers::print_string_element_as_mrz_date("Date of Birth", &self.date_of_birth);
        dg_helpers::print_string_element("Legal Sex Marker", &dg_helpers::parse_mrz_sex(self.sex));
        dg_helpers::print_string_element_as_mrz_date("Date of Expiry", &self.date_of_expiry);
        dg_helpers::print_string_element(
            "Optional elements",
            &self.personal_number_or_optional_data_elements,
        );
        let checksum_result = self.validate_check_digits(true);
        let checksum_text = match checksum_result.iter().all(|&val| val == true) {
            true => "</><green>All valid!</>",
            false => "</><red>Mismatches found!</>",
        }
        .to_string();
        dg_helpers::print_string_element("MRZ Checksums", &checksum_text);
    }
}

impl types::EFDG1 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &icao9303::DataGroup) {
        dg_helpers::print_section_intro("EF_DG1", data_group.description);
        self.mrz.fancy_print();
        info!("");
    }
}

pub fn parser(
    data: Vec<u8>,
    data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // Parse the base TLV
    let base_tlv = ber::Tlv::parse(&data).0.unwrap();
    assert!(helpers::get_tlv_tag(&base_tlv) == 0x61);
    debug!("base_tlv: {:02x?}", &base_tlv);

    // Get the TLVs stored inside the base tag and sort them by tag number
    let base_tlv_value = helpers::get_tlv_constructed_value(&base_tlv);
    let tlvs = helpers::sort_tlvs_by_tag(&base_tlv_value);
    debug!("tlvs: {:02x?}", tlvs);

    // Deserialize the file from the given TLV data.
    let mrz_obj = types::MRZ::deserialize(
        &dg_helpers::tlv_get_string_value(&tlvs, &0x5F1F).expect("MRZ field (0x5F1F) not in DG1"),
    )?;
    let result = types::EFDG1 { mrz: mrz_obj };
    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG1(result));
}
