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

impl types::EFDG11 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
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

/// The names in DG11's other-names group.
///
/// 9303 does not repeat 5F0F at the top level the way every other field of this
/// file appears. It wraps them in an A0 group holding a count and then one 5F0F
/// per name, which makes them invisible to a lookup over the file's own tags —
/// so they were read as absent no matter what a document put there, and an
/// issuer that files part of a name here lost it entirely.
///
/// Top level 5F0F is picked up as well. Nothing in 9303 puts one there, but it
/// costs a line, and a name that a document went to the trouble of recording is
/// worth more than a point about where it belongs.
fn other_names(tlvs: &Vec<ber::Tlv>) -> Option<Vec<String>> {
    let mut names = read_names(&helpers::get_tlvs_by_tag(tlvs, 0x5F0F));

    for group in helpers::get_tlvs_by_tag(tlvs, 0xA0) {
        let inside = helpers::get_tlv_constructed_value(group);
        let entries = helpers::get_tlvs_by_tag(&inside, 0x5F0F);

        // The count the group opens with, so a document that disagrees with
        // itself says so somewhere rather than quietly coming up short.
        let claimed = dg_helpers::tlv_get_byte(&helpers::sort_tlvs_by_tag(&inside), &0x02);
        if let Some(claimed) = claimed {
            if usize::from(claimed) != entries.len() {
                warn!(
                    "EF.DG11 says it carries {} other name(s) but holds {}.",
                    claimed,
                    entries.len()
                );
            }
        }
        names.append(&mut read_names(&entries));
    }

    if names.is_empty() {
        return None;
    }
    return Some(names);
}

/// Each of those TLVs as a name, with the MRZ's filler turned back into spaces.
fn read_names(tlvs: &[&ber::Tlv]) -> Vec<String> {
    return tlvs
        .iter()
        // A name that is not valid UTF-8 is one we cannot render. That is worth
        // losing the name over, not the whole read.
        .filter_map(|tlv| String::from_utf8(helpers::get_tlv_value_bytes(tlv)).ok())
        .map(|name| name.replace('<', " ").trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
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
    let result = types::EFDG11 {
        full_name: dg_helpers::tlv_get_string_value(&tlvs, &0x5F0E),
        other_names: other_names(&base_tlv_value),
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

/// Write the file out, plus any image it carries.
///
/// DG11 can carry a scan proving citizenship, which is otherwise
/// only visible as a byte count.
pub fn dumper(
    file_data: &Vec<u8>,
    parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<Vec<PathBuf>, io::Error> {
    let mut written = generic_dumper(file_data, parsed_data, base_path, &base_filename)?;

    let parsed = match parsed_data {
        Some(types::ParsedDataGroup::EFDG11(parsed)) => parsed,
        // Nothing parsed, so there is nothing to pull an image out of.
        _ => return Ok(written),
    };

    for (name, image) in [("proof-of-citizenship", &parsed.proof_of_citizenship)] {
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

    /// A DER TLV with a length short enough to fit one byte, which every field
    /// these tests build is.
    fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        return out;
    }

    fn parse(body: Vec<u8>) -> types::EFDG11 {
        let dg_info = types::DATA_GROUPS
            .iter()
            .find(|dg_info| dg_info.name == "EF.DG11")
            .unwrap();
        match parser(&tlv(&[0x6B], &body), dg_info, false) {
            Some(types::ParsedDataGroup::EFDG11(dg11)) => dg11,
            other => panic!("EF.DG11 did not parse: {:02x?}", other),
        }
    }

    /// The names 9303 puts in the other-names group.
    ///
    /// They are the one field of this file that is not a tag at the top level:
    /// A0 wraps a count and then one 5F0F per name. Looking for 5F0F beside the
    /// other tags finds nothing, which is what this file did for its whole life,
    /// so a document that recorded a name here had it dropped without a word.
    #[test]
    fn reads_the_names_in_the_other_names_group() {
        let dg11 = parse(
            [
                tlv(&[0x5F, 0x0E], b"MUSTERMANN<<ERIKA"),
                tlv(
                    &[0xA0],
                    &[
                        vec![0x02, 0x01, 0x02],
                        tlv(&[0x5F, 0x0F], b"SCHMIDT"),
                        tlv(&[0x5F, 0x0F], b"VON<HOFFMANN"),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );

        assert_eq!(dg11.full_name, Some("MUSTERMANN<<ERIKA".to_string()));
        assert_eq!(
            dg11.other_names,
            Some(vec!["SCHMIDT".to_string(), "VON HOFFMANN".to_string()])
        );
    }

    /// A document with nothing in the group must not grow an empty row for it.
    #[test]
    fn leaves_other_names_absent_when_there_are_none() {
        let dg11 = parse(tlv(&[0x5F, 0x0E], b"MUSTERMANN<<ERIKA"));
        assert_eq!(dg11.other_names, None);
    }

    /// Some issuers write the name with a space where 9303 wants `<<`.
    ///
    /// Nothing can recover which half is the family name once that has happened,
    /// so the whole string stands as the name rather than being guessed at.
    #[test]
    fn keeps_a_name_that_was_separated_with_a_space() {
        let dg11 = parse(tlv(&[0x5F, 0x0E], b"ERIKA MUSTERMANN"));
        assert_eq!(dg11.full_name, Some("ERIKA MUSTERMANN".to_string()));

        let (given_names, surname) = dg_helpers::format_mrz_name(&dg11.full_name.clone().unwrap());
        assert_eq!(given_names, "ERIKA MUSTERMANN");
        assert_eq!(surname, "");
    }

    /// 5F2B is YYYYMMDD, and issuers write the MRZ's six digits into it.
    ///
    /// Eight digits are there so the century does not have to be guessed; six
    /// throw that away. Reading them anyway beats losing a date of birth.
    #[test]
    fn reads_a_date_of_birth_that_is_missing_its_century() {
        let dg11 = parse(
            [
                tlv(&[0x5F, 0x0E], b"MUSTERMANN<<ERIKA"),
                tlv(&[0x5F, 0x2B], b"740812"),
            ]
            .concat(),
        );
        assert_eq!(dg11.full_date_of_birth, Some("740812".to_string()));
        assert_eq!(
            dg_helpers::parse_dg_date(&dg11.full_date_of_birth.unwrap()),
            Some((12, 8, 1974)),
        );
    }

    /// And the format the standard actually asks for still wins.
    #[test]
    fn still_reads_a_date_of_birth_with_its_century() {
        assert_eq!(
            dg_helpers::parse_dg_date(&"19740812".to_string()),
            Some((12, 8, 1974))
        );
        assert_eq!(dg_helpers::parse_dg_date(&"7408".to_string()), None);
        assert_eq!(dg_helpers::parse_dg_date(&"7408AB".to_string()), None);
    }
}
