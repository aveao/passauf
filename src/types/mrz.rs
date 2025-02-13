use crate::{dg_parsers::helpers as dg_helpers, icao9303};
use simplelog::warn;
use std::cmp::min;

fn validate_mrz_field_check_digit(
    field: &String,
    check_digit: &char,
    verbose: bool,
    verbose_as: Option<String>,
) -> bool {
    let calculated_check_digit = icao9303::calculate_check_digit(&field);
    let check_digit_valid = *check_digit == calculated_check_digit;
    if !check_digit_valid && verbose && verbose_as.is_some() {
        warn!(
            "{} checksum is invalid (doc={}, calculated={}).",
            verbose_as.unwrap(),
            check_digit,
            calculated_check_digit
        );
    }
    return check_digit_valid;
}

#[derive(Debug)]
pub enum MRZ {
    TD1(TD1Mrz),
    // TD2(TD2Mrz),
    TD3(TD3Mrz),
}

impl MRZ {
    pub fn deserialize(input: &String) -> Option<MRZ> {
        match input.len() {
            90 => Some(MRZ::TD1(TD1Mrz::deserialize(input)?)),
            88 => Some(MRZ::TD3(TD3Mrz::deserialize(input)?)),
            _ => None,
        }
    }

    // allowing dead code here because I think this is a useful API as a library
    #[allow(dead_code)]
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        match self {
            Self::TD1(mrzobj) => mrzobj.validate_check_digits(verbose),
            Self::TD3(mrzobj) => mrzobj.validate_check_digits(verbose),
        }
    }
}

pub trait MRZChecksum {
    /// Internal function for use with traits, as one cannot define fields in a trait.
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    );

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid)
    fn calculate_common_checksums(&self, verbose: bool) -> (bool, bool, bool, bool) {
        // cd = check digit
        let (
            document_number,
            document_number_cd,
            date_of_birth,
            date_of_birth_cd,
            date_of_expiry,
            date_of_expiry_cd,
            composite_base,
            composite_cd,
        ) = self.get_checksum_variables();

        let document_number_valid = validate_mrz_field_check_digit(
            document_number,
            document_number_cd,
            verbose,
            Some("Document number".to_string()),
        );
        let date_of_birth_valid = validate_mrz_field_check_digit(
            date_of_birth,
            date_of_birth_cd,
            verbose,
            Some("Date of birth".to_string()),
        );
        let date_of_expiry_valid = validate_mrz_field_check_digit(
            date_of_expiry,
            date_of_expiry_cd,
            verbose,
            Some("Date of expiry".to_string()),
        );
        let composite_valid = validate_mrz_field_check_digit(
            &composite_base,
            composite_cd,
            verbose,
            Some("Composite".to_string()),
        );

        return (
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            composite_valid,
        );
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TD1Mrz {
    // ICAO 9303 part 5, edition 8, 4.2.2
    /// 90 characters of MRZ (physically shown as 3 lines)
    pub raw_mrz: String,
    // Line 1
    /// 2 characters. The first character shall be P to designate an MRP.
    /// The second character shall be as specified in ICAO 9303 part 5,
    /// edition 8, 4.2.2.3 Note k.
    pub document_code: String,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    pub issuing_state: String,
    /// 9 characters
    pub document_number: String,
    /// 1 character
    pub document_number_check_digit: char,
    /// up to 15 characters
    pub optional_data_elements_line_1: String,
    // Line 2
    /// 6 characters, YYMMDD
    pub date_of_birth: String,
    /// 1 character
    pub date_of_birth_check_digit: char,
    /// F = female; M = male; < = unspecified.
    pub sex: char,
    /// 6 characters, YYMMDD
    pub date_of_expiry: String,
    /// 1 character
    pub date_of_expiry_check_digit: char,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    pub nationality: String,
    /// up to 11 characters
    pub optional_data_elements_line_2: String,
    /// 1 character
    pub composite_check_digit: char,
    // line 3
    /// 30 characters
    pub name_of_holder: String,
}

impl MRZChecksum for TD1Mrz {
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    ) {
        // ICAO 9303 p5, edition 8, 4.2.4 says:
        // Character positions (upper/middle MRZ line)
        // used to calculate check digit
        // 6 – 30 (upper line),
        // 1 – 7, 9 – 15, 19 – 29 (middle line)
        let composite_base = vec![
            &self.raw_mrz[5..30],
            &self.raw_mrz[30..30 + 7],
            &self.raw_mrz[30 + 8..30 + 15],
            &self.raw_mrz[30 + 18..30 + 29],
        ]
        .concat();

        return (
            &self.document_number,
            &self.document_number_check_digit,
            &self.date_of_birth,
            &self.date_of_birth_check_digit,
            &self.date_of_expiry,
            &self.date_of_expiry_check_digit,
            composite_base,
            &self.composite_check_digit,
        );
    }
}

impl TD1Mrz {
    pub fn deserialize(input: &String) -> Option<TD1Mrz> {
        if input.len() != 90 {
            return None;
        }
        // ICAO 9303 p5, Edition 8, 4.2.2.3, Note j says:
        // "The number of characters in the VIZ may be variable; however, if the document number has more than 9
        // characters, the 9 principal characters shall be shown in the MRZ in character positions 6 to 14. They shall be
        // followed by a filler character instead of a check digit to indicate a truncated number. The remaining characters
        // of the document number shall be shown at the beginning of the field reserved for optional data elements
        // (character positions 16 to 30 of the upper machine readable line) followed by a check digit and a filler character."
        let mut document_number = dg_helpers::remove_mrz_padding(&input[5..14].to_string());
        let mut document_number_check_digit = input.chars().nth(14)?;
        let mut optional_data_elements_line_1 =
            dg_helpers::remove_mrz_padding(&input[15..30].to_string());
        // Check if this is truncated document number
        if document_number_check_digit == '<' {
            // Find the < separating the rest of document number from optional data elements
            let end_of_doc_number = optional_data_elements_line_1
                .find('<')
                .unwrap_or(optional_data_elements_line_1.len());
            // Add the rest of the document number into the document number field and set new check digit
            document_number.push_str(&optional_data_elements_line_1[..end_of_doc_number - 1]);
            document_number_check_digit = optional_data_elements_line_1
                .chars()
                .nth(end_of_doc_number - 1)?;
            // Cut off rest of the document number from optional data elements.
            // Ensure we don't go over the size. Normally this shouldn't happen if the document number
            // follows the standard (the filler character is present), but this implementation assumes
            // that some implementations may max out the size of optional elements.
            optional_data_elements_line_1 = optional_data_elements_line_1
                [min(end_of_doc_number + 1, optional_data_elements_line_1.len())..]
                .to_string();
        }
        return Some(TD1Mrz {
            raw_mrz: input.to_string(),
            // Line 1
            document_code: input[0..2].to_string(),
            issuing_state: dg_helpers::remove_mrz_padding(&input[2..5].to_string()),
            document_number: document_number,
            document_number_check_digit: document_number_check_digit,
            optional_data_elements_line_1: optional_data_elements_line_1,
            // Line 2
            date_of_birth: input[30..36].to_string(),
            date_of_birth_check_digit: input.chars().nth(36)?,
            sex: input.chars().nth(37)?,
            date_of_expiry: input[38..44].to_string(),
            date_of_expiry_check_digit: input.chars().nth(44)?,
            nationality: dg_helpers::remove_mrz_padding(&input[45..48].to_string()),
            optional_data_elements_line_2: dg_helpers::remove_mrz_padding(
                &input[48..59].to_string(),
            ),
            composite_check_digit: input.chars().nth(59)?,
            // Line 3
            name_of_holder: dg_helpers::remove_mrz_padding(&input[60..89].to_string()),
        });
    }

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid,
    /// composite_valid)
    ///
    /// verbose argument makes invalid check digits to log as warn.
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        // Converting tuples to Vectors is hard.
        let (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid) =
            self.calculate_common_checksums(verbose);

        return vec![
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            composite_valid,
        ];
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TD3Mrz {
    // ICAO 9303 part 4, edition 8, 4.2.2
    /// 88 characters of MRZ (physically shown as 2 lines)
    pub raw_mrz: String,
    /// 2 characters. The first character shall be P to designate an MRP.
    /// The second character shall identify the MRP type, as detailed in Section 4.4.
    pub document_code: String,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    /// Spaces shall be replaced by filler characters (<).
    pub issuing_state: String,
    /// 39 characters.
    pub name_of_holder: String,
    /// 9 characters
    pub document_number: String,
    /// 1 character
    pub document_number_check_digit: char,
    /// The three-letter code specified in Doc 9303-3 shall be used.
    /// Spaces shall be replaced by filler characters (<).
    pub nationality: String,
    /// 6 characters, YYMMDD
    pub date_of_birth: String,
    /// 1 character
    pub date_of_birth_check_digit: char,
    /// F = female; M = male; < = unspecified.
    pub sex: char,
    /// 6 characters, YYMMDD
    pub date_of_expiry: String,
    /// 1 character
    pub date_of_expiry_check_digit: char,
    /// 14 characters, padded with <
    pub personal_number_or_optional_data_elements: String,
    /// 1 character, can be 0 or < if personal_number_or_optional_data_elements is unused.
    pub personal_number_or_optional_data_elements_check_digit: char,
    /// 1 character
    pub composite_check_digit: char,
}

impl MRZChecksum for TD3Mrz {
    fn get_checksum_variables(
        &self,
    ) -> (
        &String,
        &char,
        &String,
        &char,
        &String,
        &char,
        String,
        &char,
    ) {
        // ICAO 9303 p4, edition 8, 4.2.2.2 says:
        // "Composite check digit for characters of machine readable data of the lower line
        // in positions 1 to 10, 14 to 20 and 22 to 43, including values for letters that are
        // a part of the number fields and their check digits."
        let composite_base = vec![
            &self.raw_mrz[44..44 + 10],
            &self.raw_mrz[44 + 13..44 + 20],
            &self.raw_mrz[44 + 21..44 + 43],
        ]
        .concat();

        return (
            &self.document_number,
            &self.document_number_check_digit,
            &self.date_of_birth,
            &self.date_of_birth_check_digit,
            &self.date_of_expiry,
            &self.date_of_expiry_check_digit,
            composite_base,
            &self.composite_check_digit,
        );
    }
}

impl TD3Mrz {
    pub fn deserialize(input: &String) -> Option<TD3Mrz> {
        if input.len() != 88 {
            return None;
        }
        return Some(TD3Mrz {
            raw_mrz: input.to_string(),
            document_code: input[0..2].to_string(),
            issuing_state: dg_helpers::remove_mrz_padding(&input[2..5].to_string()),
            name_of_holder: dg_helpers::remove_mrz_padding(&input[5..44].to_string()),
            document_number: dg_helpers::remove_mrz_padding(&input[44..53].to_string()),
            document_number_check_digit: input.chars().nth(53)?,
            nationality: dg_helpers::remove_mrz_padding(&input[54..57].to_string()),
            date_of_birth: input[57..63].to_string(),
            date_of_birth_check_digit: input.chars().nth(63)?,
            sex: input.chars().nth(64)?,
            date_of_expiry: input[65..71].to_string(),
            date_of_expiry_check_digit: input.chars().nth(71)?,
            personal_number_or_optional_data_elements: dg_helpers::remove_mrz_padding(
                &input[72..86].to_string(),
            ),
            personal_number_or_optional_data_elements_check_digit: input.chars().nth(86)?,
            composite_check_digit: input.chars().nth(87)?,
        });
    }

    /// Returns (document_number_valid, date_of_birth_valid, date_of_expiry_valid,
    /// personal_number_or_optional_data_elements_valid, composite_valid)
    ///
    /// verbose argument makes invalid check digits to log as warn.
    pub fn validate_check_digits(&self, verbose: bool) -> Vec<bool> {
        let mut personal_number_or_optional_data_elements_valid = true;
        // If it's empty, then the check digit can be empty.
        if self.personal_number_or_optional_data_elements.len() != 0 {
            personal_number_or_optional_data_elements_valid = validate_mrz_field_check_digit(
                &self.personal_number_or_optional_data_elements,
                &self.personal_number_or_optional_data_elements_check_digit,
                verbose,
                Some("Personal number or optional data elements".to_string()),
            );
        } else if verbose {
            warn!("Personal number or optional data elements is empty, ignoring check digit.");
        }

        let (document_number_valid, date_of_birth_valid, date_of_expiry_valid, composite_valid) =
            self.calculate_common_checksums(verbose);

        return vec![
            document_number_valid,
            date_of_birth_valid,
            date_of_expiry_valid,
            personal_number_or_optional_data_elements_valid,
            composite_valid,
        ];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn td1_mrz_short_document_number_parsing() {
        let mrz = &"I<UTO1234567897ABCDEFGH<<<<<<<0001029<3001020UTO<<<<<<<<<<<8MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789");
        assert_eq!(result.document_number_check_digit, '7');
        assert_eq!(result.optional_data_elements_line_1, "ABCDEFGH");
    }

    #[test]
    fn td1_mrz_long_document_number_parsing() {
        let mrz = &"I<UTO123456789<ABCD3<TEST<<<<<0001029<3001020UTO<<<<<<<<<<<2MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789ABCD");
        assert_eq!(result.document_number_check_digit, '3');
        assert_eq!(result.optional_data_elements_line_1, "TEST");
    }

    #[test]
    fn td1_mrz_full_length_document_number_parsing() {
        let mrz = &"I<UTO123456789<ABCDABCDABCDAB60001029<3001020UTO<<<<<<<<<<<0MUSTERMANN<<ERIKA<<<<<<<<<<<<<".to_string();
        let result = TD1Mrz::deserialize(mrz).unwrap();
        assert_eq!(result.document_number, "123456789ABCDABCDABCDAB");
        assert_eq!(result.document_number_check_digit, '6');
        assert_eq!(result.optional_data_elements_line_1, "");
    }
}
