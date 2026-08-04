use crate::{dg_parsers::helpers as dg_helpers, icao9303};
use simplelog::warn;
use std::cmp::min;
use std::fmt;

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

/// The shapes ICAO 9303 gives a machine readable zone, as (lines, characters per line).
///
/// TD1 is three lines of thirty (Doc 9303-5), TD2 two of thirty six (Doc 9303-6) and TD3
/// two of forty four (Doc 9303-4). Visas reuse two of these rather than adding their own:
/// MRV-A is 2x44 like TD3, MRV-B is 2x36 like TD2. So a shape narrows the candidates and
/// never settles the format on its own, which is what parsing and the check digits are for.
const MRZ_LAYOUTS: [(usize, usize); 3] = [(3, 30), (2, 36), (2, 44)];

/// Characters a recogniser reaches for when it meets a filler, and that an MRZ can never
/// hold, so rewriting them costs nothing.
///
/// Anything absent from this list is left alone. `K` and `S` are also common misreads of
/// `<`, but they are legal MRZ characters, and rewriting those would turn a bad frame into
/// a wrong answer instead of a rejected one.
const FILLER_LOOKALIKES: [(char, &str); 5] = [
    ('\u{00AB}', "<<"),
    ('\u{2039}', "<"),
    ('\u{FF1C}', "<"),
    ('\u{2329}', "<"),
    ('\u{27E8}', "<"),
];

/// Turns one line of recognised text into what an MRZ line would look like.
fn normalize_recognized_line(line: &String) -> String {
    let mut normalized = String::with_capacity(line.len());
    for character in line.chars() {
        // An MRZ holds no spaces, and a recogniser inserting them is the usual reason a
        // line comes back the wrong length.
        if character.is_whitespace() {
            continue;
        }
        match FILLER_LOOKALIKES
            .iter()
            .find(|(lookalike, _)| *lookalike == character)
        {
            Some((_, filler)) => normalized.push_str(filler),
            None => {
                for uppercased in character.to_uppercase() {
                    normalized.push(uppercased);
                }
            }
        }
    }
    return normalized;
}

/// Whether every character is one an MRZ is allowed to carry.
fn is_mrz_alphabet(line: &String) -> bool {
    return line.chars().all(|character| {
        character.is_ascii_uppercase() || character.is_ascii_digit() || character == '<'
    });
}

/// Why recognised text did not turn into an MRZ.
///
/// A camera that will not scan a document is failing at one of these, and they want
/// different things done about them, so the difference is worth carrying back out
/// rather than flattening into "no".
#[derive(Debug, Clone, PartialEq)]
pub enum MrzScanFailure {
    /// Nothing came back the length of an MRZ row. The print was never resolved.
    NoCandidates,
    /// Rows of usable lengths, but never enough of one length together.
    NoLayout { lengths: Vec<usize> },
    /// A layout's worth of rows that the parser would not take.
    Unparsed { lines: usize, length: usize },
    /// Rows that parsed, and check digits that disagreed with their fields.
    CheckDigits {
        lines: usize,
        length: usize,
        failed: Vec<&'static str>,
    },
}

impl MrzScanFailure {
    /// How far a run of lines got, so the most informative failure is the one reported.
    ///
    /// Reaching the check digits says far more than never finding a layout, and a frame
    /// usually produces several of these at once.
    fn rank(&self) -> u8 {
        return match self {
            Self::NoCandidates => 0,
            Self::NoLayout { .. } => 1,
            Self::Unparsed { .. } => 2,
            Self::CheckDigits { .. } => 3,
        };
    }
}

impl fmt::Display for MrzScanFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            Self::NoCandidates => write!(f, "Nothing came back the length of an MRZ row."),
            Self::NoLayout { lengths } => write!(
                f,
                "Rows of {} characters. A passport needs two of 44, an identity card three of 30.",
                lengths
                    .iter()
                    .map(|length| length.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            // 2x36 is the one shape that reaches here on a correct read, because TD2
            // has no parser yet. Saying so beats letting it look like a bad scan.
            Self::Unparsed { lines, length } if *lines == 2 && *length == 36 => write!(
                f,
                "Read a TD2 machine readable zone, which passauf cannot parse yet."
            ),
            Self::Unparsed { lines, length } => {
                write!(f, "{} rows of {} would not parse.", lines, length)
            }
            Self::CheckDigits {
                lines,
                length,
                failed,
            } => write!(
                f,
                "{}x{} read, but the {} check digit{} did not match. A character is being \
                 misread; hold steadier or move closer.",
                lines,
                length,
                failed.join(" and "),
                if failed.len() == 1 { "" } else { "s" }
            ),
        };
    }
}

impl MRZ {
    pub fn deserialize(input: &String) -> Option<MRZ> {
        match input.len() {
            90 => Some(MRZ::TD1(TD1Mrz::deserialize(input)?)),
            88 => Some(MRZ::TD3(TD3Mrz::deserialize(input)?)),
            _ => None,
        }
    }

    /// Picks an MRZ out of lines of text recognised in an image.
    ///
    /// Everything the recogniser saw goes in, in reading order. What comes back is an MRZ
    /// only once some run of lines took one of the shapes in [`MRZ_LAYOUTS`], parsed, and
    /// passed every check digit.
    ///
    /// Nothing else about the input is trusted. Lines are normalised, then dropped unless
    /// they hold only MRZ characters *and* are as long as some layout expects. Dropping on
    /// length is what lets a stray line sitting between the rows — a "SPECIMEN" overprint,
    /// a scrap of the visual inspection zone — fall out and leave the real rows adjacent,
    /// so a window can slide over what remains.
    ///
    /// Every check digit has to pass. A document whose issuer got one wrong will not be
    /// found here and has to be typed in by hand, which is the right trade against a live
    /// camera: there is always another frame, and a wrong answer taken quietly is worse
    /// than no answer at all.
    ///
    /// When nothing is found, the [`MrzScanFailure`] says how far the lines got, because
    /// a camera that will not scan is a different problem depending on where it stopped.
    pub fn from_recognized_lines(lines: &[String]) -> Result<MRZ, MrzScanFailure> {
        let candidates: Vec<String> = lines
            .iter()
            .map(normalize_recognized_line)
            .filter(is_mrz_alphabet)
            // Only ASCII survives the filter above, so bytes and characters agree here.
            .filter(|line| {
                MRZ_LAYOUTS
                    .iter()
                    .any(|(_, line_length)| *line_length == line.len())
            })
            .collect();

        if candidates.is_empty() {
            return Err(MrzScanFailure::NoCandidates);
        }

        let mut furthest: Option<MrzScanFailure> = None;
        let mut remember = |failure: MrzScanFailure| {
            if furthest
                .as_ref()
                .map_or(true, |best| failure.rank() > best.rank())
            {
                furthest = Some(failure);
            }
        };

        for (line_count, line_length) in MRZ_LAYOUTS {
            if candidates.len() < line_count {
                continue;
            }
            for window in candidates.windows(line_count) {
                if window.iter().any(|line| line.len() != line_length) {
                    continue;
                }
                let mrz = match MRZ::deserialize(&window.concat()) {
                    Some(mrz) => mrz,
                    // TD2 has no parser yet, so a 2x36 gets this far and then stops.
                    None => {
                        remember(MrzScanFailure::Unparsed {
                            lines: line_count,
                            length: line_length,
                        });
                        continue;
                    }
                };

                let valid = mrz.validate_check_digits(false);
                if valid.iter().all(|passed| *passed) {
                    return Ok(mrz);
                }
                remember(MrzScanFailure::CheckDigits {
                    lines: line_count,
                    length: line_length,
                    failed: mrz
                        .check_digit_names()
                        .iter()
                        .zip(valid.iter())
                        .filter(|(_, passed)| !**passed)
                        .map(|(name, _)| *name)
                        .collect(),
                });
            }
        }

        return Err(furthest.unwrap_or(MrzScanFailure::NoLayout {
            lengths: candidates.iter().map(|line| line.len()).collect(),
        }));
    }

    /// What each entry of [`MRZ::validate_check_digits`] is checking, in the same order.
    pub fn check_digit_names(&self) -> &'static [&'static str] {
        return match self {
            Self::TD1(_) => &[
                "document number",
                "date of birth",
                "date of expiry",
                "composite",
            ],
            Self::TD3(_) => &[
                "document number",
                "date of birth",
                "date of expiry",
                "optional data",
                "composite",
            ],
        };
    }

    /// The two characters naming what kind of document this is.
    ///
    /// Not padding-stripped, so a passport reads `P<` rather than `P`.
    pub fn document_code(&self) -> &String {
        return match self {
            Self::TD1(mrz) => &mrz.document_code,
            Self::TD3(mrz) => &mrz.document_code,
        };
    }

    /// The three character code of the state that issued the document, filler removed.
    ///
    /// With [`MRZ::document_code`] this identifies a document before anything has been
    /// read off its chip, which is the point of scanning an MRZ first: a German residence
    /// permit is code `AR` issued by `D`, printed `ARD<<`.
    pub fn issuing_state(&self) -> &String {
        return match self {
            Self::TD1(mrz) => &mrz.issuing_state,
            Self::TD3(mrz) => &mrz.issuing_state,
        };
    }

    /// The document number as printed, with the MRZ's filler removed.
    ///
    /// Safe to hand straight to an access key: [`icao9303::pad_document_number`] puts the
    /// filler back when keys are derived, so this is the same form the CLI's flags and the
    /// app's form already carry.
    pub fn document_number(&self) -> &String {
        return match self {
            Self::TD1(mrz) => &mrz.document_number,
            Self::TD3(mrz) => &mrz.document_number,
        };
    }

    /// Date of birth, YYMMDD.
    pub fn date_of_birth(&self) -> &String {
        return match self {
            Self::TD1(mrz) => &mrz.date_of_birth,
            Self::TD3(mrz) => &mrz.date_of_birth,
        };
    }

    /// Date of expiry, YYMMDD.
    pub fn date_of_expiry(&self) -> &String {
        return match self {
            Self::TD1(mrz) => &mrz.date_of_expiry,
            Self::TD3(mrz) => &mrz.date_of_expiry,
        };
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

    /// The TD3 specimen from ICAO 9303 p4. Every check digit on it is correct.
    const TD3_LINE_1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const TD3_LINE_2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    /// The TD1 specimen, as its three printed rows.
    const TD1_LINE_1: &str = "I<UTO1234567897ABCDEFGH<<<<<<<";
    const TD1_LINE_2: &str = "0001029<3001020UTO<<<<<<<<<<<8";
    const TD1_LINE_3: &str = "MUSTERMANN<<ERIKA<<<<<<<<<<<<<";

    fn lines(input: &[&str]) -> Vec<String> {
        return input.iter().map(|line| line.to_string()).collect();
    }

    /// A recogniser hands over everything it saw, most of which is the visual inspection
    /// zone rather than the MRZ.
    #[test]
    fn finds_a_td3_among_the_rest_of_the_page() {
        let result = MRZ::from_recognized_lines(&lines(&[
            "PASSPORT",
            "UTOPIA",
            "ERIKSSON",
            "ANNA MARIA",
            TD3_LINE_1,
            TD3_LINE_2,
        ]))
        .unwrap();
        match result {
            MRZ::TD3(mrz) => assert_eq!(mrz.document_number, "L898902C3"),
            other => panic!("expected a TD3, got {:?}", other),
        }
    }

    #[test]
    fn finds_a_td1_across_its_three_rows() {
        let result =
            MRZ::from_recognized_lines(&lines(&[TD1_LINE_1, TD1_LINE_2, TD1_LINE_3])).unwrap();
        match result {
            MRZ::TD1(mrz) => assert_eq!(mrz.document_number, "123456789"),
            other => panic!("expected a TD1, got {:?}", other),
        }
    }

    /// A line landing between the rows must not separate them. Dropping candidates on
    /// length is what closes the gap back up.
    #[test]
    fn a_stray_line_between_the_rows_does_not_hide_them() {
        let result =
            MRZ::from_recognized_lines(&lines(&[TD3_LINE_1, "SPECIMEN", TD3_LINE_2])).unwrap();
        assert!(matches!(result, MRZ::TD3(_)));
    }

    /// Lowercase, inserted spaces and a guillemet where two fillers belong are all things
    /// a recogniser does to an MRZ, and none of them should cost a read.
    #[test]
    fn normalises_case_spacing_and_filler_lookalikes() {
        let noisy_line_1 = "p<utoeriksson\u{00AB}anna<maria <<<<<<<<<<<<<<<<<<<";
        let result = MRZ::from_recognized_lines(&lines(&[noisy_line_1, TD3_LINE_2])).unwrap();
        match result {
            MRZ::TD3(mrz) => assert_eq!(mrz.name_of_holder, "ERIKSSON<<ANNA<MARIA"),
            other => panic!("expected a TD3, got {:?}", other),
        }
    }

    /// Two rows of thirty is not a layout any document uses, however MRZ-shaped the
    /// characters are.
    #[test]
    fn rejects_a_shape_no_document_has() {
        assert_eq!(
            MRZ::from_recognized_lines(&lines(&[TD1_LINE_1, TD1_LINE_2])).unwrap_err(),
            MrzScanFailure::NoLayout {
                lengths: vec![30, 30]
            }
        );
    }

    /// One wrong character in the document number, which the shape cannot notice and the
    /// check digits must. Naming the ones that failed is what tells a camera's user that
    /// they are close rather than nowhere.
    #[test]
    fn names_the_check_digits_a_misread_breaks() {
        let misread = "L898902C46UTO7408122F1204159ZE184226B<<<<<10";
        assert_eq!(misread.len(), TD3_LINE_2.len());
        assert_eq!(
            MRZ::from_recognized_lines(&lines(&[TD3_LINE_1, misread])).unwrap_err(),
            MrzScanFailure::CheckDigits {
                lines: 2,
                length: 44,
                failed: vec!["document number", "composite"],
            }
        );
    }

    /// Nothing the right length at all is a different problem from something close.
    #[test]
    fn says_when_nothing_was_even_the_right_length() {
        assert_eq!(
            MRZ::from_recognized_lines(&lines(&["PASSPORT", "UTOPIA"])).unwrap_err(),
            MrzScanFailure::NoCandidates
        );
    }

    /// Documents the gap rather than the behaviour: the shape is recognised and the parser
    /// is what is missing, so this changes the day TD2Mrz lands.
    #[test]
    fn a_td2_shape_is_seen_but_cannot_be_parsed_yet() {
        let line_1 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<";
        let line_2 = "D231458907UTO7408122F1204159<<<<<<<6";
        assert_eq!(line_1.len(), 36);
        assert_eq!(line_2.len(), 36);
        let failure = MRZ::from_recognized_lines(&lines(&[line_1, line_2])).unwrap_err();
        assert_eq!(
            failure,
            MrzScanFailure::Unparsed {
                lines: 2,
                length: 36
            }
        );
        assert!(failure.to_string().contains("TD2"));
    }

    /// The most informative failure is the one worth showing, and a frame usually
    /// produces several at once.
    #[test]
    fn reports_the_furthest_a_run_of_lines_got() {
        let misread = "L898902C46UTO7408122F1204159ZE184226B<<<<<10";
        // A stray thirty-character row alongside a TD3 that only fails its check digits.
        let failure =
            MRZ::from_recognized_lines(&lines(&[TD1_LINE_1, TD3_LINE_1, misread])).unwrap_err();
        assert!(matches!(failure, MrzScanFailure::CheckDigits { .. }));
    }
}
