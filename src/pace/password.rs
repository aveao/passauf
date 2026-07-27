///! PACE password encoding and derivation (ICAO 9303 p11 section 9.7.3)
use sha1::{Digest, Sha1};
use std::fmt;

use crate::icao9303;
use crate::secure_messaging::{kdf, SmAlgorithm};

/// Password reference values for MSE:Set AT data object 0x83.
///
/// ICAO 9303 only assigns MRZ and CAN. BSI TR-03110 additionally has PIN (3)
/// and PUK (4), which are eID rather than eMRTD concerns.
const PASSWORD_REFERENCE_MRZ: u8 = 0x01;
const PASSWORD_REFERENCE_CAN: u8 = 0x02;

/// A PACE password, in the two forms an eMRTD accepts.
#[derive(Debug, Clone)]
pub enum Password {
    /// Derived from the MRZ, the same three fields BAC uses.
    Mrz {
        document_number: String,
        date_of_birth: String,
        date_of_expiry: String,
    },
    /// The Card Access Number printed on the document.
    Can(String),
}

impl Password {
    /// The value for MSE:Set AT data object 0x83.
    pub fn reference(&self) -> u8 {
        return match self {
            Password::Mrz { .. } => PASSWORD_REFERENCE_MRZ,
            Password::Can(_) => PASSWORD_REFERENCE_CAN,
        };
    }

    /// The encoding K = f(pi) of ICAO 9303 p11 Table 8.
    pub fn encode(&self) -> Vec<u8> {
        return match self {
            Password::Mrz {
                document_number,
                date_of_birth,
                date_of_expiry,
            } => {
                // Same MRZ information BAC hashes: each field carries its check
                // digit. For TD1 documents with document numbers longer than
                // nine characters the caller is expected to have already
                // stitched the number back together from the optional data
                // field, as Doc 9303-5 requires.
                let mrz_information = vec![
                    icao9303::append_check_digit(document_number).as_bytes(),
                    icao9303::append_check_digit(date_of_birth).as_bytes(),
                    icao9303::append_check_digit(date_of_expiry).as_bytes(),
                ]
                .concat();
                let mut hasher = Sha1::new();
                hasher.update(mrz_information.as_slice());
                hasher.finalize().to_vec()
            }
            // ISO/IEC 8859-1 agrees with ASCII over the digits a CAN is made
            // of, and maps every remaining code point straight onto its byte.
            Password::Can(can) => can.chars().map(|character| character as u8).collect(),
        };
    }

    /// Derive the password key K_pi = KDF(K, 3).
    pub fn derive_kpi(&self, algorithm: SmAlgorithm) -> Vec<u8> {
        return kdf(algorithm, &self.encode(), 3);
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Deliberately does not print the password itself.
        return match self {
            Password::Mrz { .. } => write!(f, "MRZ"),
            Password::Can(_) => write!(f, "CAN"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MRZ from ICAO 9303 p11 Appendix G, shared by both worked examples.
    fn worked_example_mrz() -> Password {
        return Password::Mrz {
            document_number: "T22000129".to_string(),
            date_of_birth: "640812".to_string(),
            date_of_expiry: "101031".to_string(),
        };
    }

    /// Appendix G quotes both K and K_pi for the MRZ password.
    #[test]
    fn mrz_encoding_matches_worked_example() {
        assert_eq!(
            worked_example_mrz().encode(),
            vec![
                0x7E, 0x2D, 0x2A, 0x41, 0xC7, 0x4E, 0xA0, 0xB3, 0x8C, 0xD3, 0x6F, 0x86, 0x39, 0x39,
                0xBF, 0xA8, 0xE9, 0x03, 0x2A, 0xAD
            ]
        );
    }

    #[test]
    fn mrz_kpi_matches_worked_example() {
        assert_eq!(
            worked_example_mrz().derive_kpi(SmAlgorithm::Aes128),
            vec![
                0x89, 0xDE, 0xD1, 0xB2, 0x66, 0x24, 0xEC, 0x1E, 0x63, 0x4C, 0x19, 0x89, 0x30, 0x28,
                0x49, 0xDD
            ]
        );
    }

    /// ICAO 9303 p11 Appendix H says it reuses "the MRZ-derived key K from the
    /// previous Example", but the K_pi it lists is the one derived from the CAN
    /// 123456. The text is wrong; the value is what implementations must match.
    #[test]
    fn can_kpi_matches_integrated_mapping_example() {
        let can = Password::Can("123456".to_string());
        assert_eq!(can.encode(), b"123456".to_vec());
        assert_eq!(
            can.derive_kpi(SmAlgorithm::Aes128),
            vec![
                0x59, 0x14, 0x68, 0xCD, 0xA8, 0x3D, 0x65, 0x21, 0x9C, 0xCC, 0xB8, 0x56, 0x02, 0x33,
                0x60, 0x0F
            ]
        );
    }

    #[test]
    fn password_references_match_the_standard() {
        assert_eq!(worked_example_mrz().reference(), 0x01);
        assert_eq!(Password::Can("123456".to_string()).reference(), 0x02);
    }

    /// The derived key has to be the right width for whichever cipher the
    /// document picked.
    #[test]
    fn kpi_length_follows_the_cipher() {
        let password = worked_example_mrz();
        assert_eq!(password.derive_kpi(SmAlgorithm::Tdes).len(), 16);
        assert_eq!(password.derive_kpi(SmAlgorithm::Aes128).len(), 16);
        assert_eq!(password.derive_kpi(SmAlgorithm::Aes192).len(), 24);
        assert_eq!(password.derive_kpi(SmAlgorithm::Aes256).len(), 32);
    }

    /// Display must not leak the secret into logs.
    #[test]
    fn display_hides_the_password() {
        assert_eq!(format!("{}", Password::Can("123456".to_string())), "CAN");
        assert_eq!(format!("{}", worked_example_mrz()), "MRZ");
    }
}
