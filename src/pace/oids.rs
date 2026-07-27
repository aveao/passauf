///! PACE object identifiers (ICAO 9303 p11 section 9.2.3)
use std::fmt;

use crate::secure_messaging::SmAlgorithm;

/// Every PACE OID is `0.4.0.127.0.7.2.2.4.<mapping>.<cipher>`.
///
/// In DER these leading arcs encode to the bytes below. The spec has us send the
/// OID's value only (with tag 0x06 omitted) in MSE:Set AT, so raw bytes are the
/// most useful representation to keep around.
pub const PACE_OID_PREFIX: [u8; 8] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04];

/// The key agreement algorithm and the mapping are encoded in a single arc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreement {
    Dh,
    Ecdh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    Generic,
    Integrated,
    /// Chip Authentication Mapping. Recognized so we can report it precisely,
    /// but not implemented.
    ChipAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaceAlgorithm {
    pub key_agreement: KeyAgreement,
    pub mapping: Mapping,
    /// The cipher the session keys will be used with. Shared with BAC's secure
    /// messaging, which is 3DES-only.
    pub cipher: SmAlgorithm,
}

impl PaceAlgorithm {
    /// Parse the arc pair at the end of a PACE OID.
    ///
    /// Returns None when the arcs aren't ones the standard assigns.
    fn from_arcs(mapping_arc: u8, cipher_arc: u8) -> Option<PaceAlgorithm> {
        let (key_agreement, mapping) = match mapping_arc {
            0x01 => (KeyAgreement::Dh, Mapping::Generic),
            0x02 => (KeyAgreement::Ecdh, Mapping::Generic),
            0x03 => (KeyAgreement::Dh, Mapping::Integrated),
            0x04 => (KeyAgreement::Ecdh, Mapping::Integrated),
            // 0x05 is unassigned, CAM is ECDH-only.
            0x06 => (KeyAgreement::Ecdh, Mapping::ChipAuthentication),
            _ => return None,
        };
        let cipher = match cipher_arc {
            0x01 => SmAlgorithm::Tdes,
            0x02 => SmAlgorithm::Aes128,
            0x03 => SmAlgorithm::Aes192,
            0x04 => SmAlgorithm::Aes256,
            _ => return None,
        };
        return Some(PaceAlgorithm {
            key_agreement,
            mapping,
            cipher,
        });
    }

    /// Parse a PACE algorithm from the DER value bytes of its object identifier.
    pub fn from_oid_bytes(oid_bytes: &[u8]) -> Option<PaceAlgorithm> {
        // Prefix, then exactly the mapping and cipher arcs.
        if oid_bytes.len() != PACE_OID_PREFIX.len() + 2 {
            return None;
        }
        if oid_bytes[..PACE_OID_PREFIX.len()] != PACE_OID_PREFIX {
            return None;
        }
        return Self::from_arcs(oid_bytes[8], oid_bytes[9]);
    }

    /// The DER value bytes of this algorithm's object identifier.
    ///
    /// This is what goes into MSE:Set AT tag 0x80 and the authentication
    /// token's public key data object.
    pub fn to_oid_bytes(&self) -> Vec<u8> {
        let mapping_arc = match (self.key_agreement, self.mapping) {
            (KeyAgreement::Dh, Mapping::Generic) => 0x01,
            (KeyAgreement::Ecdh, Mapping::Generic) => 0x02,
            (KeyAgreement::Dh, Mapping::Integrated) => 0x03,
            (KeyAgreement::Ecdh, Mapping::Integrated) => 0x04,
            (KeyAgreement::Ecdh, Mapping::ChipAuthentication) => 0x06,
            // DH with Chip Authentication Mapping has no assigned OID.
            (KeyAgreement::Dh, Mapping::ChipAuthentication) => {
                panic!("DH with Chip Authentication Mapping does not exist.")
            }
        };
        let cipher_arc = match self.cipher {
            SmAlgorithm::Tdes => 0x01,
            SmAlgorithm::Aes128 => 0x02,
            SmAlgorithm::Aes192 => 0x03,
            SmAlgorithm::Aes256 => 0x04,
        };
        return vec![PACE_OID_PREFIX.as_slice(), &[mapping_arc, cipher_arc]].concat();
    }

    /// Why this variant is unsupported, for reporting to the user.
    pub fn unsupported_reason(&self) -> Option<&'static str> {
        return match self.mapping {
            Mapping::ChipAuthentication => {
                Some("Chip Authentication Mapping (PACE-CAM) is not implemented")
            }
            _ => None,
        };
    }
}

impl fmt::Display for PaceAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key_agreement = match self.key_agreement {
            KeyAgreement::Dh => "DH",
            KeyAgreement::Ecdh => "ECDH",
        };
        let mapping = match self.mapping {
            Mapping::Generic => "Generic Mapping",
            Mapping::Integrated => "Integrated Mapping",
            Mapping::ChipAuthentication => "Chip Authentication Mapping",
        };
        let cipher = match self.cipher {
            SmAlgorithm::Tdes => "3DES-CBC-CBC",
            SmAlgorithm::Aes128 => "AES-CBC-CMAC-128",
            SmAlgorithm::Aes192 => "AES-CBC-CMAC-192",
            SmAlgorithm::Aes256 => "AES-CBC-CMAC-256",
        };
        return write!(f, "PACE-{}-{} with {}", key_agreement, mapping, cipher);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OIDs quoted by the worked examples in ICAO 9303 p11.
    #[test]
    fn parses_worked_example_oids() {
        // Appendix G.1: PACE with ECDH, generic mapping and AES 128 session keys
        let gm_ecdh = PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02,
        ])
        .unwrap();
        assert_eq!(gm_ecdh.key_agreement, KeyAgreement::Ecdh);
        assert_eq!(gm_ecdh.mapping, Mapping::Generic);
        assert_eq!(gm_ecdh.cipher, SmAlgorithm::Aes128);

        // Appendix G.2: PACE with DH, generic mapping and AES 128 session keys
        let gm_dh = PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02,
        ])
        .unwrap();
        assert_eq!(gm_dh.key_agreement, KeyAgreement::Dh);
        assert_eq!(gm_dh.mapping, Mapping::Generic);
        assert_eq!(gm_dh.cipher, SmAlgorithm::Aes128);

        // Appendix H.1: PACE with ECDH, integrated mapping and AES 128 session keys
        let im_ecdh = PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02,
        ])
        .unwrap();
        assert_eq!(im_ecdh.key_agreement, KeyAgreement::Ecdh);
        assert_eq!(im_ecdh.mapping, Mapping::Integrated);
        assert_eq!(im_ecdh.cipher, SmAlgorithm::Aes128);
    }

    #[test]
    fn oid_encoding_round_trips() {
        for mapping_arc in [0x01u8, 0x02, 0x03, 0x04, 0x06] {
            for cipher_arc in [0x01u8, 0x02, 0x03, 0x04] {
                let oid_bytes =
                    vec![PACE_OID_PREFIX.as_slice(), &[mapping_arc, cipher_arc]].concat();
                let algorithm = PaceAlgorithm::from_oid_bytes(&oid_bytes).unwrap();
                assert_eq!(algorithm.to_oid_bytes(), oid_bytes);
            }
        }
    }

    #[test]
    fn rejects_unassigned_and_malformed_oids() {
        // 0x05 is not an assigned mapping arc.
        assert!(PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x05, 0x02
        ])
        .is_none());
        // 0x05 is not an assigned cipher arc.
        assert!(PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x05
        ])
        .is_none());
        // Chip Authentication OID, not a PACE one.
        assert!(PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02
        ])
        .is_none());
        // Truncated.
        assert!(PaceAlgorithm::from_oid_bytes(&[0x04, 0x00, 0x7F]).is_none());
    }

    #[test]
    fn chip_authentication_mapping_is_unsupported() {
        let cam = PaceAlgorithm::from_oid_bytes(&[
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02,
        ])
        .unwrap();
        assert_eq!(cam.mapping, Mapping::ChipAuthentication);
        assert!(cam.unsupported_reason().is_some());

        // The mappings we do implement report no reason.
        for mapping_arc in [0x01u8, 0x02, 0x03, 0x04] {
            let oid = vec![PACE_OID_PREFIX.as_slice(), &[mapping_arc, 0x02]].concat();
            assert!(PaceAlgorithm::from_oid_bytes(&oid)
                .unwrap()
                .unsupported_reason()
                .is_none());
        }
    }
}
