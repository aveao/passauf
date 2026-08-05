///! EF.CardAccess SecurityInfos (ICAO 9303 p11 section 9.2)
///
/// EF.CardAccess carries a `SecurityInfos ::= SET OF SecurityInfo`, where each
/// entry is a SEQUENCE opening with an object identifier that decides how the
/// rest of the entry is read:
///
/// ```text
/// SecurityInfo ::= SEQUENCE {
///     protocol     OBJECT IDENTIFIER,
///     requiredData ANY DEFINED BY protocol,
///     optionalData ANY DEFINED BY protocol OPTIONAL
/// }
/// ```
///
/// Only the entries PACE needs are modelled. Anything else is kept as an
/// unrecognized entry rather than being dropped, so the file can still be
/// displayed in full.
use std::fmt;

use crate::pace::oids::PaceAlgorithm;

/// A PACEInfo entry (ICAO 9303 p11 section 9.2.1).
#[derive(Debug, Clone)]
pub struct PaceInfo {
    pub algorithm: PaceAlgorithm,
    /// BSI TR-03110-3 says this SHOULD be 2.
    pub version: u64,
    /// The standardized domain parameter ID. Required when the document offers
    /// more than one set of domain parameters, which is why it is optional here.
    pub parameter_id: Option<u64>,
}

/// A SecurityInfo entry we recognized but do not model in detail.
#[derive(Debug, Clone)]
pub struct UnknownSecurityInfo {
    /// The DER value bytes of the entry's object identifier.
    pub protocol: Vec<u8>,
}

/// A ChipAuthenticationPublicKeyInfo entry (ICAO 9303 p11 section 9.2.6).
///
/// This carries the chip's *static* Chip Authentication public key, which
/// PACE-CAM checks its mapping key against.
#[derive(Debug, Clone)]
pub struct ChipAuthenticationPublicKeyInfo {
    /// Standardized domain parameter ID the key belongs to.
    pub parameter_id: Option<u64>,
    /// The public key, SEC1 encoded for ECDH.
    pub public_key: Vec<u8>,
    /// Distinguishes keys when the chip holds more than one.
    pub key_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum SecurityInfo {
    Pace(PaceInfo),
    Unknown(UnknownSecurityInfo),
}

#[derive(Debug, Clone)]
pub struct EFCardAccess {
    pub security_infos: Vec<SecurityInfo>,
}

impl EFCardAccess {
    /// Every PACEInfo entry the document offers.
    pub fn pace_infos(&self) -> Vec<&PaceInfo> {
        return self
            .security_infos
            .iter()
            .filter_map(|security_info| match security_info {
                SecurityInfo::Pace(pace_info) => Some(pace_info),
                _ => None,
            })
            .collect();
    }

    /// Whether the document offers PACE at all, regardless of whether we can
    /// actually run any of the variants it lists.
    pub fn supports_pace(&self) -> bool {
        return !self.pace_infos().is_empty();
    }
}

/// Every protocol object identifier BSI TR-03110 defines under `bsi-de`, with the name
/// the standard gives it.
///
/// EF.CardAccess is a set of SecurityInfos, and each one opens with one of these. Only
/// PACE is modelled in detail, because only PACE is something passauf can carry out —
/// but a document listing Chip Authentication or Restricted Identification is saying
/// something about itself, and printing a bare `0.4.0.127.0.7.2.2.2` at someone amounts
/// to withholding it.
///
/// Taken from the ASN.1 in TR-03110 Part 3 Annex A rather than typed out, and kept to
/// the `protocols(2) smartcard(2)` subtree: the auxiliary data identifiers under
/// `applications(3)` are what a terminal sends, not what a chip advertises.
const BSI_PROTOCOL_OIDS: &[(&str, &str)] = &[
    ("0.4.0.127.0.7.2.2.1", "id-PK"),
    ("0.4.0.127.0.7.2.2.1.1", "id-PK-DH"),
    ("0.4.0.127.0.7.2.2.1.2", "id-PK-ECDH"),
    ("0.4.0.127.0.7.2.2.2", "id-TA"),
    ("0.4.0.127.0.7.2.2.2.1", "id-TA-RSA"),
    ("0.4.0.127.0.7.2.2.2.1.1", "id-TA-RSA-v1-5-SHA-1"),
    ("0.4.0.127.0.7.2.2.2.1.2", "id-TA-RSA-v1-5-SHA-256"),
    ("0.4.0.127.0.7.2.2.2.1.3", "id-TA-RSA-PSS-SHA-1"),
    ("0.4.0.127.0.7.2.2.2.1.4", "id-TA-RSA-PSS-SHA-256"),
    ("0.4.0.127.0.7.2.2.2.1.5", "id-TA-RSA-v1-5-SHA-512"),
    ("0.4.0.127.0.7.2.2.2.1.6", "id-TA-RSA-PSS-SHA-512"),
    ("0.4.0.127.0.7.2.2.2.2", "id-TA-ECDSA"),
    ("0.4.0.127.0.7.2.2.2.2.1", "id-TA-ECDSA-SHA-1"),
    ("0.4.0.127.0.7.2.2.2.2.2", "id-TA-ECDSA-SHA-224"),
    ("0.4.0.127.0.7.2.2.2.2.3", "id-TA-ECDSA-SHA-256"),
    ("0.4.0.127.0.7.2.2.2.2.4", "id-TA-ECDSA-SHA-384"),
    ("0.4.0.127.0.7.2.2.2.2.5", "id-TA-ECDSA-SHA-512"),
    ("0.4.0.127.0.7.2.2.3", "id-CA"),
    ("0.4.0.127.0.7.2.2.3.1", "id-CA-DH"),
    ("0.4.0.127.0.7.2.2.3.1.1", "id-CA-DH-3DES-CBC-CBC"),
    ("0.4.0.127.0.7.2.2.3.1.2", "id-CA-DH-AES-CBC-CMAC-128"),
    ("0.4.0.127.0.7.2.2.3.1.3", "id-CA-DH-AES-CBC-CMAC-192"),
    ("0.4.0.127.0.7.2.2.3.1.4", "id-CA-DH-AES-CBC-CMAC-256"),
    ("0.4.0.127.0.7.2.2.3.2", "id-CA-ECDH"),
    ("0.4.0.127.0.7.2.2.3.2.1", "id-CA-ECDH-3DES-CBC-CBC"),
    ("0.4.0.127.0.7.2.2.3.2.2", "id-CA-ECDH-AES-CBC-CMAC-128"),
    ("0.4.0.127.0.7.2.2.3.2.3", "id-CA-ECDH-AES-CBC-CMAC-192"),
    ("0.4.0.127.0.7.2.2.3.2.4", "id-CA-ECDH-AES-CBC-CMAC-256"),
    ("0.4.0.127.0.7.2.2.4", "id-PACE"),
    ("0.4.0.127.0.7.2.2.4.1", "id-PACE-DH-GM"),
    ("0.4.0.127.0.7.2.2.4.1.1", "id-PACE-DH-GM-3DES-CBC-CBC"),
    ("0.4.0.127.0.7.2.2.4.1.2", "id-PACE-DH-GM-AES-CBC-CMAC-128"),
    ("0.4.0.127.0.7.2.2.4.1.3", "id-PACE-DH-GM-AES-CBC-CMAC-192"),
    ("0.4.0.127.0.7.2.2.4.1.4", "id-PACE-DH-GM-AES-CBC-CMAC-256"),
    ("0.4.0.127.0.7.2.2.4.2", "id-PACE-ECDH-GM"),
    ("0.4.0.127.0.7.2.2.4.2.1", "id-PACE-ECDH-GM-3DES-CBC-CBC"),
    (
        "0.4.0.127.0.7.2.2.4.2.2",
        "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
    ),
    (
        "0.4.0.127.0.7.2.2.4.2.3",
        "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
    ),
    (
        "0.4.0.127.0.7.2.2.4.2.4",
        "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
    ),
    ("0.4.0.127.0.7.2.2.4.3", "id-PACE-DH-IM"),
    ("0.4.0.127.0.7.2.2.4.3.1", "id-PACE-DH-IM-3DES-CBC-CBC"),
    ("0.4.0.127.0.7.2.2.4.3.2", "id-PACE-DH-IM-AES-CBC-CMAC-128"),
    ("0.4.0.127.0.7.2.2.4.3.3", "id-PACE-DH-IM-AES-CBC-CMAC-192"),
    ("0.4.0.127.0.7.2.2.4.3.4", "id-PACE-DH-IM-AES-CBC-CMAC-256"),
    ("0.4.0.127.0.7.2.2.4.4", "id-PACE-ECDH-IM"),
    ("0.4.0.127.0.7.2.2.4.4.1", "id-PACE-ECDH-IM-3DES-CBC-CBC"),
    (
        "0.4.0.127.0.7.2.2.4.4.2",
        "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
    ),
    (
        "0.4.0.127.0.7.2.2.4.4.3",
        "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
    ),
    (
        "0.4.0.127.0.7.2.2.4.4.4",
        "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
    ),
    ("0.4.0.127.0.7.2.2.5", "id-RI"),
    ("0.4.0.127.0.7.2.2.5.1", "id-RI-DH"),
    ("0.4.0.127.0.7.2.2.5.1.1", "id-RI-DH-SHA-1"),
    ("0.4.0.127.0.7.2.2.5.1.2", "id-RI-DH-SHA-224"),
    ("0.4.0.127.0.7.2.2.5.1.3", "id-RI-DH-SHA-256"),
    ("0.4.0.127.0.7.2.2.5.1.4", "id-RI-DH-SHA-384"),
    ("0.4.0.127.0.7.2.2.5.1.5", "id-RI-DH-SHA-512"),
    ("0.4.0.127.0.7.2.2.5.2", "id-RI-ECDH"),
    ("0.4.0.127.0.7.2.2.5.2.1", "id-RI-ECDH-SHA-1"),
    ("0.4.0.127.0.7.2.2.5.2.2", "id-RI-ECDH-SHA-224"),
    ("0.4.0.127.0.7.2.2.5.2.3", "id-RI-ECDH-SHA-256"),
    ("0.4.0.127.0.7.2.2.5.2.4", "id-RI-ECDH-SHA-384"),
    ("0.4.0.127.0.7.2.2.5.2.5", "id-RI-ECDH-SHA-512"),
    ("0.4.0.127.0.7.2.2.6", "id-CI"),
    ("0.4.0.127.0.7.2.2.7", "id-eIDSecurity"),
    ("0.4.0.127.0.7.2.2.8", "id-PT"),
    ("0.4.0.127.0.7.2.2.11", "id-PS"),
    ("0.4.0.127.0.7.2.2.11.1", "id-PSA"),
    ("0.4.0.127.0.7.2.2.11.1.2", "id-PSA-ECDH-ECSchnorr"),
    ("0.4.0.127.0.7.2.2.11.2", "id-PSM"),
    ("0.4.0.127.0.7.2.2.11.2.2", "id-PSM-ECDH-ECSchnorr"),
    ("0.4.0.127.0.7.2.2.11.3", "id-PSC"),
    ("0.4.0.127.0.7.2.2.11.3.2", "id-PSC-ECDH-ECSchnorr"),
    ("0.4.0.127.0.7.2.2.12", "id-PasswordType"),
    ("0.4.0.127.0.7.2.2.12.1", "id-MRZ"),
    ("0.4.0.127.0.7.2.2.12.2", "id-CAN"),
    ("0.4.0.127.0.7.2.2.12.3", "id-PIN"),
    ("0.4.0.127.0.7.2.2.12.4", "id-PUK"),
];

/// What each family of those identifiers is for, by prefix.
///
/// Longest prefix wins, so `id-PACE-ECDH-CAM` is Chip Authentication Mapping rather than
/// falling back to plain PACE.
const BSI_PROTOCOL_FAMILIES: &[(&str, &str)] = &[
    ("0.4.0.127.0.7.2.2.1", "Chip Authentication public key"),
    ("0.4.0.127.0.7.2.2.2", "Terminal Authentication"),
    ("0.4.0.127.0.7.2.2.3", "Chip Authentication"),
    ("0.4.0.127.0.7.2.2.4", "PACE"),
    ("0.4.0.127.0.7.2.2.5", "Restricted Identification"),
    ("0.4.0.127.0.7.2.2.6", "Card info locator"),
    ("0.4.0.127.0.7.2.2.7", "eID security"),
    ("0.4.0.127.0.7.2.2.8", "Privileged terminal"),
    ("0.4.0.127.0.7.2.2.11", "Pseudonymous signature"),
    ("0.4.0.127.0.7.2.2.12", "Password type"),
];

/// Name a SecurityInfo's protocol, given its object identifier in dotted form.
///
/// Returns the family it belongs to and the standard's own identifier, so it reads as
/// something and can still be looked up in TR-03110 exactly as written. None for
/// anything outside the tree, which is left to speak for itself as digits.
pub fn describe_protocol_oid(oid: &str) -> Option<String> {
    let name = BSI_PROTOCOL_OIDS
        .iter()
        .find(|(candidate, _)| *candidate == oid)
        .map(|(_, name)| *name)?;

    let family = BSI_PROTOCOL_FAMILIES
        .iter()
        .filter(|(prefix, _)| oid == *prefix || oid.starts_with(&format!("{}.", prefix)))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, family)| *family);

    // "PACE (id-PACE)" says the same thing twice. Compared without the id- prefix,
    // which is the only difference in the cases where that happens.
    let repeats = family.is_some_and(|family| {
        family.eq_ignore_ascii_case(name.strip_prefix("id-").unwrap_or(name))
    });

    return Some(match family {
        // The readable one of the two, rather than the spelling with the prefix.
        Some(family) if repeats => family.to_string(),
        Some(family) => format!("{} ({})", family, name),
        None => name.to_string(),
    });
}

/// Render an object identifier's DER value bytes in dotted notation.
///
/// The first byte packs the first two arcs as `40 * first + second`, and every
/// arc after that is base-128 with the high bit marking continuation.
pub fn format_oid(oid_bytes: &[u8]) -> String {
    if oid_bytes.is_empty() {
        return String::new();
    }
    let mut arcs = vec![
        (oid_bytes[0] / 40).to_string(),
        (oid_bytes[0] % 40).to_string(),
    ];
    let mut current: u64 = 0;
    for byte in &oid_bytes[1..] {
        current = (current << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            arcs.push(current.to_string());
            current = 0;
        }
    }
    return arcs.join(".");
}

impl fmt::Display for PaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} (version {})", self.algorithm, self.version)?;
        return match self.parameter_id {
            Some(parameter_id) => write!(f, ", domain parameter {}", parameter_id),
            None => Ok(()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one the app was showing as bare digits.
    #[test]
    fn names_the_protocols_a_document_advertises() {
        assert_eq!(
            describe_protocol_oid("0.4.0.127.0.7.2.2.2"),
            Some("Terminal Authentication (id-TA)".to_string())
        );
        assert_eq!(
            describe_protocol_oid("0.4.0.127.0.7.2.2.3.2.4"),
            Some("Chip Authentication (id-CA-ECDH-AES-CBC-CMAC-256)".to_string())
        );
        assert_eq!(
            describe_protocol_oid("0.4.0.127.0.7.2.2.1.2"),
            Some("Chip Authentication public key (id-PK-ECDH)".to_string())
        );
        assert_eq!(
            describe_protocol_oid("0.4.0.127.0.7.2.2.12.2"),
            Some("Password type (id-CAN)".to_string())
        );
    }

    /// A family whose own name is the family reads once, not twice.
    #[test]
    fn does_not_repeat_itself() {
        assert_eq!(
            describe_protocol_oid("0.4.0.127.0.7.2.2.4"),
            Some("PACE".to_string())
        );
    }

    /// Anything outside the tree is left as digits rather than guessed at.
    #[test]
    fn says_nothing_about_identifiers_it_does_not_know() {
        assert_eq!(describe_protocol_oid("1.2.840.10045.2.1"), None);
        assert_eq!(describe_protocol_oid("0.4.0.127.0.7.2.2.99"), None);
        // A prefix of a known one is not a known one.
        assert_eq!(describe_protocol_oid("0.4.0.127.0.7.2.2"), None);
    }

    #[test]
    fn formats_object_identifiers() {
        // The PACE-ECDH-GM-AES-CBC-CMAC-128 OID from Appendix G.1.
        assert_eq!(
            format_oid(&[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02]),
            "0.4.0.127.0.7.2.2.4.2.2"
        );
        // id-ecPublicKey, which uses multi-byte arcs.
        assert_eq!(
            format_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
            "1.2.840.10045.2.1"
        );
        assert_eq!(format_oid(&[]), "");
    }
}
