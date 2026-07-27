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
