///! Shared parsing for the SecurityInfos structure (ICAO 9303 p11 section 9.2)
///
/// The same `SecurityInfos ::= SET OF SecurityInfo` turns up in three places:
/// bare in EF.CardAccess, wrapped in tag 0x6E in DG14, and inside the CMS
/// eContent of EF.CardSecurity. Only the wrapping differs, so the entry
/// parsing lives here.
use iso7816_tlv::ber;
use simplelog::{debug, warn};

use crate::helpers::{self, parse_unsigned_integer};
use crate::types::ef_cardaccess::{format_oid, ChipAuthenticationPublicKeyInfo};

/// DER tags used inside SecurityInfos.
pub const TAG_SEQUENCE: u16 = 0x30;
pub const TAG_SET: u16 = 0x31;
pub const TAG_OBJECT_IDENTIFIER: u16 = 0x06;
pub const TAG_INTEGER: u16 = 0x02;
pub const TAG_BIT_STRING: u16 = 0x03;

/// id-PK-ECDH, `0.4.0.127.0.7.2.2.1.2` (ICAO 9303 p11 section 9.2.6).
const OID_PK_ECDH: [u8; 9] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02];
/// id-PK-DH, `0.4.0.127.0.7.2.2.1.1`.
const OID_PK_DH: [u8; 9] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x01];

/// Parse a ChipAuthenticationPublicKeyInfo.
///
/// ```text
/// ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
///     protocol                    OBJECT IDENTIFIER,
///     chipAuthenticationPublicKey SubjectPublicKeyInfo,
///     keyId                       INTEGER OPTIONAL
/// }
/// ```
///
/// The SubjectPublicKeyInfo holds an AlgorithmIdentifier naming the domain
/// parameters and a BIT STRING holding the key itself.
fn parse_chip_authentication_public_key(
    fields: &Vec<ber::Tlv>,
) -> Option<ChipAuthenticationPublicKeyInfo> {
    // chipAuthenticationPublicKey is the SubjectPublicKeyInfo sequence.
    let subject_public_key_info = fields
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_SEQUENCE)?;
    let spki_fields = helpers::get_tlv_constructed_value(subject_public_key_info);

    // The AlgorithmIdentifier names the domain parameters. A standardized set
    // is an OID plus a parameter ID; explicit parameters nest them a level
    // deeper, so no ID is found and none is reported.
    let algorithm_identifier = spki_fields
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_SEQUENCE);
    let parameter_id = match algorithm_identifier {
        Some(algorithm_identifier) => helpers::get_tlv_constructed_value(algorithm_identifier)
            .iter()
            .filter(|tlv| helpers::get_tlv_tag(tlv) == TAG_INTEGER)
            .find_map(parse_unsigned_integer),
        None => None,
    };

    let key_bit_string = spki_fields
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_BIT_STRING)?;
    let key_bytes = helpers::get_tlv_value_bytes(key_bit_string);
    // A BIT STRING's first content byte counts the unused trailing bits, which
    // is always zero for a key encoded in whole octets.
    if key_bytes.is_empty() || key_bytes[0] != 0x00 {
        return None;
    }

    // keyId, when present, is the INTEGER sitting beside the SubjectPublicKeyInfo
    // rather than inside it.
    let key_id = fields
        .iter()
        .filter(|tlv| helpers::get_tlv_tag(tlv) == TAG_INTEGER)
        .find_map(parse_unsigned_integer);

    return Some(ChipAuthenticationPublicKeyInfo {
        parameter_id,
        public_key: key_bytes[1..].to_vec(),
        key_id,
    });
}

/// Collect every chip authentication public key in a SecurityInfos SET.
///
/// `security_infos` is the SET's children, i.e. one SEQUENCE per SecurityInfo.
pub fn parse_chip_authentication_public_keys(
    security_infos: &Vec<ber::Tlv>,
) -> Vec<ChipAuthenticationPublicKeyInfo> {
    let mut keys: Vec<ChipAuthenticationPublicKeyInfo> = vec![];

    for entry in security_infos.iter() {
        if helpers::get_tlv_tag(entry) != TAG_SEQUENCE {
            continue;
        }
        let fields = helpers::get_tlv_constructed_value(entry);
        let protocol_tlv = match fields.first() {
            Some(tlv) if helpers::get_tlv_tag(tlv) == TAG_OBJECT_IDENTIFIER => tlv,
            _ => continue,
        };
        let protocol = helpers::get_tlv_value_bytes(protocol_tlv);

        if protocol == OID_PK_ECDH {
            match parse_chip_authentication_public_key(&fields) {
                Some(key_info) => keys.push(key_info),
                None => warn!("Could not parse a ChipAuthenticationPublicKeyInfo, skipping it."),
            }
        } else if protocol == OID_PK_DH {
            // Chip Authentication Mapping is ECDH-only, so a DH key is of no
            // use to us even though the structure is the same.
            debug!("Skipping a DH chip authentication public key.");
        } else {
            debug!("Skipping SecurityInfo {}", format_oid(&protocol));
        }
    }

    return keys;
}

/// Work out which curve a key sits on by testing the point against each one.
///
/// A chip that spells its curve out as explicit domain parameters names no
/// parameter ID, so the point itself is the only thing left to go on. Two
/// curves of the same size could in principle both accept a point, so this is
/// a good guess rather than a guarantee.
pub fn identify_curve(public_key: &[u8]) -> Option<crate::pace::domain::EcCurve> {
    use crate::pace::domain::EcCurve;

    for curve in [
        EcCurve::NistP256,
        EcCurve::BrainpoolP256r1,
        EcCurve::NistP384,
        EcCurve::BrainpoolP384r1,
        EcCurve::NistP521,
    ] {
        if crate::pace::ecdh::ops_for(curve).is_some_and(|ops| ops.validate_point(public_key)) {
            return Some(curve);
        }
    }
    return None;
}

/// Describe a key's domain parameters for display.
///
/// A chip naming a standardized set is reported as such; one spelling its
/// curve out gets the curve identified from the key, since saying only that it
/// used explicit parameters tells the reader nothing useful.
pub fn describe_domain_parameters(key_info: &ChipAuthenticationPublicKeyInfo) -> String {
    return match key_info.parameter_id {
        Some(parameter_id) => match crate::pace::domain::from_parameter_id(parameter_id) {
            Some(parameter) => format!("{}", parameter),
            None => format!("domain parameter {}", parameter_id),
        },
        None => match identify_curve(&key_info.public_key) {
            Some(curve) => format!("{} by explicit domain parameters", curve),
            None => "explicit domain parameters, unrecognized curve".to_string(),
        },
    };
}
