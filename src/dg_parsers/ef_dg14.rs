use iso7816_tlv::ber;
use simplelog::{debug, info, warn};

use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::types;
use crate::types::ef_cardaccess::{format_oid, ChipAuthenticationPublicKeyInfo};

/// DER tags used inside SecurityInfos.
const TAG_SEQUENCE: u16 = 0x30;
const TAG_SET: u16 = 0x31;
const TAG_OBJECT_IDENTIFIER: u16 = 0x06;
const TAG_INTEGER: u16 = 0x02;
const TAG_BIT_STRING: u16 = 0x03;

/// id-PK-ECDH, `0.4.0.127.0.7.2.2.1.2` (ICAO 9303 p11 section 9.2.6).
const OID_PK_ECDH: [u8; 9] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02];
/// id-PK-DH, `0.4.0.127.0.7.2.2.1.1`.
const OID_PK_DH: [u8; 9] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x01];

/// Work out which curve a key sits on by testing the point against each one.
///
/// A chip that spells its curve out as explicit domain parameters names no
/// parameter ID, so the point itself is the only thing left to go on. Two
/// curves of the same size could in principle both accept a point, so this is
/// a good guess rather than a guarantee.
#[cfg(feature = "pace")]
fn identify_curve(public_key: &[u8]) -> Option<crate::pace::domain::EcCurve> {
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

impl types::EFDG14 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);

        for key_info in self.chip_authentication_public_keys.iter() {
            let parameters = match key_info.parameter_id {
                Some(parameter_id) => match crate::pace::domain::from_parameter_id(parameter_id) {
                    Some(parameter) => format!("{}", parameter),
                    None => format!("domain parameter {}", parameter_id),
                },
                // Naming the curve is far more use than saying the chip didn't
                // name it, so identify it from the key.
                None => match identify_curve(&key_info.public_key) {
                    Some(curve) => format!("{} by explicit domain parameters", curve),
                    None => "explicit domain parameters, unrecognized curve".to_string(),
                },
            };
            // The key ID only matters when the chip holds more than one key.
            let key_id = match key_info.key_id {
                Some(key_id) => format!(", key {}", key_id),
                None => String::new(),
            };
            info!(
                "{:>pad_len$} <yellow>{}{} ({} bytes)</>",
                "CA public key",
                parameters,
                key_id,
                key_info.public_key.len(),
                pad_len = 15
            );
        }
        info!("");
    }
}

/// Read an INTEGER's value as an unsigned integer.
fn parse_unsigned_integer(tlv: &ber::Tlv) -> Option<u64> {
    let value_bytes = helpers::get_tlv_value_bytes(tlv);
    if value_bytes.is_empty() {
        return None;
    }
    let significant = match value_bytes[0] {
        0x00 => &value_bytes[1..],
        0x80..=0xFF => return None,
        _ => &value_bytes[..],
    };
    if significant.len() > 8 {
        return None;
    }
    let mut result: u64 = 0;
    for byte in significant {
        result = (result << 8) | u64::from(*byte);
    }
    return Some(result);
}

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

    // The AlgorithmIdentifier names the domain parameters. We only handle the
    // standardized ones, which are given as an OID plus a parameter ID.
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

pub fn parser(
    data: &Vec<u8>,
    data_group: &types::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_tag = helpers::get_tlv_tag(&base_tlv);
    if base_tlv_tag != data_group.tag.into() {
        warn!(
            "Found {}'s TLV tag as 0x{:02x} (expected 0x{:02x}), skipping parsing.",
            data_group.name, base_tlv_tag, data_group.tag
        );
        return None;
    }

    // Inside the data group tag sits a SecurityInfos SET, the same structure
    // EF.CardAccess uses.
    let security_infos = helpers::get_tlv_constructed_value(&base_tlv);
    let security_infos = match security_infos
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_SET)
    {
        Some(set) => helpers::get_tlv_constructed_value(set),
        None => {
            warn!(
                "{} holds no SecurityInfos, skipping parsing.",
                data_group.name
            );
            return None;
        }
    };

    let mut chip_authentication_public_keys: Vec<ChipAuthenticationPublicKeyInfo> = vec![];
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
                Some(key_info) => chip_authentication_public_keys.push(key_info),
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

    let result = types::EFDG14 {
        chip_authentication_public_keys,
    };
    debug!("EF.DG14: {:02x?}", result);

    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFDG14(result));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect();
    }

    /// Build the SEC1 encoding of a point from its two coordinates.
    fn point(x: &str, y: &str) -> Vec<u8> {
        return vec![vec![0x04], hex(x), hex(y)].concat();
    }

    fn parse(data: Vec<u8>) -> types::EFDG14 {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFDg14 as usize];
        match parser(&data, data_group, false).unwrap() {
            types::ParsedDataGroup::EFDG14(parsed) => parsed,
            other => panic!("Expected EFDG14 but got {:?}", other),
        }
    }

    /// ICAO 9303 p11 Appendix I quotes the ChipAuthenticationPublicKeyInfo it
    /// reads out of EF.CardSecurity. DG14 wraps the same structure in tag 0x6E
    /// and a SecurityInfos SET.
    #[test]
    fn parses_worked_example_public_key() {
        let key_info = hex("30620609 04007F00 07020201 02305230
             0C060704 007F0007 01020201 0D034200
             04187270 9494399E 7470A643 1BE25E83
             EEE24FEA 568C2ED2 8DB48E05 DB3A610D
             C884D256 A40E35EF CB59BF67 53D3A489
             D28C7A4D 973C2DA1 38A6E7A4 A08F68E1
             6F02010D");
        // Wrap it: 6E <len> 31 <len> <ChipAuthenticationPublicKeyInfo>
        let set = vec![vec![0x31, key_info.len() as u8], key_info.clone()].concat();
        let dg14 = vec![vec![0x6E, set.len() as u8], set].concat();

        let parsed = parse(dg14);
        assert_eq!(parsed.chip_authentication_public_keys.len(), 1);
        let key = &parsed.chip_authentication_public_keys[0];

        // BrainpoolP256r1, and keyID 13 as the appendix notes.
        assert_eq!(key.parameter_id, Some(13));
        assert_eq!(key.key_id, Some(13));
        // The key itself, an uncompressed SEC1 point.
        assert_eq!(
            key.public_key,
            hex(
                "041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8
                 84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F"
            )
        );
        // And it has to be a real point on the curve it names.
        let ops =
            crate::pace::ecdh::ops_for(crate::pace::domain::EcCurve::BrainpoolP256r1).unwrap();
        assert!(ops.validate_point(&key.public_key));
    }

    /// A chip may spell its curve out as explicit domain parameters rather
    /// than naming a standardized one, in which case there is no parameter ID
    /// to report. The key itself must still come out intact, since that is all
    /// a PACE-CAM check needs.
    #[test]
    fn parses_a_key_with_explicit_domain_parameters() {
        use crate::helpers::encode_ber;

        // ECParameters spelled out, rather than a standardized parameter ID.
        // Only its shape matters here: the INTEGERs sit one level deeper than a
        // parameter ID would, so none is directly beside the OID.
        let ec_parameters = encode_ber(&[0x30], &hex("020101020101"));
        let algorithm_identifier = encode_ber(
            &[0x30],
            &vec![encode_ber(&[0x06], &hex("2A8648CE3D0201")), ec_parameters].concat(),
        );
        // The BIT STRING's leading 0x00 counts unused trailing bits.
        let subject_public_key = encode_ber(
            &[0x03],
            &vec![
                hex("00"),
                point(
                    "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8",
                    "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F",
                ),
            ]
            .concat(),
        );
        let subject_public_key_info = encode_ber(
            &[0x30],
            &vec![algorithm_identifier, subject_public_key].concat(),
        );
        let key_info = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x06], &hex("04007F000702020102")),
                subject_public_key_info,
            ]
            .concat(),
        );
        let dg14 = encode_ber(&[0x6E], &encode_ber(&[0x31], &key_info));

        let parsed = parse(dg14);
        assert_eq!(parsed.chip_authentication_public_keys.len(), 1);
        let key = &parsed.chip_authentication_public_keys[0];

        // No standardized parameter ID, but the key is there and usable.
        assert_eq!(key.parameter_id, None);
        assert_eq!(key.public_key.len(), 65);
        let ops =
            crate::pace::ecdh::ops_for(crate::pace::domain::EcCurve::BrainpoolP256r1).unwrap();
        assert!(ops.validate_point(&key.public_key));
    }

    /// The curve is identified from the key when the chip names no parameter
    /// ID. This is the key off a real Reiseausweis für Ausländer, which uses
    /// explicit domain parameters.
    #[test]
    fn identifies_the_curve_of_a_real_key() {
        let public_key = point(
            "66AEE03B01264B94FD48AE5155F7159FC9D80BA512DE7E3350A0582D07B1C138",
            "575312399D0C86A16B7AA7FAB00C42118E1DE4055F1385DBBE2D1F246A6CFAF2",
        );
        assert_eq!(
            identify_curve(&public_key),
            Some(crate::pace::domain::EcCurve::BrainpoolP256r1)
        );

        // Appendix I's key, on the same curve.
        assert_eq!(
            identify_curve(&point(
                "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8",
                "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F",
            )),
            Some(crate::pace::domain::EcCurve::BrainpoolP256r1)
        );

        // Something that is on no curve we know.
        let mut off_curve = public_key.clone();
        let last = off_curve.len() - 1;
        off_curve[last] ^= 0x01;
        assert_eq!(identify_curve(&off_curve), None);
        assert_eq!(identify_curve(&[]), None);
    }

    /// A DG14 with only unrelated SecurityInfos yields no keys rather than
    /// failing to parse.
    #[test]
    fn ignores_security_infos_that_are_not_public_keys() {
        // A ChipAuthenticationInfo (id-CA-ECDH, version 1, keyId 13), which is
        // not a public key entry.
        let entry = hex("3011
             0609 04007F000702020302
             020101
             02010D");
        let set = vec![vec![0x31, entry.len() as u8], entry].concat();
        let dg14 = vec![vec![0x6E, set.len() as u8], set].concat();
        assert_eq!(parse(dg14).chip_authentication_public_keys.len(), 0);
    }

    #[test]
    fn rejects_a_file_with_the_wrong_tag() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFDg14 as usize];
        // 0x6F where 0x6E belongs.
        assert!(parser(&vec![0x6F, 0x02, 0x31, 0x00], data_group, false).is_none());
    }
}
