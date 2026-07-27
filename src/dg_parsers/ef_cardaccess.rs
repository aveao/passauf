use iso7816_tlv::ber;
use simplelog::{debug, info, warn};

use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers;
use crate::pace::oids::PaceAlgorithm;
use crate::types;
use crate::types::ef_cardaccess::{
    format_oid, EFCardAccess, PaceInfo, SecurityInfo, UnknownSecurityInfo,
};

/// DER tags used inside SecurityInfos.
const TAG_SEQUENCE: u16 = 0x30;
const TAG_SET: u16 = 0x31;
const TAG_OBJECT_IDENTIFIER: u16 = 0x06;
const TAG_INTEGER: u16 = 0x02;

/// Why we cannot run a PACEInfo, covering both the algorithm and its domain
/// parameters.
fn unsupported_reason(pace_info: &PaceInfo) -> Option<String> {
    if let Some(reason) = pace_info.algorithm.unsupported_reason() {
        return Some(reason.to_string());
    }

    let parameter_id = pace_info.parameter_id?;
    let parameter = match crate::pace::domain::from_parameter_id(parameter_id) {
        Some(parameter) => parameter,
        None => {
            return Some(format!(
                "domain parameter {} is reserved for future use",
                parameter_id
            ))
        }
    };
    return parameter
        .unsupported_reason()
        .map(|reason| format!("{}: {}", parameter, reason));
}

impl types::EFCardAccess {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);

        for security_info in self.security_infos.iter() {
            match security_info {
                SecurityInfo::Pace(pace_info) => {
                    // Say so up front rather than letting the user find out when
                    // authentication fails. Both the algorithm and the domain
                    // parameters can be ones we don't implement.
                    let support = match unsupported_reason(pace_info) {
                        Some(reason) => format!(" <red>(unsupported: {})</>", reason),
                        None => String::new(),
                    };
                    info!(
                        "{:>pad_len$} <yellow>{}</>{}",
                        "PACEInfo",
                        pace_info,
                        support,
                        pad_len = 15
                    );
                }
                SecurityInfo::Unknown(unknown) => {
                    info!(
                        "{:>pad_len$} <yellow>{}</>",
                        "SecurityInfo",
                        format_oid(&unknown.protocol),
                        pad_len = 15
                    );
                }
            }
        }
        info!("");
    }
}

/// Read an INTEGER's value as an unsigned integer.
///
/// Returns None for negative or oversized values, neither of which any field
/// we read here is allowed to be.
fn parse_unsigned_integer(tlv: &ber::Tlv) -> Option<u64> {
    let value_bytes = helpers::get_tlv_value_bytes(tlv);
    if value_bytes.is_empty() {
        return None;
    }
    // DER pads with a leading zero to keep a high bit from meaning negative.
    let significant = match value_bytes[0] {
        0x00 => &value_bytes[1..],
        // A set high bit without that padding means the value is negative.
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

/// Parse one SecurityInfo entry.
fn parse_security_info(sequence: &ber::Tlv) -> Option<SecurityInfo> {
    let fields = helpers::get_tlv_constructed_value(sequence);
    // protocol is mandatory and comes first.
    let protocol_tlv = fields.first()?;
    if helpers::get_tlv_tag(protocol_tlv) != TAG_OBJECT_IDENTIFIER {
        return None;
    }
    let protocol = helpers::get_tlv_value_bytes(protocol_tlv);

    let algorithm = match PaceAlgorithm::from_oid_bytes(&protocol) {
        Some(algorithm) => algorithm,
        // Not a PACE OID. Terminal Authentication, Chip Authentication and the
        // rest all land here.
        None => {
            return Some(SecurityInfo::Unknown(UnknownSecurityInfo { protocol }));
        }
    };

    // For PACEInfo, requiredData is the version and optionalData the parameter
    // ID, both INTEGERs.
    let integers: Vec<u64> = fields[1..]
        .iter()
        .filter(|tlv| helpers::get_tlv_tag(tlv) == TAG_INTEGER)
        .filter_map(parse_unsigned_integer)
        .collect();

    let version = match integers.first() {
        Some(version) => *version,
        None => {
            warn!(
                "PACEInfo for {} has no version, skipping it.",
                format_oid(&protocol)
            );
            return None;
        }
    };

    return Some(SecurityInfo::Pace(PaceInfo {
        algorithm,
        version,
        parameter_id: integers.get(1).copied(),
    }));
}

pub fn parser(
    data: &Vec<u8>,
    data_group: &types::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    // EF.CardAccess is a bare SET, with no enclosing application tag of its own.
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    debug!("base_tlv: {:02x?}", &base_tlv);

    let base_tlv_tag = helpers::get_tlv_tag(&base_tlv);
    if base_tlv_tag != TAG_SET {
        warn!(
            "Found {}'s TLV tag as 0x{:02x} (expected 0x{:02x}), skipping parsing.",
            data_group.name, base_tlv_tag, TAG_SET
        );
        return None;
    }

    let mut security_infos: Vec<SecurityInfo> = vec![];
    for entry in helpers::get_tlv_constructed_value(&base_tlv).iter() {
        if helpers::get_tlv_tag(entry) != TAG_SEQUENCE {
            warn!(
                "Skipping a SecurityInfos entry with unexpected tag 0x{:02x}.",
                helpers::get_tlv_tag(entry)
            );
            continue;
        }
        match parse_security_info(entry) {
            Some(security_info) => security_infos.push(security_info),
            None => {}
        }
    }

    let result = EFCardAccess { security_infos };
    debug!("EF.CardAccess: {:02x?}", result);

    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFCardAccess(result));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pace::oids::{KeyAgreement, Mapping};
    use crate::secure_messaging::SmAlgorithm;

    fn parse(data: Vec<u8>) -> EFCardAccess {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFCardAccess as usize];
        match parser(&data, data_group, false).unwrap() {
            types::ParsedDataGroup::EFCardAccess(parsed) => parsed,
            other => panic!("Expected EFCardAccess but got {:?}", other),
        }
    }

    /// ICAO 9303 p11 Appendix G.1 quotes this PACEInfo in full:
    /// PACE with ECDH, generic mapping, AES-128, on BrainpoolP256r1.
    #[test]
    fn parses_worked_example_pace_info() {
        let parsed = parse(vec![
            0x31, 0x14, // SET
            0x30, 0x12, // SEQUENCE
            0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, // OID
            0x02, 0x01, 0x02, // version 2
            0x02, 0x01, 0x0D, // parameter 13, BrainpoolP256r1
        ]);

        assert!(parsed.supports_pace());
        let pace_infos = parsed.pace_infos();
        assert_eq!(pace_infos.len(), 1);
        assert_eq!(pace_infos[0].version, 2);
        assert_eq!(pace_infos[0].parameter_id, Some(13));
        assert_eq!(pace_infos[0].algorithm.key_agreement, KeyAgreement::Ecdh);
        assert_eq!(pace_infos[0].algorithm.mapping, Mapping::Generic);
        assert_eq!(pace_infos[0].algorithm.cipher, SmAlgorithm::Aes128);
    }

    /// Appendix G.2's PACEInfo, which selects a MODP group instead.
    #[test]
    fn parses_dh_pace_info() {
        let parsed = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x01, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
        ]);
        let pace_infos = parsed.pace_infos();
        assert_eq!(pace_infos[0].algorithm.key_agreement, KeyAgreement::Dh);
        // Parameter 0 must survive, rather than being lost as a falsy value.
        assert_eq!(pace_infos[0].parameter_id, Some(0));
    }

    /// The parameter ID is optional, and its absence is meaningful.
    #[test]
    fn parses_pace_info_without_parameter_id() {
        let parsed = parse(vec![
            0x31, 0x11, 0x30, 0x0F, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x02, 0x02, 0x02, 0x01, 0x02,
        ]);
        let pace_infos = parsed.pace_infos();
        assert_eq!(pace_infos[0].version, 2);
        assert_eq!(pace_infos[0].parameter_id, None);
    }

    /// A real document lists several PACEInfos plus entries for other
    /// protocols. The non-PACE ones must be kept, not silently dropped.
    #[test]
    fn keeps_non_pace_security_infos() {
        let parsed = parse(vec![
            0x31, 0x28, // SET
            // PACEInfo
            0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02,
            0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
            // ChipAuthenticationInfo, not a PACE OID
            0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02,
            0x02, 0x01, 0x01, 0x02, 0x01, 0x0D,
        ]);
        assert_eq!(parsed.security_infos.len(), 2);
        assert_eq!(parsed.pace_infos().len(), 1);
        assert!(matches!(parsed.security_infos[1], SecurityInfo::Unknown(_)));
    }

    /// A document with no PACEInfo at all is a BAC-only document.
    #[test]
    fn reports_no_pace_when_absent() {
        let parsed = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03,
            0x02, 0x02, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0D,
        ]);
        assert!(!parsed.supports_pace());
        assert_eq!(parsed.pace_infos().len(), 0);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_set() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFCardAccess as usize];
        // A SEQUENCE where a SET belongs.
        assert!(parser(&vec![0x30, 0x02, 0x02, 0x00], data_group, false).is_none());
    }

    #[test]
    fn reads_multi_byte_and_padded_integers() {
        // A parameter ID of 128 needs DER's leading zero so the high bit isn't
        // read as a sign bit.
        let parsed = parse(vec![
            0x31, 0x15, // SET, 21 bytes
            0x30, 0x13, // SEQUENCE, 19 bytes
            0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, // OID
            0x02, 0x01, 0x02, // version 2
            0x02, 0x02, 0x00, 0x80, // parameter 128, zero-padded
        ]);
        assert_eq!(parsed.pace_infos()[0].parameter_id, Some(128));
    }

    /// A negative INTEGER is not a valid parameter ID, so it must be rejected
    /// rather than wrapping around into a plausible-looking one.
    #[test]
    fn rejects_negative_integers() {
        let parsed = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x02, 0x02, 0x02, 0x01, 0x02, // version 2
            0x02, 0x01, 0x80, // -128
        ]);
        // The version still reads, but the bad parameter ID is dropped.
        assert_eq!(parsed.pace_infos()[0].version, 2);
        assert_eq!(parsed.pace_infos()[0].parameter_id, None);
    }

    /// The display must flag unsupported domain parameters, not just
    /// unsupported mappings, so the user sees why before authentication runs.
    #[test]
    fn flags_both_kinds_of_unsupported_variant() {
        // Chip Authentication Mapping, which we recognize but do not perform.
        let cam = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x06, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
        ]);
        let reason = unsupported_reason(cam.pace_infos()[0]).unwrap();
        assert!(reason.contains("PACE-CAM"), "{}", reason);

        // A supported mapping on BrainpoolP512r1, which has no Rust crate.
        let unavailable_curve = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x11,
        ]);
        let reason = unsupported_reason(unavailable_curve.pace_infos()[0]).unwrap();
        assert!(reason.contains("BrainpoolP512r1"), "{}", reason);

        // And one we can actually run.
        let supported = parse(vec![
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
        ]);
        assert!(unsupported_reason(supported.pace_infos()[0]).is_none());
    }
}
