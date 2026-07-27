///! EF.SOD, the Document Security Object (ICAO 9303 p10 section 4.6.2)
///
/// EF.SOD is a CMS SignedData whose eContent is an LDSSecurityObject:
///
/// ```text
/// LDSSecurityObject ::= SEQUENCE {
///     version              LDSSecurityObjectVersion,
///     hashAlgorithm        DigestAlgorithmIdentifier,
///     dataGroupHashValues  SEQUENCE OF DataGroupHash,
///     ldsVersionInfo       LDSVersionInfo OPTIONAL }
///
/// DataGroupHash ::= SEQUENCE {
///     dataGroupNumber      DataGroupNumber,
///     dataGroupHashValue   OCTET STRING }
/// ```
///
/// Comparing those hashes against the data groups actually read proves the two
/// agree with each other. It does not prove either is genuine: the signature
/// over this object is *not* verified, which would need the issuing country's
/// certificates. See the note in the README about Passive Authentication.
use iso7816_tlv::ber;
#[cfg(feature = "cli")]
use simplelog::info;
use simplelog::{debug, warn};

use crate::dg_parsers::cms;
#[cfg(feature = "cli")]
use crate::dg_parsers::helpers as dg_helpers;
use crate::helpers::{self, parse_unsigned_integer};
use crate::icao9303::DocumentHashAlgorithm;
use crate::types;
use crate::types::parsed_data_groups::DataGroupHash;

const TAG_SEQUENCE: u16 = 0x30;
const TAG_OBJECT_IDENTIFIER: u16 = 0x06;
const TAG_OCTET_STRING: u16 = 0x04;

impl types::EFSOD {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);

        info!(
            "{:>pad_len$} <yellow>{}</>",
            "Hash algorithm",
            self.hash_algorithm,
            pad_len = 15
        );
        for data_group_hash in self.data_group_hashes.iter() {
            info!(
                "{:>pad_len$} <yellow>{}</>",
                format!("DG{}", data_group_hash.data_group_number),
                data_group_hash
                    .hash
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>(),
                pad_len = 15
            );
        }
        info!("<d>The signature on this object is not verified.</>");
        info!("");
    }
}

/// Parse the LDSSecurityObject out of the eContent bytes.
fn parse_lds_security_object(e_content: &[u8]) -> Option<types::EFSOD> {
    let lds_security_object = ber::Tlv::parse(e_content).0.ok()?;
    if helpers::get_tlv_tag(&lds_security_object) != TAG_SEQUENCE {
        return None;
    }
    let fields = helpers::get_tlv_constructed_value(&lds_security_object);

    // hashAlgorithm is an AlgorithmIdentifier, so a SEQUENCE opening with the
    // digest's OID.
    let algorithm_identifier = fields
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_SEQUENCE)?;
    let algorithm_oid = helpers::get_tlv_constructed_value(algorithm_identifier)
        .iter()
        .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_OBJECT_IDENTIFIER)
        .map(helpers::get_tlv_value_bytes)?;
    let hash_algorithm = match DocumentHashAlgorithm::from_oid_bytes(&algorithm_oid) {
        Some(hash_algorithm) => hash_algorithm,
        None => {
            // Guessing here would silently compare against the wrong digest, so
            // refuse instead.
            warn!("EF.SOD uses an unrecognized hash algorithm, so its hashes cannot be checked.");
            return None;
        }
    };

    // dataGroupHashValues is the SEQUENCE OF, i.e. the second SEQUENCE.
    let hash_values = fields
        .iter()
        .filter(|tlv| helpers::get_tlv_tag(tlv) == TAG_SEQUENCE)
        .nth(1)?;

    let mut data_group_hashes: Vec<DataGroupHash> = vec![];
    for entry in helpers::get_tlv_constructed_value(hash_values).iter() {
        if helpers::get_tlv_tag(entry) != TAG_SEQUENCE {
            continue;
        }
        let entry_fields = helpers::get_tlv_constructed_value(entry);
        let data_group_number = entry_fields.first().and_then(parse_unsigned_integer);
        let hash = entry_fields
            .iter()
            .find(|tlv| helpers::get_tlv_tag(tlv) == TAG_OCTET_STRING)
            .map(helpers::get_tlv_value_bytes);

        match (data_group_number, hash) {
            (Some(data_group_number), Some(hash)) => data_group_hashes.push(DataGroupHash {
                data_group_number,
                hash,
            }),
            _ => warn!("Skipping a malformed DataGroupHash in EF.SOD."),
        }
    }

    if data_group_hashes.is_empty() {
        return None;
    }
    return Some(types::EFSOD {
        hash_algorithm,
        data_group_hashes,
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
    if base_tlv_tag != u16::from(data_group.tag) {
        warn!(
            "Found {}'s TLV tag as 0x{:02x} (expected 0x{:02x}), skipping parsing.",
            data_group.name, base_tlv_tag, data_group.tag
        );
        return None;
    }

    let e_content = match cms::find_e_content(&base_tlv, &cms::OID_LDS_SECURITY_OBJECT) {
        Some(e_content) => e_content,
        None => {
            warn!(
                "Could not find an LDSSecurityObject inside {}, skipping parsing.",
                data_group.name
            );
            return None;
        }
    };

    let result = match parse_lds_security_object(&e_content) {
        Some(result) => result,
        None => {
            warn!("Could not parse {}'s LDSSecurityObject.", data_group.name);
            return None;
        }
    };
    debug!("EF.SOD: {:02x?}", result);

    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFSOD(result));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::encode_ber;

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect();
    }

    /// Build an EF.SOD around the given data group hashes.
    fn build_sod(algorithm_oid: &str, hashes: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut hash_entries = vec![];
        for (number, hash) in hashes {
            hash_entries.extend_from_slice(&encode_ber(
                &[0x30],
                &vec![
                    encode_ber(&[0x02], &vec![*number]),
                    encode_ber(&[0x04], hash),
                ]
                .concat(),
            ));
        }
        let lds_security_object = encode_ber(
            &[0x30],
            &vec![
                // version 0
                encode_ber(&[0x02], &hex("00")),
                // hashAlgorithm
                encode_ber(&[0x30], &encode_ber(&[0x06], &hex(algorithm_oid))),
                // dataGroupHashValues
                encode_ber(&[0x30], &hash_entries),
            ]
            .concat(),
        );

        let encap_content_info = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x06], &cms::OID_LDS_SECURITY_OBJECT),
                encode_ber(&[0xA0], &encode_ber(&[0x04], &lds_security_object)),
            ]
            .concat(),
        );
        let signed_data = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x02], &hex("03")),
                encode_ber(&[0x31], &vec![]),
                encap_content_info,
            ]
            .concat(),
        );
        let content_info = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x06], &hex("2A864886F70D010702")),
                encode_ber(&[0xA0], &signed_data),
            ]
            .concat(),
        );
        // EF.SOD wraps the whole thing in tag 0x77.
        return encode_ber(&[0x77], &content_info);
    }

    fn parse(data: Vec<u8>) -> types::EFSOD {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFSod as usize];
        match parser(&data, data_group, false).unwrap() {
            types::ParsedDataGroup::EFSOD(parsed) => parsed,
            other => panic!("Expected EFSOD but got {:?}", other),
        }
    }

    #[test]
    fn parses_data_group_hashes() {
        // SHA-256
        let sod = build_sod(
            "608648016503040201",
            &[(1, vec![0xAAu8; 32]), (2, vec![0xBBu8; 32])],
        );
        let parsed = parse(sod);

        assert_eq!(parsed.hash_algorithm, DocumentHashAlgorithm::Sha256);
        assert_eq!(parsed.data_group_hashes.len(), 2);
        assert_eq!(parsed.data_group_hashes[0].data_group_number, 1);
        assert_eq!(parsed.data_group_hashes[0].hash, vec![0xAAu8; 32]);
        assert_eq!(parsed.data_group_hashes[1].data_group_number, 2);
    }

    /// Older documents are signed with SHA-1, which still has to parse.
    #[test]
    fn parses_a_sha1_document() {
        let sod = build_sod("2B0E03021A", &[(1, vec![0xCCu8; 20])]);
        let parsed = parse(sod);
        assert_eq!(parsed.hash_algorithm, DocumentHashAlgorithm::Sha1);
        assert_eq!(parsed.data_group_hashes[0].hash.len(), 20);
    }

    /// An algorithm we cannot compute must be refused, not guessed at, since
    /// comparing against the wrong digest would fail confusingly.
    #[test]
    fn rejects_an_unknown_hash_algorithm() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFSod as usize];
        // MD5, which ICAO does not permit and we do not implement.
        let sod = build_sod("2A864886F70D0205", &[(1, vec![0xDDu8; 16])]);
        assert!(parser(&sod, data_group, false).is_none());
    }

    #[test]
    fn rejects_a_file_with_the_wrong_tag() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFSod as usize];
        assert!(parser(&vec![0x76, 0x02, 0x30, 0x00], data_group, false).is_none());
    }

    /// Something that is not an EF.SOD at all yields nothing rather than an
    /// empty hash list that would look like a document with no data groups.
    #[test]
    fn rejects_a_file_without_an_lds_security_object() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFSod as usize];
        let not_a_sod = encode_ber(
            &[0x77],
            &encode_ber(&[0x30], &encode_ber(&[0x02], &hex("01"))),
        );
        assert!(parser(&not_a_sod, data_group, false).is_none());
    }
}
