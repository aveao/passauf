///! EF.CardSecurity (ICAO 9303 p11 section 9.2)
///
/// Unlike EF.CardAccess, which is a bare SecurityInfos SET, EF.CardSecurity
/// wraps the same structure in a CMS SignedData ([RFC 5652]). ICAO 9303 p11
/// Appendix I reads the chip's Chip Authentication public key from here rather
/// than DG14, and a document can publish a key here that DG14 never mentions.
///
/// The signature is not checked. Doing so is Passive Authentication, which
/// needs the country signing certificates passauf does not handle yet, so
/// nothing read out of this file is trustworthy on its own.
use iso7816_tlv::ber;
#[cfg(feature = "cli")]
use simplelog::info;
use simplelog::{debug, warn};

#[cfg(feature = "cli")]
use crate::dg_parsers::helpers as dg_helpers;
use crate::dg_parsers::security_infos::{self, TAG_SET};
use crate::helpers;
use crate::types;

/// DER tag for an OCTET STRING, which is what holds the eContent.
const TAG_OCTET_STRING: u16 = 0x04;

impl types::EFCardSecurity {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);

        if self.chip_authentication_public_keys.is_empty() {
            info!(
                "{:>pad_len$} <yellow>none</>",
                "CA public keys",
                pad_len = 15
            );
        }
        for key_info in self.chip_authentication_public_keys.iter() {
            let key_id = match key_info.key_id {
                Some(key_id) => format!(", key {}", key_id),
                None => String::new(),
            };
            info!(
                "{:>pad_len$} <yellow>{}{} ({} bytes)</>",
                "CA public key",
                security_infos::describe_domain_parameters(key_info),
                key_id,
                key_info.public_key.len(),
                pad_len = 15
            );
        }
        info!("<d>The signature on this file is not verified.</>");
        info!("");
    }
}

/// Find the eContent OCTET STRING that holds the SecurityInfos.
///
/// The nesting is
/// `ContentInfo -> [0] -> SignedData -> encapContentInfo -> [0] -> OCTET STRING`,
/// and the OCTET STRING's contents are the SecurityInfos SET. Rather than walk
/// that path rigidly, this looks for any OCTET STRING whose contents parse as a
/// SET, which is shorter and tolerates the structure varying.
///
/// Deliberately does not treat a bare SET in the tree as a match: SignedData's
/// digestAlgorithms is a SET too, and it comes first.
fn find_e_content(tlv: &ber::Tlv) -> Option<Vec<ber::Tlv>> {
    match tlv.value() {
        ber::Value::Primitive(bytes) => {
            if helpers::get_tlv_tag(tlv) != TAG_OCTET_STRING {
                return None;
            }
            let inner = ber::Tlv::parse(bytes).0.ok()?;
            if helpers::get_tlv_tag(&inner) != TAG_SET {
                return None;
            }
            return Some(helpers::get_tlv_constructed_value(&inner));
        }
        ber::Value::Constructed(children) => {
            for child in children.iter() {
                if let Some(found) = find_e_content(child) {
                    return Some(found);
                }
            }
            return None;
        }
    }
}

/// Find the SecurityInfos SET in an EF.CardSecurity.
fn find_security_infos(tlv: &ber::Tlv) -> Option<Vec<ber::Tlv>> {
    if let Some(security_infos) = find_e_content(tlv) {
        return Some(security_infos);
    }
    // A file that is a bare SecurityInfos rather than a SignedData. Checked
    // only at the top level, so SignedData's inner SETs cannot be mistaken
    // for it.
    if helpers::get_tlv_tag(tlv) == TAG_SET {
        return Some(helpers::get_tlv_constructed_value(tlv));
    }
    return None;
}

pub fn parser(
    data: &Vec<u8>,
    data_group: &types::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    let base_tlv = ber::Tlv::parse(data).0.ok()?;
    debug!("base_tlv: {:02x?}", &base_tlv);

    let security_infos = match find_security_infos(&base_tlv) {
        Some(security_infos) => security_infos,
        None => {
            warn!(
                "Could not find SecurityInfos inside {}, skipping parsing.",
                data_group.name
            );
            return None;
        }
    };

    let chip_authentication_public_keys =
        security_infos::parse_chip_authentication_public_keys(&security_infos);

    let result = types::EFCardSecurity {
        chip_authentication_public_keys,
    };
    debug!("EF.CardSecurity: {:02x?}", result);

    if print_data {
        #[cfg(feature = "cli")]
        result.fancy_print(data_group);
    }
    return Some(types::ParsedDataGroup::EFCardSecurity(result));
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

    fn parse(data: Vec<u8>) -> types::EFCardSecurity {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFCardSecurity as usize];
        match parser(&data, data_group, false).unwrap() {
            types::ParsedDataGroup::EFCardSecurity(parsed) => parsed,
            other => panic!("Expected EFCardSecurity but got {:?}", other),
        }
    }

    /// The ChipAuthenticationPublicKeyInfo of ICAO 9303 p11 Appendix I, which
    /// the appendix reads out of EF.CardSecurity.
    fn worked_example_key_info() -> Vec<u8> {
        return hex("30620609 04007F00 07020201 02305230
             0C060704 007F0007 01020201 0D034200
             04187270 9494399E 7470A643 1BE25E83
             EEE24FEA 568C2ED2 8DB48E05 DB3A610D
             C884D256 A40E35EF CB59BF67 53D3A489
             D28C7A4D 973C2DA1 38A6E7A4 A08F68E1
             6F02010D");
    }

    /// Wrap SecurityInfos the way a CMS SignedData does, nesting deeply enough
    /// that the search has to recurse.
    fn wrap_in_signed_data(security_infos: Vec<u8>) -> Vec<u8> {
        // encapContentInfo: eContentType OID, then [0] holding the OCTET STRING.
        let e_content = encode_ber(&[0x04], &security_infos);
        let encap_content_info = encode_ber(
            &[0x30],
            &vec![
                // id-SecurityObject, the eContentType EF.CardSecurity uses.
                encode_ber(&[0x06], &hex("04007F0007030201")),
                encode_ber(&[0xA0], &e_content),
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
        return encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x06], &hex("2A864886F70D010702")),
                encode_ber(&[0xA0], &signed_data),
            ]
            .concat(),
        );
    }

    #[test]
    fn finds_keys_inside_signed_data() {
        let security_infos = encode_ber(&[0x31], &worked_example_key_info());
        let parsed = parse(wrap_in_signed_data(security_infos));

        assert_eq!(parsed.chip_authentication_public_keys.len(), 1);
        let key = &parsed.chip_authentication_public_keys[0];
        assert_eq!(key.parameter_id, Some(13));
        assert_eq!(key.key_id, Some(13));
        assert_eq!(
            key.public_key,
            hex(
                "041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8
                 84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F"
            )
        );
    }

    /// Several keys in one file all come out, which is the case that matters
    /// for a chip whose CAM key is not the one DG14 advertises.
    #[test]
    fn finds_every_key_in_the_file() {
        let second = hex("30620609 04007F00 07020201 02305230
             0C060704 007F0007 01020201 0D034200
             042E3252 DB8687B9 EC132494 5E0BEE33
             3B64C35F 38FECEA0 F56E8920 A421F928
             17988E79 507DC7D5 615A0480 1B057636
             7933908677D55D2030BB6B0861A8F849C902
             0141");
        let security_infos = encode_ber(&[0x31], &vec![worked_example_key_info(), second].concat());
        let parsed = parse(wrap_in_signed_data(security_infos));

        assert_eq!(parsed.chip_authentication_public_keys.len(), 2);
        assert_eq!(parsed.chip_authentication_public_keys[1].key_id, Some(65));
    }

    /// A file with nothing resembling SecurityInfos is rejected rather than
    /// yielding an empty result that looks like a document without keys.
    #[test]
    fn rejects_a_file_with_no_security_infos() {
        let data_group = &types::DATA_GROUPS[types::DataGroupEnum::EFCardSecurity as usize];
        let nonsense = encode_ber(&[0x30], &encode_ber(&[0x02], &hex("01")));
        assert!(parser(&nonsense, data_group, false).is_none());
    }
}
