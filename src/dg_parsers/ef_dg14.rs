use iso7816_tlv::ber;
#[cfg(feature = "cli")]
use simplelog::info;
use simplelog::{debug, warn};

#[cfg(feature = "cli")]
use crate::dg_parsers::helpers as dg_helpers;
use crate::dg_parsers::security_infos::{self, TAG_SET};
use crate::helpers;
use crate::types;

impl types::EFDG14 {
    #[cfg(feature = "cli")]
    pub fn fancy_print(&self, data_group: &types::DataGroup) {
        dg_helpers::print_section_intro(data_group);

        for key_info in self.chip_authentication_public_keys.iter() {
            // The key ID only matters when the chip holds more than one key.
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
        info!("");
    }
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

    let chip_authentication_public_keys =
        security_infos::parse_chip_authentication_public_keys(&security_infos);

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
    use crate::dg_parsers::security_infos::identify_curve;

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
