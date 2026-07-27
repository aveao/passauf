///! Just enough Cryptographic Message Syntax to reach a signed payload
///
/// EF.SOD and EF.CardSecurity are both CMS SignedData ([RFC 5652]) wrapping the
/// structure we actually want:
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType OBJECT IDENTIFIER,
///     content     [0] EXPLICIT SignedData }
///
/// SignedData ::= SEQUENCE {
///     version, digestAlgorithms, encapContentInfo, certificates, crls, signerInfos }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType OBJECT IDENTIFIER,
///     eContent     [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
///
/// Nothing here verifies a signature. That is Passive Authentication, which
/// needs country signing certificates passauf does not handle, so a payload
/// found through this module is unauthenticated.
use iso7816_tlv::ber;

use crate::helpers;

const TAG_SEQUENCE: u16 = 0x30;
const TAG_OBJECT_IDENTIFIER: u16 = 0x06;
const TAG_OCTET_STRING: u16 = 0x04;

/// id-icao-ldsSecurityObject, `2.23.136.1.1.1`, the eContentType of EF.SOD.
pub const OID_LDS_SECURITY_OBJECT: [u8; 6] = [0x67, 0x81, 0x08, 0x01, 0x01, 0x01];

/// Find the eContent of the encapContentInfo with a given eContentType.
///
/// Matching on the content type rather than hunting for any OCTET STRING
/// matters here: SignedData also carries certificates and signed attributes,
/// which are full of OCTET STRINGs and SEQUENCEs that would match a looser
/// search.
///
/// Returns the eContent's bytes, i.e. the DER of whatever was signed.
pub fn find_e_content(tlv: &ber::Tlv, e_content_type: &[u8]) -> Option<Vec<u8>> {
    let children = match tlv.value() {
        ber::Value::Constructed(children) => children,
        // A primitive cannot be an encapContentInfo nor hold one.
        ber::Value::Primitive(_) => return None,
    };

    // Is this the encapContentInfo we want? It opens with its content type.
    if helpers::get_tlv_tag(tlv) == TAG_SEQUENCE {
        let is_wanted = children.first().is_some_and(|first| {
            helpers::get_tlv_tag(first) == TAG_OBJECT_IDENTIFIER
                && helpers::get_tlv_value_bytes(first) == e_content_type
        });
        if is_wanted {
            if let Some(e_content) = find_octet_string(children) {
                return Some(e_content);
            }
        }
    }

    for child in children.iter() {
        if let Some(found) = find_e_content(child, e_content_type) {
            return Some(found);
        }
    }
    return None;
}

/// Pull the eContent OCTET STRING out of an encapContentInfo's children.
///
/// It sits inside an explicit [0], so this looks one level down as well as at
/// the children themselves.
fn find_octet_string(children: &Vec<ber::Tlv>) -> Option<Vec<u8>> {
    for child in children.iter() {
        match child.value() {
            ber::Value::Primitive(bytes) => {
                if helpers::get_tlv_tag(child) == TAG_OCTET_STRING {
                    return Some(bytes.clone());
                }
            }
            // The explicit [0] tag wrapping the OCTET STRING.
            ber::Value::Constructed(inner) => {
                if let Some(found) = find_octet_string(inner) {
                    return Some(found);
                }
            }
        }
    }
    return None;
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

    /// Build a SignedData carrying a payload under the given content type,
    /// with a certificate alongside it that a looser search would trip over.
    fn signed_data(e_content_type: &[u8], payload: &[u8]) -> Vec<u8> {
        let encap_content_info = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x06], e_content_type),
                encode_ber(&[0xA0], &encode_ber(&[0x04], payload)),
            ]
            .concat(),
        );
        // A stand-in certificate: a SEQUENCE holding an OCTET STRING, which is
        // the shape a naive search would latch onto.
        let certificates = encode_ber(
            &[0xA0],
            &encode_ber(&[0x30], &encode_ber(&[0x04], &hex("DEADBEEF"))),
        );
        let signed_data = encode_ber(
            &[0x30],
            &vec![
                encode_ber(&[0x02], &hex("03")),
                encode_ber(&[0x31], &vec![]),
                encap_content_info,
                certificates,
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
    fn finds_the_payload_by_content_type() {
        let payload = encode_ber(&[0x30], &hex("020100020101"));
        let data = signed_data(&OID_LDS_SECURITY_OBJECT, &payload);
        let parsed = ber::Tlv::parse(&data).0.unwrap();

        assert_eq!(
            find_e_content(&parsed, &OID_LDS_SECURITY_OBJECT),
            Some(payload)
        );
    }

    /// The certificate's OCTET STRING must not be mistaken for the eContent,
    /// which is what matching on the content type buys us.
    #[test]
    fn ignores_octet_strings_elsewhere_in_the_structure() {
        let payload = encode_ber(&[0x30], &hex("020100020101"));
        let data = signed_data(&OID_LDS_SECURITY_OBJECT, &payload);
        let parsed = ber::Tlv::parse(&data).0.unwrap();

        let found = find_e_content(&parsed, &OID_LDS_SECURITY_OBJECT).unwrap();
        assert_ne!(found, hex("DEADBEEF"));
        assert_eq!(found, payload);
    }

    /// A different content type finds nothing rather than the wrong payload.
    #[test]
    fn rejects_a_content_type_that_is_not_there() {
        let payload = encode_ber(&[0x30], &hex("020100020101"));
        let data = signed_data(&OID_LDS_SECURITY_OBJECT, &payload);
        let parsed = ber::Tlv::parse(&data).0.unwrap();

        // id-SecurityObject, EF.CardSecurity's type, not EF.SOD's.
        assert_eq!(find_e_content(&parsed, &hex("04007F0007030201")), None);
    }
}
