use crate::types;
use block_padding;
use cbc::cipher::{BlockCipherEncrypt, KeyIvInit};
use log::warn;
use phf::phf_map;
use rand::Rng;
use retail_mac::{digest::KeyInit, Mac, RetailMac};
use sha1::{Digest, Sha1};

type RetailMacDes = RetailMac<des::Des>;
type TDesCbcEnc = cbc::Encryptor<des::TdesEde2>;

#[derive(Debug)]
pub struct DataGroup {
    pub tag: u8,
    pub dg_num: u8,
    pub file_id: u16,
    pub description: &'static str, // length is 15b, ng is 1b
    pub pace_only: bool,
    pub eac_only: bool,
    // Whether the DG is under MF or eMRTD LDS1 applet.
    // For more info, see ICAO 9303 p10, page 39, figure 3
    // Alternatively: https://elixi.re/i/4tlij260gf43v.png
    // We basically can only read these if the applet is not selected.
    pub in_lds1: bool,
    pub is_asn1: bool,
    pub parser: fn(Vec<u8>),
}

/// Calculates MRZ check digits according to ICAO 9303 p3
///
/// Can be used for document number, DOB, Expiry and MRZ text
/// Accepts a String of A-Z 0-9 and <
pub fn calculate_check_digit(text: &String) -> u8 {
    let mrz_weights = [7, 3, 1];
    // MRZ isn't supposed to have lowercase characters, but user input is user input.
    let uppercase_text = text.to_uppercase();
    let mut check_digit: u8 = 0;

    for (i, character) in uppercase_text.as_bytes().into_iter().enumerate() {
        let char_value = match character {
            b'A'..=b'Z' => character - 55, // A = 10, Z = 35
            b'0'..=b'9' => character - 48, // turn ASCII numbers into actual numbers
            b'<' => 0,
            _ => 0, // we shouldn't get any other chars ideally
        };
        // The check digit is supposed to be mod10 at the end.
        // As long as we're adding positive integers to it (we control them),
        // mod10 on each iteration should lead to the same result
        // and let us stay u8 while accepting arbitrary length inputs.
        check_digit += char_value * mrz_weights[i % 3];
        check_digit %= 10;
    }
    return check_digit;
}

/// Appends MRZ check digits to a given String
///
/// Can be used for document number, DOB, Expiry and MRZ text
/// Accepts a String of A-Z 0-9 and <
pub fn append_check_digit(text: &String) -> String {
    let check_digit = calculate_check_digit(text);
    let result = text.to_owned() + &check_digit.to_string();
    return result;
}

/// Does key derivation based on ICAO 9303 p11 for SHA1
///
/// For BAC, this is always used.
/// For PACE, this is only used for 128-bit AES keys.
pub fn kdf_sha1(shared_secret: Vec<u8>, counter: u32) -> Vec<u8> {
    let base_secret = vec![shared_secret, counter.to_be_bytes().to_vec()].concat();
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(base_secret.as_slice());
    // Trim to first 16 bytes.
    let keydata = sha1_hasher.finalize_reset()[0..=16].to_vec();
    // TODO: adjust parity bits
    return keydata;
}

pub fn calculate_bac(
    rnd_ic: Vec<u8>,
    document_number: String,
    date_of_birth: String,
    date_of_expiry: String,
) {
    let mut sha1_hasher = Sha1::new();

    // Generate RND.IFD
    let mut rnd_ifd = [0u8; 8];
    rand::rng().fill(&mut rnd_ifd[..]);

    // Generate keying material K.IFD
    let mut k_ifd = [0u8; 16];
    rand::rng().fill(&mut k_ifd[..]);

    // Concatinate RND.IC, RND.IFD and K.IFD into S
    let shared_secret = vec![rnd_ic.as_slice(), &rnd_ifd, &k_ifd].concat();

    // Concatinate MRZ with added check digits for key formation.
    let kmrz = vec![
        append_check_digit(&document_number).into_bytes(),
        append_check_digit(&date_of_birth).into_bytes(),
        append_check_digit(&date_of_expiry).into_bytes(),
    ]
    .concat();

    // Calculate the seed for the key
    sha1_hasher.update(kmrz.as_slice());
    let kseed = sha1_hasher.finalize_reset();

    // Derive keys K.enc and K.mac
    let kenc = kdf_sha1(kseed.to_vec(), 1);
    let kmac = kdf_sha1(kseed.to_vec(), 2);

    // Calculate E.IFD = E(KEnc, S)
    let iv = [0x00; 8];
    // ICAO 9303 calls for ISO 9797-1's padding 2,
    // but block_padding's Iso7816 padding is identical to it.
    let e_ifd = TDesCbcEnc::new(kenc.into(), &iv.into())
        .encrypt_padded_vec::<block_padding::Iso7816>(&shared_secret);

    // uint8_t m_ifd[8] = { 0x00 };
    // retail_mac(kmac, e_ifd, 32, m_ifd);

    // Calculate M.IFD = MAC(K.MAC, E.IFD)
    let mut mac = RetailMacDes::new_from_slice(kmac.as_slice()).unwrap();
}

fn generic_parser(data: Vec<u8>) {
    warn!("Read file ({:?}b): {:x?}", data.len(), data);
}

fn generic_parser_asn1(data: Vec<u8>) {
    warn!("Read file ({:?}b): {:x?}", data.len(), data);
}

fn cardaccess_parser(data: Vec<u8>) {
    warn!("Read file ({:?}b): {:x?}", data.len(), data);
    return;
    // let fake_data = [0x31, 0x82, 0x1, 0x24, 0x30, 0xd, 0x6, 0x8, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x2, 0x2, 0x1, 0x2, 0x30, 0x12, 0x6, 0xa, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x2, 0x2, 0x1, 0x2, 0x2, 0x1, 0x48, 0x30, 0x12, 0x6, 0xa, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x2, 0x2, 0x1, 0x3, 0x2, 0x1, 0x4f, 0x30, 0x12, 0x6, 0xa, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x4, 0x2, 0x2, 0x2, 0x1, 0x2, 0x2, 0x1, 0xd, 0x30, 0x12, 0x6, 0xa, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x4, 0x6, 0x2, 0x2, 0x1, 0x2, 0x2, 0x1, 0xd, 0x30, 0x1b, 0x6, 0xb, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0xb, 0x1, 0x2, 0x3, 0x30, 0x9, 0x2, 0x1, 0x1, 0x2, 0x1, 0x0, 0x2,1, 0x1, 0x2, 0x1, 0x4f, 0x30, 0x1c, 0x6, 0x9, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x30, 0xc, 0x6, 0x7, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x1, 0x2, 0x2, 0x1, 0xd, 0x2, 0x1, 0x48, 0x30, 0x1c, 0x6, 0x9, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x30, 0xc, 0x6, 0x7, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x1, 0x2, 0x2, 0x1, 0xd, 0x2, 0x1, 0x4f, 0x30, 0x2a, 0x6, 0x8, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x6, 0x16, 0x1e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x62, 0x73, 0x69, 0x2e, 0x62, 0x75, 0x6e, 0x64, 0x2e, 0x64, 0x65, 0x2f, 0x63, 0x69, 0x66, 0x2f, 0x6e, 0x70, 0x61, 0x2e, 0x78, 0x6d, 0x6c, 0x30, 0x3e, 0x6, 0x8, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x8, 0x31, 0x32, 0x30,12, 0x6, 0xa, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x2, 0x2, 0x1, 0x2, 0x2, 0x1, 0x49, 0x30, 0x1c, 0x6, 0x9, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x2, 0x2, 0x3, 0x2, 0x30, 0xc, 0x6, 0x7, 0x4, 0x0, 0x7f, 0x0, 0x7, 0x1, 0x2, 0x2, 0x1, 0xd, 0x2, 0x1, 0x49].to_vec();
    let cardaccess_data = asn1::parse_single::<types::EFCardAccess>(&data).unwrap();

    // for security_info in cardaccess_data.security_infos {
    //     warn!("Parsed of file: {:x?}", security_info);
    // }
    //    let parsed_set = parse_der(&data).unwrap().1;
    //    warn!("DER parsed of file: {:x?}", parsed_set);
    //    assert!(parsed_set.header.tag() == der_parser::ber::Tag::Set);
    //    for object in parsed_set.content.as_set().unwrap() {
    // warn!("obj: {:x?}", object);
    // // check that they're all tag 10 (Sequence)
    // //
    //    }
}

pub static AID_MRTD_LDS1: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
pub static DATA_GROUPS: phf::Map<&'static str, &'static DataGroup> = phf_map! {
    "EF.COM" => &DataGroup{tag: 0x60, dg_num: 0, file_id: 0x011E, description: "Header and Data Group Presence Information", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser, is_asn1: true},
    "EF.CardAccess" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011C, description: "SecurityInfos (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: cardaccess_parser, is_asn1: true},
    "EF.CardSecurity" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011D, description: "SecurityInfos for Chip Authentication Mapping (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: generic_parser, is_asn1: true},
    "EF.ATR/INFO" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F01, description: "Answer to Reset File", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser, is_asn1: false},
    "EF.DIR" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F00, description: "Directory", pace_only: false, eac_only: false, in_lds1: false, parser: generic_parser_asn1, is_asn1: true},
    "EF.DG1" => &DataGroup{tag: 0x61, dg_num: 1, file_id: 0x0101, description: "Details recorded in MRZ", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG2" => &DataGroup{tag: 0x75, dg_num: 2, file_id: 0x0102, description: "Encoded Face", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG3" => &DataGroup{tag: 0x63, dg_num: 3, file_id: 0x0103, description: "Encoded Finger(s)", pace_only: false, eac_only: true, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG4" => &DataGroup{tag: 0x76, dg_num: 4, file_id: 0x0104, description: "Encoded Eye(s)", pace_only: false, eac_only: true, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG5" => &DataGroup{tag: 0x65, dg_num: 5, file_id: 0x0105, description: "Displayed Portrait", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG6" => &DataGroup{tag: 0x66, dg_num: 6, file_id: 0x0106, description: "Reserved for Future Use", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG7" => &DataGroup{tag: 0x67, dg_num: 7, file_id: 0x0107, description: "Displayed Signature or Usual Mark", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG8" => &DataGroup{tag: 0x68, dg_num: 8, file_id: 0x0108, description: "Data Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG9" => &DataGroup{tag: 0x69, dg_num: 9, file_id: 0x0109, description: "Structure Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG10" => &DataGroup{tag: 0x6a, dg_num: 10, file_id: 0x010A, description: "Substance Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG11" => &DataGroup{tag: 0x6b, dg_num: 11, file_id: 0x010B, description: "Additional Personal Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG12" => &DataGroup{tag: 0x6c, dg_num: 12, file_id: 0x010C, description: "Additional Document Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG13" => &DataGroup{tag: 0x6d, dg_num: 13, file_id: 0x010D, description: "Optional Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG14" => &DataGroup{tag: 0x6e, dg_num: 14, file_id: 0x010E, description: "Security Options", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG15" => &DataGroup{tag: 0x6f, dg_num: 15, file_id: 0x010F, description: "Active Authentication Public Key Info", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.DG16" => &DataGroup{tag: 0x70, dg_num: 16, file_id: 0x0110, description: "Person(s) to Notify", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
    "EF.SOD" => &DataGroup{tag: 0x77, dg_num: 0, file_id: 0x011D, description: "Document Security Object", pace_only: false, eac_only: false, in_lds1: true, parser: generic_parser, is_asn1: true},
};
