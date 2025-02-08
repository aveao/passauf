use cbc::cipher::{
    inout::block_padding, inout::block_padding::RawPadding, BlockModeDecrypt, BlockModeEncrypt,
    KeyInit, KeyIvInit,
};
use phf::phf_map;
use retail_mac::{Mac, RetailMac};
use sha1::{Digest, Sha1};
use simplelog::debug;

use crate::dg_parsers;
use crate::types;

type RetailMacDes = RetailMac<des::Des>;
type TDesCbcEnc = cbc::Encryptor<des::TdesEde2>;
type TDesCbcDec = cbc::Decryptor<des::TdesEde2>;

const TDES_IV: [u8; 8] = [0x00u8; 8];
pub static AID_MRTD_LDS1: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

pub static DATA_GROUPS: phf::Map<&'static str, &'static DataGroup> = phf_map! {
    "EF.COM" => &DataGroup{tag: 0x60, dg_num: 0, file_id: 0x011E, description: "Header and Data Group Presence Information", pace_only: false, eac_only: false, in_lds1: false, parser: dg_parsers::ef_com::parser, is_binary: false},
    "EF.CardAccess" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011C, description: "SecurityInfos (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.CardSecurity" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x011D, description: "SecurityInfos for Chip Authentication Mapping (PACE)", pace_only: true, eac_only: false, in_lds1: false, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.ATR/INFO" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F01, description: "Answer to Reset File", pace_only: false, eac_only: false, in_lds1: false, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DIR" => &DataGroup{tag: 0xff, dg_num: 0, file_id: 0x2F00, description: "Directory", pace_only: false, eac_only: false, in_lds1: false, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG1" => &DataGroup{tag: 0x61, dg_num: 1, file_id: 0x0101, description: "Details recorded in MRZ", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::ef_dg1::parser, is_binary: false},
    "EF.DG2" => &DataGroup{tag: 0x75, dg_num: 2, file_id: 0x0102, description: "Encoded Face", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},
    "EF.DG3" => &DataGroup{tag: 0x63, dg_num: 3, file_id: 0x0103, description: "Encoded Finger(s)", pace_only: false, eac_only: true, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},
    "EF.DG4" => &DataGroup{tag: 0x76, dg_num: 4, file_id: 0x0104, description: "Encoded Eye(s)", pace_only: false, eac_only: true, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},
    "EF.DG5" => &DataGroup{tag: 0x65, dg_num: 5, file_id: 0x0105, description: "Displayed Portrait", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},
    "EF.DG6" => &DataGroup{tag: 0x66, dg_num: 6, file_id: 0x0106, description: "Reserved for Future Use", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG7" => &DataGroup{tag: 0x67, dg_num: 7, file_id: 0x0107, description: "Displayed Signature or Usual Mark", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG8" => &DataGroup{tag: 0x68, dg_num: 8, file_id: 0x0108, description: "Data Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG9" => &DataGroup{tag: 0x69, dg_num: 9, file_id: 0x0109, description: "Structure Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG10" => &DataGroup{tag: 0x6a, dg_num: 10, file_id: 0x010A, description: "Substance Feature(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG11" => &DataGroup{tag: 0x6b, dg_num: 11, file_id: 0x010B, description: "Additional Personal Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::ef_dg11::parser, is_binary: false},
    "EF.DG12" => &DataGroup{tag: 0x6c, dg_num: 12, file_id: 0x010C, description: "Additional Document Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::ef_dg12::parser, is_binary: false},
    "EF.DG13" => &DataGroup{tag: 0x6d, dg_num: 13, file_id: 0x010D, description: "Optional Detail(s)", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.DG14" => &DataGroup{tag: 0x6e, dg_num: 14, file_id: 0x010E, description: "Security Options", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},  // this isn't actually binary, but the parser is quite complex and isn't ready yet
    "EF.DG15" => &DataGroup{tag: 0x6f, dg_num: 15, file_id: 0x010F, description: "Active Authentication Public Key Info", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: true},
    "EF.DG16" => &DataGroup{tag: 0x70, dg_num: 16, file_id: 0x0110, description: "Person(s) to Notify", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
    "EF.SOD" => &DataGroup{tag: 0x77, dg_num: 0, file_id: 0x011D, description: "Document Security Object", pace_only: false, eac_only: false, in_lds1: true, parser: dg_parsers::generic::parser, is_binary: false},
};

#[derive(Debug)]
#[allow(dead_code)]
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
    // Whether this file should be read when printing info
    pub is_binary: bool,
    pub parser: fn(Vec<u8>, &DataGroup, bool) -> Option<types::ParsedDataGroup>,
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

/// Does key derivation based on ICAO 9303 p11 for SHA-1
///
/// For BAC, this is always used.
/// For PACE, this is only used for 128-bit AES keys.
pub fn kdf_sha1(shared_secret: &[u8], counter: u32) -> Vec<u8> {
    let base_secret = vec![shared_secret, &counter.to_be_bytes()].concat();
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(base_secret.as_slice());
    // Trim to first 16 bytes.
    let keydata = &sha1_hasher.finalize_reset()[0..16];
    // We can optionally adjust parity bits here, but rustcrypto/des doesn't care.
    return keydata.to_vec();
}

/// Applies Padding Method 2 based on ISO 9797-1.
///
/// Takes the data and returns a new Vec with the appropriate padding.
pub fn padding_method_2_pad(input: &Vec<u8>) -> Vec<u8> {
    // block_padding::Iso7816 is pretty close to this, but it has one key difference:
    // This function adds a full block of padding when data is block size-aligned.
    // block_padding::Iso7816, however, does not. IME, this can make or break the comms.

    let padding = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    // This assumes a block size of 8 bytes.
    let padding_to_append = 8 - (input.len() % 8);
    return vec![input.as_slice(), &padding[0..padding_to_append]].concat();
}

/// Undoes Padding Method 2 based on ISO 9797-1.
///
/// Takes the data and returns a new Vec without the padding.
pub fn padding_method_2_unpad(input: &Vec<u8>) -> Vec<u8> {
    return block_padding::Iso7816::raw_unpad(input).unwrap().to_vec();
}

/// Applies Retail Mac based on ISO 9797-1.
///
/// Does not apply padding method 2, it should be done separately.
pub fn retail_mac(k_mac: &[u8], input_data: &Vec<u8>) -> Vec<u8> {
    let mut rmac_instance = RetailMacDes::new_from_slice(k_mac).unwrap();
    rmac_instance.update(input_data);
    return rmac_instance.finalize().as_bytes().to_vec();
}

/// Encrypts given data according to 3DES as used in ICAO 9303
///
/// Data should be pre-padded.
pub fn tdes_enc(key: &[u8], data: &[u8]) -> Vec<u8> {
    return TDesCbcEnc::new_from_slices(key, TDES_IV.as_slice())
        .unwrap()
        .encrypt_padded_vec::<block_padding::NoPadding>(data);
}

/// Decrypts given data according to 3DES as used in ICAO 9303
pub fn tdes_dec(key: &[u8], data: &[u8]) -> Vec<u8> {
    return TDesCbcDec::new_from_slices(key, TDES_IV.as_slice())
        .unwrap()
        .decrypt_padded_vec::<block_padding::NoPadding>(data)
        .unwrap();
}

/// Calculates E.IFD and M.IFD for BAC
///
/// Returns K.enc, E.ifd and M.ifd
pub fn calculate_bac_eifd_and_mifd(
    rnd_ic: &[u8],
    rnd_ifd: &[u8],
    k_ifd: &[u8],
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut sha1_hasher = Sha1::new();
    // Glossary of terms for the authentication:
    // RND. = Random Number
    // K. = Key, KS. = Session Key, E. = Encrypted
    // M./.MAC = MAC
    // .IC = Integrated Circuit (eMRTD)
    // .IFD = Interface Device (Us)
    // .ENC = Encryption
    // .MRZ = Machine Readable Zone
    // .seed = Seed to generate a key
    // SSC = Send Sequence Counter

    // Concatinate RND.IFD, RND.IC and K.IFD into S (shared secret)
    let shared_secret = vec![rnd_ifd, rnd_ic, k_ifd].concat();
    debug!("shared_secret: {:02x?}", shared_secret);

    // Concatinate MRZ with added check digits for key formation.
    let k_mrz = vec![
        append_check_digit(document_number).as_bytes(),
        append_check_digit(date_of_birth).as_bytes(),
        append_check_digit(date_of_expiry).as_bytes(),
    ]
    .concat();
    debug!("K.mrz: {:02x?}", k_mrz);

    // Calculate the seed for the key
    sha1_hasher.update(k_mrz.as_slice());
    let k_seed = &sha1_hasher.finalize_reset()[0..16];

    // Derive keys K.enc and K.mac
    let k_enc = kdf_sha1(k_seed, 1);
    let k_mac = kdf_sha1(k_seed, 2);
    debug!("K.enc: {:02x?}", k_enc);
    debug!("K.mac: {:02x?}", k_mac);

    // Calculate E.IFD = E(KEnc, S)
    let e_ifd = tdes_enc(k_enc.as_slice(), &shared_secret);
    debug!("E.ifd: {:02x?}", e_ifd);

    // Calculate M.IFD = MAC(K.MAC, E.IFD)
    // Here we use Retail Mac (ISO 9797-1 MAC format 3) with Padding Method 2
    let m_ifd = retail_mac(&k_mac, &padding_method_2_pad(&e_ifd));
    debug!("M.ifd: {:02x?}", m_ifd);

    return (k_enc, e_ifd, m_ifd);
}

/// Calculate session keys for BAC
///
/// Returns KS.enc and KS.mac
pub fn calculate_bac_session_keys(
    auth_resp: &[u8],
    k_enc: &[u8],
    rnd_ifd: &[u8],
    k_ifd: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // Decrypt data we receive as response to BAC EXTERNAL_AUTHENTICATE
    let dec_resp = tdes_dec(k_enc, &auth_resp);
    debug!("Decoded auth response: {:x?}", dec_resp);
    // Compare received RND.IFD with generated RND.IFD.
    assert!(&dec_resp[8..16] == rnd_ifd);

    // Calculate K.seed = XOR(K.IFD, K.IC)
    let k_ic = &dec_resp[16..32];
    debug!("K.IC: {:x?}", k_ic);
    let mut k_seed = [0u8; 16];
    for i in 0..16 {
        k_seed[i] = k_ifd[i] ^ k_ic[i];
    }
    debug!("K.seed: {:x?}", k_seed);

    // Calculate session keys (KS.enc, KS.mac)
    let ks_enc = kdf_sha1(&k_seed, 1);
    let ks_mac = kdf_sha1(&k_seed, 2);
    debug!("KS.enc: {:x?}", ks_enc);
    debug!("KS.mac: {:x?}", ks_mac);
    return (ks_enc, ks_mac);
}

/// Calculates initial Send Sequence Counter for BAC
pub fn calculate_initial_ssc_bac(rnd_ic: &[u8], rnd_ifd: &[u8]) -> u64 {
    let ssc_bytes = vec![&rnd_ic[4..8], &rnd_ifd[4..8]].concat();
    return u64::from_be_bytes(ssc_bytes.try_into().unwrap());
}
