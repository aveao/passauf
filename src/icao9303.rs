use cbc::cipher::{inout::block_padding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use rand::RngExt;
use sha1::{Digest, Sha1};
use simplelog::{info, trace, warn};

use crate::secure_messaging::{
    kdf, padding_method_2_pad, retail_mac, SecureMessaging, SmAlgorithm,
};
use crate::{iso7816, smartcard_abstractions::Smartcard};

type TDesCbcEnc = cbc::Encryptor<des::TdesEde2>;
type TDesCbcDec = cbc::Decryptor<des::TdesEde2>;

const TDES_IV: [u8; 8] = [0x00u8; 8];
pub static AID_MRTD_LDS1: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

/// Calculates MRZ check digits according to ICAO 9303 p3
///
/// Can be used for document number, DOB, Expiry and MRZ text
/// Accepts a String of A-Z 0-9 and <
pub fn calculate_check_digit(text: &String) -> char {
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
    return char::from_digit(check_digit as u32, 10).unwrap();
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

/// The MRZ gives the document number a fixed width field, padded out with `<`.
const DOCUMENT_NUMBER_MRZ_LENGTH: usize = 9;

/// Pads a document number out to the width of its MRZ field.
///
/// Keys are derived from the MRZ *field*, not from the number as printed in the
/// visual inspection zone, so a number shorter than nine characters has to carry
/// its `<` filler or everything derived from it comes out wrong.
///
/// The check digit is the same either way, because the filler is trailing and `<`
/// is worth zero. That is what makes forgetting this so quiet: nothing fails a
/// checksum, the document simply refuses to open.
///
/// Numbers of nine characters or more are returned untouched. A TD1 number too long
/// for the field is stitched back together from the optional data by the caller, as
/// Doc 9303-5 requires, and is used at its full length.
pub fn pad_document_number(document_number: &String) -> String {
    let length = document_number.chars().count();
    if length >= DOCUMENT_NUMBER_MRZ_LENGTH {
        return document_number.to_owned();
    }
    return document_number.to_owned() + &"<".repeat(DOCUMENT_NUMBER_MRZ_LENGTH - length);
}

/// Builds the MRZ information that BAC and PACE both derive their keys from.
///
/// ICAO 9303 p11 section 9.7.2: the padded document number, the date of birth and
/// the date of expiry, each followed by its own check digit.
pub fn mrz_information(
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> Vec<u8> {
    return vec![
        append_check_digit(&pad_document_number(document_number)).as_bytes(),
        append_check_digit(date_of_birth).as_bytes(),
        append_check_digit(date_of_expiry).as_bytes(),
    ]
    .concat();
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

/// The digest algorithms ICAO 9303 allows for the Document Security Object.
///
/// EF.SOD names one by OID and hashes every data group with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentHashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DocumentHashAlgorithm {
    /// Resolve a digest from the DER value bytes of its object identifier.
    ///
    /// Returns None for anything we cannot compute, so a caller refuses rather
    /// than comparing against the wrong digest.
    pub fn from_oid_bytes(oid_bytes: &[u8]) -> Option<DocumentHashAlgorithm> {
        return Some(match oid_bytes {
            // 1.3.14.3.2.26
            [0x2B, 0x0E, 0x03, 0x02, 0x1A] => DocumentHashAlgorithm::Sha1,
            // 2.16.840.1.101.3.4.2.x
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04] => DocumentHashAlgorithm::Sha224,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => DocumentHashAlgorithm::Sha256,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => DocumentHashAlgorithm::Sha384,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => DocumentHashAlgorithm::Sha512,
            _ => return None,
        });
    }

    /// Hash data with this algorithm.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        return match self {
            DocumentHashAlgorithm::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DocumentHashAlgorithm::Sha224 => {
                let mut hasher = sha2::Sha224::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DocumentHashAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DocumentHashAlgorithm::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DocumentHashAlgorithm::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        };
    }
}

impl std::fmt::Display for DocumentHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(
            f,
            "{}",
            match self {
                DocumentHashAlgorithm::Sha1 => "SHA-1",
                DocumentHashAlgorithm::Sha224 => "SHA-224",
                DocumentHashAlgorithm::Sha256 => "SHA-256",
                DocumentHashAlgorithm::Sha384 => "SHA-384",
                DocumentHashAlgorithm::Sha512 => "SHA-512",
            }
        );
    }
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
    trace!("shared_secret: {:02x?}", shared_secret);

    // Concatinate MRZ with added check digits for key formation.
    let k_mrz = mrz_information(document_number, date_of_birth, date_of_expiry);
    trace!("K.mrz: {:02x?}", k_mrz);

    // Calculate the seed for the key
    sha1_hasher.update(k_mrz.as_slice());
    let k_seed = &sha1_hasher.finalize_reset()[0..16];

    // Derive keys K.enc and K.mac
    let k_enc = kdf(SmAlgorithm::Tdes, k_seed, 1);
    let k_mac = kdf(SmAlgorithm::Tdes, k_seed, 2);
    trace!("K.enc: {:02x?}", k_enc);
    trace!("K.mac: {:02x?}", k_mac);

    // Calculate E.IFD = E(KEnc, S)
    let e_ifd = tdes_enc(k_enc.as_slice(), &shared_secret);
    trace!("E.ifd: {:02x?}", e_ifd);

    // Calculate M.IFD = MAC(K.MAC, E.IFD)
    // Here we use Retail Mac (ISO 9797-1 MAC format 3) with Padding Method 2
    let m_ifd = retail_mac(&k_mac, &padding_method_2_pad(&e_ifd, 8));
    trace!("M.ifd: {:02x?}", m_ifd);

    return (k_enc, e_ifd, m_ifd);
}

/// Calculate session keys for BAC
///
/// Returns KS.enc and KS.mac, or None if the document did not authenticate itself back.
pub fn calculate_bac_session_keys(
    auth_resp: &[u8],
    k_enc: &[u8],
    rnd_ifd: &[u8],
    k_ifd: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    // Decrypt data we receive as response to BAC EXTERNAL_AUTHENTICATE
    let dec_resp = tdes_dec(k_enc, &auth_resp);
    trace!("Decoded auth response: {:x?}", dec_resp);
    // The document echoes our own random back, encrypted under the key it derived. Any
    // other answer means it derived a different key from the one we did, and nothing
    // after this point would decrypt to anything.
    if dec_resp.len() < 32 || &dec_resp[8..16] != rnd_ifd {
        warn!("The document did not echo our challenge back, so the keys do not match.");
        return None;
    }

    // Calculate K.seed = XOR(K.IFD, K.IC)
    let k_ic = &dec_resp[16..32];
    trace!("K.IC: {:x?}", k_ic);
    let mut k_seed = [0u8; 16];
    for i in 0..16 {
        k_seed[i] = k_ifd[i] ^ k_ic[i];
    }
    trace!("K.seed: {:x?}", k_seed);

    // Calculate session keys (KS.enc, KS.mac)
    let ks_enc = kdf(SmAlgorithm::Tdes, &k_seed, 1);
    let ks_mac = kdf(SmAlgorithm::Tdes, &k_seed, 2);
    trace!("KS.enc: {:x?}", ks_enc);
    trace!("KS.mac: {:x?}", ks_mac);
    return Some((ks_enc, ks_mac));
}

/// Calculates initial Send Sequence Counter for BAC
pub fn calculate_initial_ssc_bac(rnd_ic: &[u8], rnd_ifd: &[u8]) -> u64 {
    let ssc_bytes = vec![&rnd_ic[4..8], &rnd_ifd[4..8]].concat();
    return u64::from_be_bytes(ssc_bytes.try_into().unwrap());
}

/// Authenticate with Basic Access Control
/// Establish a BAC session.
///
/// Returns None when the document refuses, which in practice means the three MRZ fields
/// did not derive the key it expected. The chip does not say which of the three was
/// wrong, and cannot: it only knows the MAC did not verify.
pub fn do_bac_authentication(
    port: &mut Box<impl Smartcard + ?Sized>,
    document_number: &String,
    date_of_birth: &String,
    date_of_expiry: &String,
) -> Option<SecureMessaging> {
    info!("<d>Starting Basic Access Control</>");

    // Get RND.IC by calling GET_CHALLENGE.
    let mut apdu = iso7816::apdu_get_challenge();
    let (rapdu, status_code) = apdu.exchange(port, false);
    if status_code != iso7816::StatusCode::Ok as u16 || rapdu.len() < 8 {
        warn!(
            "The document would not issue a challenge (0x{:04X}).",
            status_code
        );
        return None;
    }
    // get the first 8 bytes of the response, which is the actual response
    // (rest is SW and checksum)
    let rnd_ic = &rapdu[0..8];

    // Generate RND.IFD
    let mut rnd_ifd = [0u8; 8];
    rand::rng().fill(&mut rnd_ifd[..]);

    // Generate keying material K.IFD
    let mut k_ifd = [0u8; 16];
    rand::rng().fill(&mut k_ifd[..]);

    // Calculate K.ENC, E.IFD and M.IFD
    let (k_enc, e_ifd, m_ifd) = calculate_bac_eifd_and_mifd(
        rnd_ic,
        &rnd_ifd,
        &k_ifd,
        document_number,
        date_of_birth,
        date_of_expiry,
    );

    // Do EXTERNAL_AUTHENTICATION with the key and MAC we calculated.
    let external_auth_data = vec![e_ifd, m_ifd].concat();
    let mut apdu = iso7816::apdu_external_authentication(external_auth_data);
    let (rapdu, status_code) = apdu.exchange(port, false);
    // 0x6300 is what a document answers when the MAC it was sent does not verify, which
    // is to say when the key derived from the MRZ is not the one it holds. Asserting on
    // the status here used to turn a mistyped date into a panic.
    if status_code != iso7816::StatusCode::Ok as u16 {
        warn!(
            "The document rejected the authentication (0x{:04X}).",
            status_code
        );
        return None;
    }
    if rapdu.len() < 40 {
        warn!("The document's authentication response was too short to use.");
        return None;
    }
    info!("Successfully authenticated!");

    // Calculate session keys
    let (ks_enc, ks_mac) = calculate_bac_session_keys(
        &rapdu[0..40],
        k_enc.as_slice(),
        rnd_ifd.as_slice(),
        k_ifd.as_slice(),
    )?;

    // Calculate session counter
    let ssc = calculate_initial_ssc_bac(rnd_ic, &rnd_ifd);

    // Unlike PACE, BAC's counter doesn't start at zero.
    return Some(SecureMessaging::new_bac(ks_enc, ks_mac, ssc));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ICAO 9303 p11 Appendix D, the worked example for BAC. The document number
    /// is eight characters long, so every value below depends on it being padded
    /// out to the nine the MRZ field gives it.
    fn worked_example_fields() -> (String, String, String) {
        return (
            "L898902C".to_string(),
            "690806".to_string(),
            "940623".to_string(),
        );
    }

    #[test]
    fn document_number_is_padded_to_the_mrz_field_width() {
        assert_eq!(pad_document_number(&"L898902C".to_string()), "L898902C<");
        assert_eq!(pad_document_number(&"12345".to_string()), "12345<<<<");
        // Exactly nine characters is already the width of the field.
        assert_eq!(pad_document_number(&"T22000129".to_string()), "T22000129");
        // A TD1 number stitched back together from the optional data outgrows the
        // field and has to be left alone.
        assert_eq!(
            pad_document_number(&"AB1234567890".to_string()),
            "AB1234567890"
        );
    }

    /// The filler is trailing and `<` is worth zero, so padding never moves the
    /// check digit. An unpadded number therefore derives the wrong key without
    /// anything failing a checksum on the way.
    #[test]
    fn padding_does_not_move_the_check_digit() {
        assert_eq!(
            calculate_check_digit(&"L898902C".to_string()),
            calculate_check_digit(&"L898902C<".to_string())
        );
    }

    #[test]
    fn mrz_information_matches_worked_example() {
        let (document_number, date_of_birth, date_of_expiry) = worked_example_fields();
        assert_eq!(
            mrz_information(&document_number, &date_of_birth, &date_of_expiry),
            b"L898902C<369080619406236".to_vec()
        );
    }

    /// Appendix D quotes K.enc, E.IFD and M.IFD for the randoms below. Passing the
    /// document number in unpadded, as this did before, changes K.seed and with it
    /// every value here.
    #[test]
    fn bac_key_derivation_matches_worked_example() {
        let (document_number, date_of_birth, date_of_expiry) = worked_example_fields();
        let rnd_ic = vec![0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12];
        let rnd_ifd = vec![0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26];
        let k_ifd = vec![
            0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80,
            0x4F, 0x0B,
        ];

        let (k_enc, e_ifd, m_ifd) = calculate_bac_eifd_and_mifd(
            &rnd_ic,
            &rnd_ifd,
            &k_ifd,
            &document_number,
            &date_of_birth,
            &date_of_expiry,
        );

        // Appendix D quotes K.enc with DES parity bits set. passauf leaves the
        // low bit of each key byte as the KDF produced it, and DES drops that bit
        // during the key schedule, so the two keys are the same key. E.IFD and
        // M.IFD below are the proof: they go on the wire and match exactly.
        let appendix_d_k_enc = vec![
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F,
            0x76, 0xF2,
        ];
        let without_parity = |key: &Vec<u8>| -> Vec<u8> {
            return key.iter().map(|byte| byte & 0xFE).collect();
        };
        assert_eq!(without_parity(&k_enc), without_parity(&appendix_d_k_enc));
        assert_eq!(
            e_ifd,
            vec![
                0x72, 0xC2, 0x9C, 0x23, 0x71, 0xCC, 0x9B, 0xDB, 0x65, 0xB7, 0x79, 0xB8, 0xE8, 0xD3,
                0x7B, 0x29, 0xEC, 0xC1, 0x54, 0xAA, 0x56, 0xA8, 0x79, 0x9F, 0xAE, 0x2F, 0x49, 0x8F,
                0x76, 0xED, 0x92, 0xF2
            ]
        );
        assert_eq!(m_ifd, vec![0x5F, 0x14, 0x48, 0xEE, 0xA8, 0xAD, 0x90, 0xA7]);
    }
}
