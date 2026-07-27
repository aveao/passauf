///! Secure messaging session state (ICAO 9303 p11 section 9.8)
///
/// BAC only ever uses 3DES, but PACE picks its cipher from the OID the document
/// offers, so everything the session needs to encrypt, authenticate and count
/// lives behind one type rather than being threaded around as loose values.
use cbc::cipher::BlockCipherEncrypt;
use cbc::cipher::{inout::block_padding, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use cmac::{Cmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;

type TDesCbcEnc = cbc::Encryptor<des::TdesEde2>;
type TDesCbcDec = cbc::Decryptor<des::TdesEde2>;

/// The ciphers ICAO 9303 allows for secure messaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmAlgorithm {
    /// Two-key 3DES in CBC mode with a Retail-MAC. The only option for BAC.
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

impl SmAlgorithm {
    /// Key length in bytes.
    pub fn key_length(&self) -> usize {
        return match self {
            // Two-key EDE, so 16 rather than 24.
            SmAlgorithm::Tdes => 16,
            SmAlgorithm::Aes128 => 16,
            SmAlgorithm::Aes192 => 24,
            SmAlgorithm::Aes256 => 32,
        };
    }

    /// Block size in bytes. This is also the width of the send sequence counter.
    pub fn block_size(&self) -> usize {
        return match self {
            SmAlgorithm::Tdes => 8,
            _ => 16,
        };
    }

    /// ICAO 9303 p11 section 9.7.1: SHA-1 derives 3DES and AES-128 keys,
    /// SHA-256 derives AES-192 and AES-256 keys.
    pub fn uses_sha1_kdf(&self) -> bool {
        return matches!(self, SmAlgorithm::Tdes | SmAlgorithm::Aes128);
    }
}

/// Applies Padding Method 2 based on ISO 9797-1.
///
/// Takes the data and returns a new Vec with the appropriate padding.
pub fn padding_method_2_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    // block_padding::Iso7816 is pretty close to this, but it has one key difference:
    // This function adds a full block of padding when data is block size-aligned.
    // block_padding::Iso7816, however, does not. IME, this can make or break the comms.
    let padding_to_append = block_size - (input.len() % block_size);
    let mut padding = vec![0x00u8; padding_to_append];
    padding[0] = 0x80;
    return vec![input, padding.as_slice()].concat();
}

/// Undoes Padding Method 2 based on ISO 9797-1.
///
/// Returns None when the data isn't padded that way.
pub fn padding_method_2_unpad_checked(input: &[u8]) -> Option<Vec<u8>> {
    // Walk back over the trailing zeroes to the 0x80 marker.
    let mut end = input.len();
    while end > 0 {
        end -= 1;
        match input[end] {
            0x00 => continue,
            0x80 => return Some(input[..end].to_vec()),
            // Anything else means this was never padded this way.
            _ => break,
        }
    }
    return None;
}

/// Undoes Padding Method 2 based on ISO 9797-1.
///
/// Takes the data and returns a new Vec without the padding.
pub fn padding_method_2_unpad(input: &[u8]) -> Vec<u8> {
    return padding_method_2_unpad_checked(input)
        .expect("Data is not padded according to padding method 2.");
}

/// The key derivation function KDF(K, c) of ICAO 9303 p11 section 9.7.1.
///
/// The hash is picked by the target key length and the output truncated to it.
pub fn kdf(algorithm: SmAlgorithm, shared_secret: &[u8], counter: u32) -> Vec<u8> {
    let input = vec![shared_secret, &counter.to_be_bytes()].concat();
    let keydata = if algorithm.uses_sha1_kdf() {
        let mut hasher = Sha1::new();
        hasher.update(input.as_slice());
        hasher.finalize().to_vec()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(input.as_slice());
        hasher.finalize().to_vec()
    };
    return keydata[..algorithm.key_length()].to_vec();
}

/// Decrypt in CBC mode with an all-zero IV.
///
/// PACE's encrypted nonce uses this rather than the session's IV rule
/// (ICAO 9303 p11 section 4.4.3.3), so it sits outside [`SecureMessaging`].
#[cfg(feature = "pace")]
pub fn cbc_decrypt_zero_iv(algorithm: SmAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    return match algorithm {
        SmAlgorithm::Tdes => TDesCbcDec::new_from_slices(key, &[0u8; 8])
            .unwrap()
            .decrypt_padded_vec::<block_padding::NoPadding>(data)
            .unwrap(),
        SmAlgorithm::Aes128 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .decrypt_padded_vec::<block_padding::NoPadding>(data)
            .unwrap(),
        SmAlgorithm::Aes192 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .decrypt_padded_vec::<block_padding::NoPadding>(data)
            .unwrap(),
        SmAlgorithm::Aes256 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .decrypt_padded_vec::<block_padding::NoPadding>(data)
            .unwrap(),
    };
}

/// An established secure messaging session.
#[derive(Debug)]
pub struct SecureMessaging {
    pub algorithm: SmAlgorithm,
    ks_enc: Vec<u8>,
    ks_mac: Vec<u8>,
    /// Send sequence counter, one block wide, big-endian.
    ssc: Vec<u8>,
}

impl SecureMessaging {
    /// Build a session from derived keys, with the send sequence counter at zero.
    ///
    /// PACE starts every session this way.
    pub fn new(algorithm: SmAlgorithm, ks_enc: Vec<u8>, ks_mac: Vec<u8>) -> SecureMessaging {
        assert!(ks_enc.len() == algorithm.key_length());
        assert!(ks_mac.len() == algorithm.key_length());
        return SecureMessaging {
            algorithm,
            ks_enc,
            ks_mac,
            ssc: vec![0u8; algorithm.block_size()],
        };
    }

    /// Build a 3DES session whose counter starts at a given value.
    ///
    /// BAC derives its initial counter from the two nonces rather than starting
    /// at zero, so it needs this instead of [`SecureMessaging::new`].
    pub fn new_bac(ks_enc: Vec<u8>, ks_mac: Vec<u8>, ssc: u64) -> SecureMessaging {
        return SecureMessaging {
            algorithm: SmAlgorithm::Tdes,
            ks_enc,
            ks_mac,
            ssc: ssc.to_be_bytes().to_vec(),
        };
    }

    pub fn block_size(&self) -> usize {
        return self.algorithm.block_size();
    }

    /// The current send sequence counter, as the block-wide big-endian value
    /// that goes into MAC computations.
    pub fn ssc(&self) -> &[u8] {
        return self.ssc.as_slice();
    }

    /// Increment the send sequence counter by one.
    pub fn bump_ssc(&mut self) {
        // Big-endian increment with carry, so this works at any counter width.
        for byte in self.ssc.iter_mut().rev() {
            let (incremented, overflowed) = byte.overflowing_add(1);
            *byte = incremented;
            if !overflowed {
                return;
            }
        }
        // Wrapping all the way around would take 2^64 messages for 3DES. If we
        // ever get here the counter has silently desynchronized from the chip.
        panic!("Send sequence counter overflowed.");
    }

    /// Pad data with padding method 2 at this session's block size.
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        return padding_method_2_pad(data, self.block_size());
    }

    /// Encrypt a single block with the session's encryption key in ECB mode.
    ///
    /// Used to derive initialisation vectors, which is the only place ICAO 9303
    /// applies the raw block cipher.
    fn encrypt_block_ecb(&self, block: [u8; 16]) -> Vec<u8> {
        let mut block = block.into();
        match self.algorithm {
            SmAlgorithm::Aes128 => aes::Aes128::new_from_slice(&self.ks_enc)
                .unwrap()
                .encrypt_block(&mut block),
            SmAlgorithm::Aes192 => aes::Aes192::new_from_slice(&self.ks_enc)
                .unwrap()
                .encrypt_block(&mut block),
            SmAlgorithm::Aes256 => aes::Aes256::new_from_slice(&self.ks_enc)
                .unwrap()
                .encrypt_block(&mut block),
            // 3DES has a different block size and never needs this.
            SmAlgorithm::Tdes => unreachable!("3DES derives no IV from a block cipher."),
        }
        return block.to_vec();
    }

    /// The CBC initialisation vector for the current counter value.
    ///
    /// ICAO 9303 p11 section 9.8.6.1 has 3DES use an all-zero IV, while AES
    /// encrypts the send sequence counter in ECB mode to produce one.
    fn iv(&self) -> Vec<u8> {
        return match self.algorithm {
            SmAlgorithm::Tdes => vec![0u8; 8],
            _ => {
                let mut block = [0u8; 16];
                block.copy_from_slice(&self.ssc);
                self.encrypt_block_ecb(block)
            }
        };
    }

    /// Encrypt already-padded data.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let iv = self.iv();
        return match self.algorithm {
            SmAlgorithm::Tdes => TDesCbcEnc::new_from_slices(&self.ks_enc, &iv)
                .unwrap()
                .encrypt_padded_vec::<block_padding::NoPadding>(data),
            SmAlgorithm::Aes128 => {
                cbc::Encryptor::<aes::Aes128>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .encrypt_padded_vec::<block_padding::NoPadding>(data)
            }
            SmAlgorithm::Aes192 => {
                cbc::Encryptor::<aes::Aes192>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .encrypt_padded_vec::<block_padding::NoPadding>(data)
            }
            SmAlgorithm::Aes256 => {
                cbc::Encryptor::<aes::Aes256>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .encrypt_padded_vec::<block_padding::NoPadding>(data)
            }
        };
    }

    /// Decrypt data, leaving any padding in place.
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let iv = self.iv();
        return match self.algorithm {
            SmAlgorithm::Tdes => TDesCbcDec::new_from_slices(&self.ks_enc, &iv)
                .unwrap()
                .decrypt_padded_vec::<block_padding::NoPadding>(data)
                .unwrap(),
            SmAlgorithm::Aes128 => {
                cbc::Decryptor::<aes::Aes128>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .unwrap()
            }
            SmAlgorithm::Aes192 => {
                cbc::Decryptor::<aes::Aes192>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .unwrap()
            }
            SmAlgorithm::Aes256 => {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.ks_enc, &iv)
                    .unwrap()
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .unwrap()
            }
        };
    }

    /// Decrypt the Encrypted Chip Authentication Data of PACE-CAM
    /// (ICAO 9303 p11 section 4.4.3.5.4).
    ///
    /// This uses the session's encryption key but its own initialisation
    /// vector, `E(KS_enc, -1)` where `-1` is 128 bits all set, rather than the
    /// counter-derived one secure messaging uses. Returns the unpadded value.
    ///
    /// Returns None if the input isn't a whole number of blocks or isn't
    /// padded the way the standard requires.
    #[cfg(feature = "pace")]
    pub fn decrypt_chip_authentication_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        // Chip Authentication Mapping is ECDH-only, and every PACE ECDH variant
        // uses AES, so 3DES cannot come up here.
        if self.algorithm == SmAlgorithm::Tdes {
            return None;
        }
        if data.is_empty() || data.len() % self.block_size() != 0 {
            return None;
        }

        let iv = self.encrypt_block_ecb([0xFFu8; 16]);
        let decrypted = match self.algorithm {
            SmAlgorithm::Aes128 => {
                cbc::Decryptor::<aes::Aes128>::new_from_slices(&self.ks_enc, &iv)
                    .ok()?
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .ok()?
            }
            SmAlgorithm::Aes192 => {
                cbc::Decryptor::<aes::Aes192>::new_from_slices(&self.ks_enc, &iv)
                    .ok()?
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .ok()?
            }
            SmAlgorithm::Aes256 => {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.ks_enc, &iv)
                    .ok()?
                    .decrypt_padded_vec::<block_padding::NoPadding>(data)
                    .ok()?
            }
            SmAlgorithm::Tdes => unreachable!(),
        };
        // 4.4.3.5.3: padding method 2. The chip controls this value, so a bad
        // padding is a protocol error rather than something to panic over.
        return padding_method_2_unpad_checked(&decrypted);
    }

    /// Authenticate exactly the bytes given, adding no padding of its own.
    ///
    /// 3DES needs block-aligned input here because ISO 9797-1 MAC algorithm 3
    /// has no internal padding; AES-CMAC accepts any length.
    pub fn mac(&self, data: &[u8]) -> Vec<u8> {
        return match self.algorithm {
            SmAlgorithm::Tdes => retail_mac(&self.ks_mac, data),
            SmAlgorithm::Aes128 => cmac_8(Cmac::<aes::Aes128>::new_from_slice(&self.ks_mac), data),
            SmAlgorithm::Aes192 => cmac_8(Cmac::<aes::Aes192>::new_from_slice(&self.ks_mac), data),
            SmAlgorithm::Aes256 => cmac_8(Cmac::<aes::Aes256>::new_from_slice(&self.ks_mac), data),
        };
    }

    /// Authenticate data, padding it first if the algorithm needs it.
    ///
    /// ICAO 9303 p11 section 4.4.3.4 says the PACE authentication token applies
    /// no padding of its own because the MAC handles it, which is true of
    /// AES-CMAC but not of the 3DES Retail-MAC.
    pub fn mac_with_internal_padding(&self, data: &[u8]) -> Vec<u8> {
        return match self.algorithm {
            SmAlgorithm::Tdes => self.mac(&self.pad(data)),
            _ => self.mac(data),
        };
    }
}

/// Applies Retail MAC based on ISO 9797-1.
///
/// Does not apply padding method 2, it should be done separately.
pub fn retail_mac(k_mac: &[u8], input_data: &[u8]) -> Vec<u8> {
    let mut rmac_instance = retail_mac::RetailMac::<des::Des>::new_from_slice(k_mac).unwrap();
    retail_mac::Mac::update(&mut rmac_instance, input_data);
    return retail_mac::Mac::finalize(rmac_instance).as_bytes().to_vec();
}

/// Computes a CMAC and truncates it to the 8 bytes ICAO 9303 asks for.
fn cmac_8<M: Mac>(mac: Result<M, cmac::digest::InvalidLength>, data: &[u8]) -> Vec<u8> {
    let mut mac = mac.unwrap();
    mac.update(data);
    return mac.finalize().into_bytes()[..8].to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_method_2_always_adds_a_marker() {
        // Partial block gets topped up.
        assert_eq!(
            padding_method_2_pad(&[0x01, 0x02, 0x03], 8),
            vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]
        );
        // A block-aligned input gains a whole extra block, which is the
        // behaviour that differs from block_padding::Iso7816.
        assert_eq!(
            padding_method_2_pad(&[0u8; 8], 8),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]
        );
        // Same rules at the AES block size.
        assert_eq!(padding_method_2_pad(&[0u8; 16], 16).len(), 32);
        assert_eq!(padding_method_2_pad(&[0u8; 3], 16).len(), 16);
    }

    #[test]
    fn padding_round_trips() {
        for block_size in [8usize, 16] {
            for length in 0..40 {
                let data = vec![0xABu8; length];
                let padded = padding_method_2_pad(&data, block_size);
                assert_eq!(padded.len() % block_size, 0);
                assert_eq!(padding_method_2_unpad(&padded), data);
            }
        }
    }

    #[test]
    fn send_sequence_counter_carries() {
        let mut sm = SecureMessaging::new(SmAlgorithm::Aes128, vec![0u8; 16], vec![0u8; 16]);
        assert_eq!(sm.ssc(), [0u8; 16]);
        sm.bump_ssc();
        assert_eq!(sm.ssc()[15], 1);

        // Force a carry across a byte boundary.
        let mut sm = SecureMessaging::new(SmAlgorithm::Aes128, vec![0u8; 16], vec![0u8; 16]);
        for _ in 0..256 {
            sm.bump_ssc();
        }
        assert_eq!(sm.ssc()[14], 1);
        assert_eq!(sm.ssc()[15], 0);
    }

    #[test]
    fn bac_counter_starts_where_it_is_told() {
        let sm = SecureMessaging::new_bac(vec![0u8; 16], vec![0u8; 16], 0x0102030405060708);
        assert_eq!(sm.ssc(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(sm.block_size(), 8);
    }

    /// Adjust each byte to odd parity, forming proper DES keys.
    ///
    /// ICAO 9303 p11 section 9.7.1.1 makes this step optional and the des crate
    /// ignores parity bits entirely, so [`kdf`] skips it. The worked examples
    /// nonetheless quote the adjusted keys, so the tests need it to compare.
    fn adjust_des_parity(key: &[u8]) -> Vec<u8> {
        return key
            .iter()
            .map(|byte| {
                let without_parity = byte & 0xFE;
                return without_parity | (1 - (without_parity.count_ones() as u8 & 1));
            })
            .collect();
    }

    /// ICAO 9303 p11 Appendix D.1 works through the BAC key derivation.
    ///
    /// The appendix lists the parity-adjusted keys, so that adjustment has to
    /// be applied before the values line up.
    #[test]
    fn kdf_matches_bac_worked_example() {
        let k_seed = [
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66, 0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B,
            0xFB, 0xAE,
        ];
        assert_eq!(
            adjust_des_parity(&kdf(SmAlgorithm::Tdes, &k_seed, 1)),
            vec![
                0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F,
                0x76, 0xF2
            ]
        );
        assert_eq!(
            adjust_des_parity(&kdf(SmAlgorithm::Tdes, &k_seed, 2)),
            vec![
                0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD, 0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13,
                0x15, 0x43
            ]
        );
    }

    /// The KDF deliberately leaves parity bits alone, so its raw output differs
    /// from the appendix in exactly those bits and nowhere else.
    #[test]
    fn kdf_leaves_parity_bits_untouched() {
        let k_seed = [
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66, 0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B,
            0xFB, 0xAE,
        ];
        let raw = kdf(SmAlgorithm::Tdes, &k_seed, 1);
        let adjusted = adjust_des_parity(&raw);
        assert_ne!(raw, adjusted);
        // Every difference is confined to the low bit of some byte.
        for (raw_byte, adjusted_byte) in raw.iter().zip(adjusted.iter()) {
            assert_eq!(raw_byte & 0xFE, adjusted_byte & 0xFE);
        }
    }

    /// The KDF truncates to the key length, and switches hash above AES-128.
    #[test]
    fn kdf_output_lengths_follow_the_algorithm() {
        let secret = [0x42u8; 32];
        assert_eq!(kdf(SmAlgorithm::Tdes, &secret, 1).len(), 16);
        assert_eq!(kdf(SmAlgorithm::Aes128, &secret, 1).len(), 16);
        assert_eq!(kdf(SmAlgorithm::Aes192, &secret, 1).len(), 24);
        assert_eq!(kdf(SmAlgorithm::Aes256, &secret, 1).len(), 32);
        // AES-128 and 3DES share SHA-1, so they agree on the first 16 bytes.
        assert_eq!(
            kdf(SmAlgorithm::Tdes, &secret, 1),
            kdf(SmAlgorithm::Aes128, &secret, 1)
        );
        // AES-256 uses SHA-256 instead, so it must not.
        assert_ne!(
            kdf(SmAlgorithm::Aes256, &secret, 1)[..16],
            kdf(SmAlgorithm::Aes128, &secret, 1)[..]
        );
    }

    #[test]
    fn encryption_round_trips_for_every_algorithm() {
        for algorithm in [
            SmAlgorithm::Tdes,
            SmAlgorithm::Aes128,
            SmAlgorithm::Aes192,
            SmAlgorithm::Aes256,
        ] {
            let sm = SecureMessaging::new(
                algorithm,
                vec![0x11u8; algorithm.key_length()],
                vec![0x22u8; algorithm.key_length()],
            );
            let plaintext = sm.pad(b"passauf");
            let ciphertext = sm.encrypt(&plaintext);
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_ne!(ciphertext, plaintext);
            assert_eq!(sm.decrypt(&ciphertext), plaintext);
        }
    }

    #[test]
    fn aes_iv_tracks_the_counter() {
        let mut sm = SecureMessaging::new(SmAlgorithm::Aes128, vec![0x11u8; 16], vec![0x22u8; 16]);
        let plaintext = sm.pad(b"passauf");
        let first = sm.encrypt(&plaintext);
        sm.bump_ssc();
        // The IV is derived from the counter, so the same plaintext must not
        // encrypt to the same ciphertext once the counter moves.
        assert_ne!(sm.encrypt(&plaintext), first);
    }

    #[test]
    fn mac_lengths_are_eight_bytes() {
        for algorithm in [
            SmAlgorithm::Tdes,
            SmAlgorithm::Aes128,
            SmAlgorithm::Aes192,
            SmAlgorithm::Aes256,
        ] {
            let sm = SecureMessaging::new(
                algorithm,
                vec![0x11u8; algorithm.key_length()],
                vec![0x22u8; algorithm.key_length()],
            );
            assert_eq!(sm.mac(&sm.pad(b"passauf")).len(), 8);
            assert_eq!(sm.mac_with_internal_padding(b"passauf").len(), 8);
        }
    }

    /// ICAO 9303 p11 Appendix I works through PACE-CAM, including the
    /// Encrypted Chip Authentication Data and the unusual IV it uses.
    #[cfg(feature = "pace")]
    #[test]
    fn decrypts_chip_authentication_data_from_worked_example() {
        let ks_enc = vec![
            0x0A, 0x9D, 0xA4, 0xDB, 0x03, 0xBD, 0xDE, 0x39, 0xFC, 0x52, 0x02, 0xBC, 0x44, 0xB2,
            0xE8, 0x9E,
        ];
        let sm = SecureMessaging::new(SmAlgorithm::Aes128, ks_enc, vec![0x11u8; 16]);

        // The IV is E(KS_enc, -1), not the counter-derived one.
        assert_eq!(
            sm.encrypt_block_ecb([0xFFu8; 16]),
            vec![
                0xF6, 0xA3, 0xB7, 0x5A, 0x1E, 0x93, 0x39, 0x41, 0xDD, 0x7A, 0x13, 0xE2, 0x52, 0x07,
                0x79, 0xDF
            ]
        );

        let encrypted = [
            0x1E, 0xEA, 0x96, 0x4D, 0xAA, 0xE3, 0x72, 0xAC, 0x99, 0x0E, 0x3E, 0xFD, 0xE6, 0x33,
            0x33, 0x53, 0xBF, 0xC8, 0x9A, 0x67, 0x04, 0xD9, 0x3D, 0xA8, 0x79, 0x8C, 0xF7, 0x7F,
            0x5B, 0x7A, 0x54, 0xBD, 0x10, 0xCB, 0xA3, 0x72, 0xB4, 0x2B, 0xE0, 0xB9, 0xB5, 0xF2,
            0x8A, 0xA8, 0xDE, 0x2F, 0x4F, 0x92,
        ];
        assert_eq!(
            sm.decrypt_chip_authentication_data(&encrypted).unwrap(),
            vec![
                0x85, 0xDC, 0x3F, 0xA9, 0x3D, 0x09, 0x52, 0xBF, 0xA8, 0x2F, 0x5F, 0xD1, 0x89, 0xEE,
                0x75, 0xBD, 0x82, 0xF1, 0x1D, 0x1F, 0x0B, 0x8E, 0xD4, 0xBF, 0x53, 0x19, 0xAC, 0x9B,
                0x53, 0xC4, 0x26, 0xB3
            ]
        );
    }

    /// The chip controls this data, so malformed input must be rejected rather
    /// than panicking the way the internal unpad does.
    #[cfg(feature = "pace")]
    #[test]
    fn rejects_malformed_chip_authentication_data() {
        let sm = SecureMessaging::new(SmAlgorithm::Aes128, vec![0x11u8; 16], vec![0x22u8; 16]);
        // Not a whole number of blocks.
        assert!(sm.decrypt_chip_authentication_data(&[0u8; 17]).is_none());
        // Empty.
        assert!(sm.decrypt_chip_authentication_data(&[]).is_none());
        // Whole blocks, but the plaintext won't carry valid padding.
        assert!(sm.decrypt_chip_authentication_data(&[0u8; 16]).is_none());
    }

    #[test]
    fn unpad_reports_bad_padding_instead_of_guessing() {
        assert_eq!(
            padding_method_2_unpad_checked(&[1, 2, 0x80]),
            Some(vec![1, 2])
        );
        // No 0x80 marker anywhere.
        assert!(padding_method_2_unpad_checked(&[1, 2, 3]).is_none());
        assert!(padding_method_2_unpad_checked(&[]).is_none());
    }

    /// AES-CMAC pads internally, 3DES does not, so only 3DES should see a
    /// difference between the padded and unpadded entry points.
    #[test]
    fn token_mac_only_pre_pads_for_3des() {
        let tdes = SecureMessaging::new(SmAlgorithm::Tdes, vec![0x11u8; 16], vec![0x22u8; 16]);
        assert_eq!(
            tdes.mac_with_internal_padding(b"passauf"),
            tdes.mac(&tdes.pad(b"passauf"))
        );

        let aes = SecureMessaging::new(SmAlgorithm::Aes128, vec![0x11u8; 16], vec![0x22u8; 16]);
        assert_eq!(
            aes.mac_with_internal_padding(b"passauf"),
            aes.mac(b"passauf")
        );
        assert_ne!(
            aes.mac_with_internal_padding(b"passauf"),
            aes.mac(&aes.pad(b"passauf"))
        );
    }
}
