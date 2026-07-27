///! The Integrated Mapping of ICAO 9303 p11 section 4.4.3.3.2
///
/// Where the Generic Mapping does a second key exchange to reach a fresh
/// generator, the Integrated Mapping derives one directly: a pseudo-random
/// function turns the two nonces into a field element, which is then mapped
/// onto the group.
use cbc::cipher::{inout::block_padding, BlockModeEncrypt, KeyIvInit};
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, NonZero, Odd, Resize};

use crate::pace::domain::EcParameters;
use crate::secure_messaging::SmAlgorithm;

/// The constants of ICAO 9303 p11 section 4.4.3.3.2, for a 128-bit output.
const C0_128: [u8; 16] = [
    0xA6, 0x68, 0x89, 0x2A, 0x7C, 0x41, 0xE3, 0xCA, 0x73, 0x9F, 0x40, 0xB0, 0x57, 0xD8, 0x59, 0x04,
];
const C1_128: [u8; 16] = [
    0xA4, 0xE1, 0x36, 0xAC, 0x72, 0x5F, 0x73, 0x8B, 0x01, 0xC1, 0xF6, 0x02, 0x17, 0xC1, 0x88, 0xAD,
];

/// And for a 256-bit output.
const C0_256: [u8; 32] = [
    0xD4, 0x63, 0xD6, 0x52, 0x34, 0x12, 0x4E, 0xF7, 0x89, 0x70, 0x54, 0x98, 0x6D, 0xCA, 0x0A, 0x17,
    0x4E, 0x28, 0xDF, 0x75, 0x8C, 0xBA, 0xA0, 0x3F, 0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A, 0x16, 0x76,
];
const C1_256: [u8; 32] = [
    0x54, 0xBD, 0x72, 0x55, 0xF0, 0xAA, 0xF8, 0x31, 0xBE, 0xC3, 0x42, 0x3F, 0xCF, 0x39, 0xD6, 0x9B,
    0x6C, 0xBF, 0x06, 0x66, 0x77, 0xD0, 0xFA, 0xAE, 0x5A, 0xAD, 0xD9, 0x9D, 0xF8, 0xE5, 0x35, 0x17,
];

/// Encrypt in CBC mode with an all-zero IV, under a key of the algorithm's size.
fn cbc_encrypt(algorithm: SmAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    // The key comes from the previous round's output, which is as wide as the
    // PRF's output rather than the cipher's key. 4.4.3.3.2: "Where required,
    // the output ki MUST be truncated to key size k", which only bites for
    // AES-192.
    let key = &key[..algorithm.key_length()];
    return match algorithm {
        // 4.4.3.3.2: "In case of DES, k is considered to be equal to 128 bits,
        // and the output of R(s,t) shall be 128 bits", so 3DES runs with a
        // 16-byte key and an 8-byte block like everywhere else.
        SmAlgorithm::Tdes => cbc::Encryptor::<des::TdesEde2>::new_from_slices(key, &[0u8; 8])
            .unwrap()
            .encrypt_padded_vec::<block_padding::NoPadding>(data),
        SmAlgorithm::Aes128 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .encrypt_padded_vec::<block_padding::NoPadding>(data),
        SmAlgorithm::Aes192 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .encrypt_padded_vec::<block_padding::NoPadding>(data),
        SmAlgorithm::Aes256 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16])
            .unwrap()
            .encrypt_padded_vec::<block_padding::NoPadding>(data),
    };
}

/// The width `l` of the PRF's output blocks, in bytes.
///
/// 4.4.3.3.3: `l` is the smallest multiple of the cipher's block size that is
/// at least the key size `k`.
fn output_block_length(algorithm: SmAlgorithm) -> usize {
    return match algorithm {
        // DES counts as a 128-bit key here, per the note in 4.4.3.3.2.
        SmAlgorithm::Tdes | SmAlgorithm::Aes128 => 16,
        SmAlgorithm::Aes192 | SmAlgorithm::Aes256 => 32,
    };
}

fn constants(algorithm: SmAlgorithm) -> (&'static [u8], &'static [u8]) {
    return match output_block_length(algorithm) {
        16 => (C0_128.as_slice(), C1_128.as_slice()),
        _ => (C0_256.as_slice(), C1_256.as_slice()),
    };
}

/// The pseudo-random function `R(s, t)` of ICAO 9303 p11 Figure 2.
///
/// Produces `n` blocks, where `n` is the smallest number with
/// `n * l >= log2(p) + 64`.
///
/// Note the nonces' roles: the chip's nonce `s` is the *data* of the first
/// encryption and the terminal's nonce `t` is its *key*. Figure 2 draws this
/// ambiguously, and getting it the wrong way round still produces
/// plausible-looking output.
pub fn pseudo_random(
    algorithm: SmAlgorithm,
    nonce_s: &[u8],
    nonce_t: &[u8],
    prime_bits: usize,
) -> Vec<u8> {
    let (c0, c1) = constants(algorithm);
    let block_length = output_block_length(algorithm);
    let blocks_needed = (prime_bits + 64).div_ceil(block_length * 8);

    // k0 = E(t, s)
    let mut key = cbc_encrypt(algorithm, nonce_t, nonce_s);
    let mut output: Vec<u8> = vec![];
    for _ in 0..blocks_needed {
        // x_i = E(k_{i-1}, c1), then k_i = E(k_{i-1}, c0)
        output.extend_from_slice(&cbc_encrypt(algorithm, &key, c1));
        key = cbc_encrypt(algorithm, &key, c0);
    }
    return output;
}

/// `R_p(s, t)`, the pseudo-random output reduced into the prime field.
pub fn pseudo_random_in_field(
    algorithm: SmAlgorithm,
    nonce_s: &[u8],
    nonce_t: &[u8],
    prime: &[u8],
) -> Vec<u8> {
    let prime_bits = prime.len() * 8;
    let raw = pseudo_random(algorithm, nonce_s, nonce_t, prime_bits);

    // Reduce at a precision wide enough to hold the raw output.
    let precision = (raw.len() * 8).max(prime_bits) as u32;
    let value = BoxedUint::from_be_slice(&raw, precision).expect("PRF output is malformed.");
    let modulus = NonZero::new(
        BoxedUint::from_be_slice(prime, prime_bits as u32)
            .expect("Prime is malformed.")
            .resize(precision),
    )
    .expect("Prime is never zero.");

    let reduced = (value % modulus).resize(prime_bits as u32);
    let mut encoded = vec![0u8; prime.len()];
    let bytes = reduced.to_be_bytes();
    encoded.copy_from_slice(&bytes[bytes.len() - prime.len()..]);
    return encoded;
}

/// Modular arithmetic helper over a curve's prime field.
struct PrimeField {
    params: BoxedMontyParams,
    p: BoxedUint,
    bits: u32,
    length: usize,
}

impl PrimeField {
    fn new(prime: &[u8]) -> PrimeField {
        let bits = (prime.len() * 8) as u32;
        let p = BoxedUint::from_be_slice(prime, bits).expect("Prime is malformed.");
        let odd_p = Odd::new(p.clone())
            .into_option()
            .expect("A curve's prime is always odd.");
        return PrimeField {
            params: BoxedMontyParams::new(odd_p),
            p,
            bits,
            length: prime.len(),
        };
    }

    fn element(&self, bytes: &[u8]) -> BoxedMontyForm {
        let value =
            BoxedUint::from_be_slice(bytes, self.bits).expect("Field element is malformed.");
        return BoxedMontyForm::new(value, &self.params);
    }

    fn one(&self) -> BoxedMontyForm {
        return self.element(&{
            let mut one = vec![0u8; self.length];
            one[self.length - 1] = 1;
            one
        });
    }

    fn encode(&self, value: &BoxedMontyForm) -> Vec<u8> {
        let bytes = value.retrieve().to_be_bytes();
        let mut encoded = vec![0u8; self.length];
        encoded.copy_from_slice(&bytes[bytes.len() - self.length..]);
        return encoded;
    }
}

/// The ECDH point encoding of ICAO 9303 p11 Appendix B.2.
///
/// Maps a field element onto a point of the curve's prime order subgroup, in
/// affine coordinates. Returns `(x, y)` as field-width big-endian bytes.
///
/// The encoding requires `p = 3 mod 4`, which holds for every curve we support.
/// ICAO 9303 excludes NIST P-224 from the Integrated Mapping for this reason.
pub fn point_encoding(
    parameters: &EcParameters,
    field_element: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let field = PrimeField::new(parameters.p);
    let a = field.element(parameters.a);
    let b = field.element(parameters.b);
    let u = field.element(field_element);
    let one = field.one();

    // 1. alpha = -u^2 mod p
    let alpha = -(u.clone() * u.clone());

    // 2. X2 = -b * a^-1 * (1 + (alpha + alpha^2)^-1) mod p
    let alpha_sum = alpha.clone() + (alpha.clone() * alpha.clone());
    let alpha_sum_inverse: BoxedMontyForm = alpha_sum.invert().into_option()?;
    let a_inverse: BoxedMontyForm = a.clone().invert().into_option()?;
    let x2 = -(b.clone() * a_inverse * (one.clone() + alpha_sum_inverse));

    // 3. X3 = alpha * X2 mod p
    let x3 = alpha * x2.clone();

    // 4. h2 = X2^3 + a * X2 + b mod p
    let h2 = (x2.clone() * x2.clone() * x2.clone()) + (a.clone() * x2.clone()) + b.clone();

    // Step 5 of the appendix computes h3, but steps 8 and 9 never use it, so
    // it is left out here.

    // 6. U = u^3 * h2 mod p
    let big_u = u.clone() * u.clone() * u.clone() * h2.clone();

    // 7. A = h2^(p - 1 - (p + 1) / 4) mod p
    let four = NonZero::new(BoxedUint::from(4u8).resize(field.bits)).expect("4 is never zero.");
    let one_uint = BoxedUint::one_with_precision(field.bits);
    let exponent = field
        .p
        .wrapping_sub(&one_uint)
        .wrapping_sub(&(field.p.wrapping_add(&one_uint) / four));
    let big_a = h2.pow(&exponent);

    // 8/9. Take (X2, A * h2) when A^2 * h2 == 1, otherwise (X3, A * U).
    let (x, y) = if (big_a.clone() * big_a.clone() * h2.clone()) == one {
        (x2, big_a * h2)
    } else {
        (x3, big_a * big_u)
    };

    // 10. Multiply by the cofactor, which is 1 for every curve we support, so
    // there is nothing left to do.
    return Some((field.encode(&x), field.encode(&y)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pace::domain::EcCurve;
    use crate::pace::ecdh;

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect();
    }

    /// ICAO 9303 p11 Appendix H.1 quotes R(s,t) in full.
    #[test]
    fn pseudo_random_matches_worked_example() {
        let nonce_s = hex("2923BE84E16CD6AE529049F1F1BBE9EB");
        let nonce_t = hex("5DD4CBFC96F5453B130D890A1CDBAE32");
        let expected = hex("E4447E2DFB3586BAC05DDB00156B57FB
             B2179A3949294C97254189800C517BAA
             8DA0FF397ED8C445D3E421E4FEB57322");
        // BrainpoolP256r1, so a 256-bit prime.
        assert_eq!(
            pseudo_random(SmAlgorithm::Aes128, &nonce_s, &nonce_t, 256),
            expected
        );
    }

    /// Swapping the two nonces must not silently produce the same answer, since
    /// that is the easy mistake to make reading Figure 2.
    #[test]
    fn pseudo_random_is_not_symmetric_in_its_nonces() {
        let nonce_s = hex("2923BE84E16CD6AE529049F1F1BBE9EB");
        let nonce_t = hex("5DD4CBFC96F5453B130D890A1CDBAE32");
        assert_ne!(
            pseudo_random(SmAlgorithm::Aes128, &nonce_s, &nonce_t, 256),
            pseudo_random(SmAlgorithm::Aes128, &nonce_t, &nonce_s, 256)
        );
    }

    /// And the reduced form R_p(s,t).
    #[test]
    fn pseudo_random_in_field_matches_worked_example() {
        let nonce_s = hex("2923BE84E16CD6AE529049F1F1BBE9EB");
        let nonce_t = hex("5DD4CBFC96F5453B130D890A1CDBAE32");
        let parameters = EcCurve::BrainpoolP256r1.parameters().unwrap();
        assert_eq!(
            pseudo_random_in_field(SmAlgorithm::Aes128, &nonce_s, &nonce_t, parameters.p),
            hex("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E")
        );
    }

    /// ICAO 9303 p11 Appendix H.1, the mapped generator.
    #[test]
    fn point_encoding_matches_worked_example() {
        let parameters = EcCurve::BrainpoolP256r1.parameters().unwrap();
        let field_element = hex("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E");
        let (x, y) = point_encoding(parameters, &field_element).unwrap();
        assert_eq!(
            x,
            hex("8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427")
        );
        assert_eq!(
            y,
            hex("4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD")
        );
    }

    /// End to end: the two nonces of Appendix H.1 produce its mapped generator,
    /// and it is a real point on the curve.
    #[test]
    fn integrated_mapping_end_to_end() {
        let nonce_s = hex("2923BE84E16CD6AE529049F1F1BBE9EB");
        let nonce_t = hex("5DD4CBFC96F5453B130D890A1CDBAE32");
        let curve = EcCurve::BrainpoolP256r1;
        let parameters = curve.parameters().unwrap();

        let field_element =
            pseudo_random_in_field(SmAlgorithm::Aes128, &nonce_s, &nonce_t, parameters.p);
        let (x, y) = point_encoding(parameters, &field_element).unwrap();

        // The curve implementation must accept it, which independently confirms
        // it satisfies the curve equation.
        let ops = ecdh::ops_for(curve).unwrap();
        let mapped_generator = ops.point_from_coordinates(&x, &y).unwrap();
        assert_eq!(
            mapped_generator,
            vec![
                vec![0x04],
                hex("8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427"),
                hex("4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD"),
            ]
            .concat()
        );
    }

    /// The point encoding must land on the curve for every supported curve and
    /// any input, not just the one the appendix happens to use.
    #[test]
    fn point_encoding_always_lands_on_the_curve() {
        for curve in [
            EcCurve::NistP256,
            EcCurve::NistP384,
            EcCurve::NistP521,
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
        ] {
            let parameters = curve.parameters().unwrap();
            let ops = ecdh::ops_for(curve).unwrap();
            for seed in 1u8..6 {
                let field_element = vec![seed; parameters.p.len()];
                let (x, y) = point_encoding(parameters, &field_element)
                    .unwrap_or_else(|| panic!("{} failed to encode seed {}", curve, seed));
                assert!(
                    ops.point_from_coordinates(&x, &y).is_some(),
                    "{} produced an off-curve point for seed {}",
                    curve,
                    seed
                );
            }
        }
    }

    /// The transcribed curve parameters have to agree with the curve crates.
    ///
    /// Each crate's own generator is checked against `y^2 = x^3 + ax + b mod p`
    /// using our constants, which would catch any transcription error.
    #[test]
    fn curve_parameters_agree_with_the_curve_crates() {
        for curve in [
            EcCurve::NistP256,
            EcCurve::NistP384,
            EcCurve::NistP521,
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
        ] {
            let parameters = curve.parameters().unwrap();
            let ops = ecdh::ops_for(curve).unwrap();
            let field_size = ops.field_size();
            assert_eq!(parameters.p.len(), field_size, "{} prime width", curve);

            let generator = ops.generator();
            let x = &generator[1..1 + field_size];
            let y = &generator[1 + field_size..];

            let field = PrimeField::new(parameters.p);
            let a = field.element(parameters.a);
            let b = field.element(parameters.b);
            let x = field.element(x);
            let y = field.element(y);

            assert_eq!(
                y.clone() * y,
                (x.clone() * x.clone() * x.clone()) + (a * x) + b,
                "{}'s generator does not satisfy our curve equation",
                curve
            );
        }
    }

    /// The PRF's block width and round count follow the cipher.
    #[test]
    fn output_length_follows_the_cipher_and_prime() {
        let nonce = [0u8; 32];
        // 3DES and AES-128 emit 128-bit blocks, so a 256-bit prime needs
        // ceil(320/128) = 3 of them.
        assert_eq!(
            pseudo_random(SmAlgorithm::Aes128, &nonce[..16], &nonce[..16], 256).len(),
            48
        );
        // AES-256 emits 256-bit blocks, so the same prime needs 2.
        assert_eq!(
            pseudo_random(SmAlgorithm::Aes256, &nonce, &nonce, 256).len(),
            64
        );
        // A 521-bit prime needs ceil(585/128) = 5 blocks at 128 bits.
        assert_eq!(
            pseudo_random(SmAlgorithm::Aes128, &nonce[..16], &nonce[..16], 521).len(),
            80
        );
    }
}
