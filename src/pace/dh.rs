///! DH key agreement over the standardized MODP groups for PACE
///
/// Values cross this module's boundary as fixed-width big-endian bytes, padded
/// to the width of the group's prime, which is how PACE encodes them on the
/// wire.
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, NonZero, Odd, RandomBits, Resize};

use crate::pace::domain::ModpGroup;

/// A MODP group with its values decoded and Montgomery parameters prepared.
pub struct DhGroupOps {
    p: BoxedUint,
    g: BoxedUint,
    q: BoxedUint,
    params: BoxedMontyParams,
    /// Width of the prime in bits, which every value is held at.
    bits: u32,
    /// Width of the prime in bytes, which every encoded value is padded to.
    length: usize,
    /// The prime as given, kept for callers that need it as bytes.
    prime_bytes: &'static [u8],
}

impl DhGroupOps {
    pub fn new(group: &ModpGroup) -> DhGroupOps {
        let bits = (group.p.len() * 8) as u32;
        let p = BoxedUint::from_be_slice(group.p, bits).expect("Group prime is malformed.");
        let odd_p = Odd::new(p.clone())
            .into_option()
            .expect("Group prime must be odd.");
        return DhGroupOps {
            g: BoxedUint::from_be_slice(group.g, bits).expect("Group generator is malformed."),
            q: BoxedUint::from_be_slice(group.q, bits).expect("Group order is malformed."),
            params: BoxedMontyParams::new(odd_p),
            p,
            bits,
            length: group.p.len(),
            prime_bytes: group.p,
        };
    }

    /// Encoded width of a group element in bytes.
    #[allow(dead_code)]
    pub fn length(&self) -> usize {
        return self.length;
    }

    /// The group's standard generator g, encoded.
    pub fn generator(&self) -> Vec<u8> {
        return self.encode(&self.g);
    }

    /// The group's prime p, encoded. The Integrated Mapping reduces into it.
    pub fn prime(&self) -> &'static [u8] {
        return self.prime_bytes;
    }

    fn decode(&self, bytes: &[u8]) -> Option<BoxedUint> {
        if bytes.len() > self.length {
            return None;
        }
        return BoxedUint::from_be_slice(bytes, self.bits).ok();
    }

    /// Encode a group element, left-padded to the width of the prime.
    fn encode(&self, value: &BoxedUint) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut encoded = vec![0u8; self.length];
        // to_be_bytes is already at the prime's precision, but be explicit so a
        // narrower value can never silently shift.
        let start = self.length.saturating_sub(bytes.len());
        let source = &bytes[bytes.len().saturating_sub(self.length)..];
        encoded[start..].copy_from_slice(source);
        return encoded;
    }

    fn monty(&self, value: &BoxedUint) -> BoxedMontyForm {
        return BoxedMontyForm::new(value.clone(), &self.params);
    }

    /// Raise a group element to a power modulo p.
    fn pow(&self, base: &BoxedUint, exponent: &BoxedUint) -> BoxedUint {
        return self.monty(base).pow(exponent).retrieve();
    }

    /// Validate a public key per RFC 2631, as ICAO 9303 p11 section 4.4.3.3.1
    /// requires to prevent small subgroup attacks.
    ///
    /// A valid key sits in `2..=p-2` and generates the prime order subgroup.
    pub fn validate_public_key(&self, public_key: &[u8]) -> bool {
        let value = match self.decode(public_key) {
            Some(value) => value,
            None => return false,
        };
        let two = BoxedUint::from(2u8).resize(self.bits);
        // Reject 0, 1 and p-1, which all sit in tiny subgroups.
        if value < two || value > self.p.wrapping_sub(&two) {
            return false;
        }
        // y^q mod p must be 1 for y to be in the q-order subgroup.
        return self.pow(&value, &self.q) == BoxedUint::one_with_precision(self.bits);
    }

    /// Generate an ephemeral key pair over the given generator.
    ///
    /// Returns the secret exponent and the public value, both encoded.
    pub fn generate_keypair(&self, generator: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let generator = self.decode(generator)?;
        let modulus = NonZero::new(self.q.clone()).into_option()?;
        let secret = loop {
            // Draw well above the order's width and reduce, so the bias towards
            // small exponents is negligible.
            let candidate = BoxedUint::random_bits(&mut rand::rng(), self.bits) % &modulus;
            if !bool::from(candidate.is_zero()) {
                break candidate;
            }
        };
        let public = self.pow(&generator, &secret);
        return Some((self.encode(&secret), self.encode(&public)));
    }

    /// The Generic Mapping of ICAO 9303 p11 section 4.4.3.3.1 for DH.
    ///
    /// Computes `g_hat = g^s * h`, where `h` is the shared secret of an
    /// anonymous key agreement between our mapping key and the chip's.
    pub fn map_generic(
        &self,
        nonce_s: &[u8],
        secret: &[u8],
        peer_public: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce_s = self.decode(nonce_s)?;
        let secret = self.decode(secret)?;
        let peer_public = self.decode(peer_public)?;

        // h = KA(SK_map_ifd, PK_map_ic)
        let h = self.monty(&self.pow(&peer_public, &secret));
        // g_hat = g^s * h
        let mapped = (self.monty(&self.pow(&self.g, &nonce_s)) * h).retrieve();
        // A mapped generator of 1 generates nothing.
        if mapped == BoxedUint::one_with_precision(self.bits) {
            return None;
        }
        return Some(self.encode(&mapped));
    }

    /// The Integrated Mapping of ICAO 9303 p11 section 4.4.3.3.2 for DH.
    ///
    /// Computes `f_g(x) = x^a mod p`, where `a = (p-1)/q` is the cofactor.
    pub fn map_integrated(&self, pseudo_random: &[u8]) -> Option<Vec<u8>> {
        let x = self.decode(pseudo_random)?;
        let order = NonZero::new(self.q.clone()).into_option()?;
        let cofactor = self
            .p
            .wrapping_sub(&BoxedUint::one_with_precision(self.bits))
            / &order;
        let mapped = self.pow(&x, &cofactor);
        // The standard requires this check explicitly.
        if mapped == BoxedUint::one_with_precision(self.bits) {
            return None;
        }
        return Some(self.encode(&mapped));
    }

    /// The shared secret `peer_public ^ secret mod p`.
    pub fn shared_secret(&self, secret: &[u8], peer_public: &[u8]) -> Option<Vec<u8>> {
        let secret = self.decode(secret)?;
        let peer_public = self.decode(peer_public)?;
        let shared = self.pow(&peer_public, &secret);
        if shared == BoxedUint::one_with_precision(self.bits) {
            return None;
        }
        return Some(self.encode(&shared));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pace::domain::{MODP_1024_160, MODP_2048_224, MODP_2048_256};

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect();
    }

    /// Appendix G.2 works entirely in the 1024-bit MODP group.
    fn group() -> DhGroupOps {
        return DhGroupOps::new(&MODP_1024_160);
    }

    /// ICAO 9303 p11 Appendix G.2, the Map Nonce step.
    #[test]
    fn generic_mapping_matches_worked_example() {
        let nonce_s = hex("FA5B7E3E49753A0DB9178B7B9BD898C8");
        let terminal_mapping_secret = hex("5265030F751F4AD18B08AC565FC7AC952E41618D");
        let chip_mapping_public = hex(
            "78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E6
             23EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882
             A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F24
             49400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6",
        );
        let expected_mapped_generator = hex(
            "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496
             84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301
             BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84
             EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5",
        );

        assert_eq!(
            group()
                .map_generic(&nonce_s, &terminal_mapping_secret, &chip_mapping_public)
                .unwrap(),
            expected_mapped_generator
        );
    }

    /// The chip reaches the same mapped generator from its own side.
    #[test]
    fn generic_mapping_agrees_from_both_sides() {
        let nonce_s = hex("FA5B7E3E49753A0DB9178B7B9BD898C8");
        let chip_mapping_secret = hex("66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C");
        let terminal_mapping_public = hex(
            "23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3E
             B71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A4
             4D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022D
             CB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C",
        );
        let expected_mapped_generator = hex(
            "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496
             84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301
             BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84
             EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5",
        );

        assert_eq!(
            group()
                .map_generic(&nonce_s, &chip_mapping_secret, &terminal_mapping_public)
                .unwrap(),
            expected_mapped_generator
        );
    }

    /// ICAO 9303 p11 Appendix G.2, the Perform Key Agreement step.
    #[test]
    fn key_agreement_matches_worked_example() {
        let terminal_secret = hex("89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA");
        let chip_public = hex(
            "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B
             D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC
             71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064
             386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1",
        );
        let expected_shared_secret = hex(
            "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3
             8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5
             990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E
             465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD",
        );

        assert_eq!(
            group()
                .shared_secret(&terminal_secret, &chip_public)
                .unwrap(),
            expected_shared_secret
        );
    }

    /// And from the chip's side.
    #[test]
    fn key_agreement_agrees_from_both_sides() {
        let chip_secret = hex("A5B780126B7C980E9FCEA1D4539DA1D27C342DFA");
        let terminal_public = hex(
            "907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD91155
             1B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08F
             A8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236
             B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4",
        );
        let expected_shared_secret = hex(
            "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3
             8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5
             990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E
             465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD",
        );

        assert_eq!(
            group()
                .shared_secret(&chip_secret, &terminal_public)
                .unwrap(),
            expected_shared_secret
        );
    }

    /// Public keys from the worked example are valid; degenerate ones are not.
    #[test]
    fn validates_public_keys() {
        let group = group();
        let valid = hex(
            "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B
             D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC
             71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064
             386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1",
        );
        assert!(group.validate_public_key(&valid));

        // 0 and 1 are in trivial subgroups.
        let mut zero = vec![0u8; group.length()];
        assert!(!group.validate_public_key(&zero));
        zero[group.length() - 1] = 1;
        assert!(!group.validate_public_key(&zero));

        // p - 1 has order 2, the classic small subgroup attack value.
        let p_minus_one = group.encode(
            &group
                .p
                .wrapping_sub(&BoxedUint::one_with_precision(group.bits)),
        );
        assert!(!group.validate_public_key(&p_minus_one));

        // A value not in the q-order subgroup at all.
        let mut not_in_subgroup = valid.clone();
        not_in_subgroup[group.length() - 1] ^= 0x01;
        assert!(!group.validate_public_key(&not_in_subgroup));
    }

    /// Every group can carry out a full exchange, and both sides agree.
    #[test]
    fn ephemeral_exchange_agrees_in_every_group() {
        for modp_group in [&MODP_1024_160, &MODP_2048_224, &MODP_2048_256] {
            let group = DhGroupOps::new(modp_group);
            let generator = group.encode(&group.g.clone());
            assert!(group.validate_public_key(&generator));

            // Map to a fresh generator the way Generic Mapping would.
            let (map_secret_a, map_public_a) = group.generate_keypair(&generator).unwrap();
            let (map_secret_b, map_public_b) = group.generate_keypair(&generator).unwrap();
            let nonce_s = [0x5Au8; 16];
            let mapped_a = group
                .map_generic(&nonce_s, &map_secret_a, &map_public_b)
                .unwrap();
            let mapped_b = group
                .map_generic(&nonce_s, &map_secret_b, &map_public_a)
                .unwrap();
            assert_eq!(mapped_a, mapped_b);

            // Then agree a secret over it.
            let (secret_a, public_a) = group.generate_keypair(&mapped_a).unwrap();
            let (secret_b, public_b) = group.generate_keypair(&mapped_a).unwrap();
            assert_eq!(
                group.shared_secret(&secret_a, &public_b).unwrap(),
                group.shared_secret(&secret_b, &public_a).unwrap()
            );
        }
    }

    #[test]
    fn encoded_values_are_the_width_of_the_prime() {
        assert_eq!(DhGroupOps::new(&MODP_1024_160).length(), 128);
        assert_eq!(DhGroupOps::new(&MODP_2048_224).length(), 256);
        assert_eq!(DhGroupOps::new(&MODP_2048_256).length(), 256);

        let group = group();
        let generator = group.encode(&group.g.clone());
        let (secret, public) = group.generate_keypair(&generator).unwrap();
        assert_eq!(secret.len(), 128);
        assert_eq!(public.len(), 128);
    }

    /// Two key pairs must differ, i.e. the RNG is actually being drawn from.
    #[test]
    fn generated_keys_differ() {
        let group = group();
        let generator = group.encode(&group.g.clone());
        let (first, _) = group.generate_keypair(&generator).unwrap();
        let (second, _) = group.generate_keypair(&generator).unwrap();
        assert_ne!(first, second);
    }

    /// The Integrated Mapping's f_g lands in the prime order subgroup.
    #[test]
    fn integrated_mapping_stays_in_the_subgroup() {
        let group = group();
        let mapped = group.map_integrated(&[0x42u8; 128]).unwrap();
        assert_eq!(mapped.len(), 128);
        assert!(group.validate_public_key(&mapped));
    }
}
