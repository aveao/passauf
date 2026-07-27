///! ECDH key agreement and point handling for PACE
///
/// PACE runs the same steps over any of the standardized curves, so the work is
/// written once against [`elliptic_curve::CurveArithmetic`] and made available
/// per curve through the object-safe [`EcCurveOps`].
///
/// Points cross this boundary in the uncompressed SEC1 encoding `04 || X || Y`
/// that PACE puts on the wire, and scalars as big-endian bytes, which keeps the
/// trait free of curve-specific types.
use elliptic_curve::array::Array;
use elliptic_curve::group::Group;
use elliptic_curve::ops::Reduce;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::{CurveArithmetic, FieldBytes, Generate};
use std::marker::PhantomData;

use crate::pace::domain::EcCurve;

/// The uncompressed point marker of SEC1. PACE never uses compressed points.
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// Curve operations PACE needs, with everything expressed as bytes.
pub trait EcCurveOps {
    /// Width of a field element in bytes, i.e. of one point coordinate.
    fn field_size(&self) -> usize;

    /// The curve's standard generator, SEC1 encoded.
    fn generator(&self) -> Vec<u8>;

    /// Generate an ephemeral key pair over the given generator.
    ///
    /// Returns the secret scalar as big-endian bytes and the public point
    /// SEC1 encoded.
    fn generate_keypair(&self, generator: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;

    /// Multiply a point by a scalar, returning the SEC1 encoded result.
    fn multiply(&self, point: &[u8], scalar: &[u8]) -> Option<Vec<u8>>;

    /// The Generic Mapping of ICAO 9303 p11 section 4.4.3.3.1.
    ///
    /// Computes `G_hat = s * G + H`, where `H` is the shared secret of an
    /// anonymous key agreement between our mapping key and the chip's.
    fn map_generic(&self, nonce_s: &[u8], secret: &[u8], peer_point: &[u8]) -> Option<Vec<u8>>;

    /// The x-coordinate of `secret * peer_point`, which is the shared secret
    /// the session keys are derived from.
    fn shared_secret(&self, secret: &[u8], peer_point: &[u8]) -> Option<Vec<u8>>;

    /// Build a point from its affine coordinates, rejecting anything not on
    /// the curve. Used by the Integrated Mapping's point encoding.
    fn point_from_coordinates(&self, x: &[u8], y: &[u8]) -> Option<Vec<u8>>;

    /// Whether a SEC1 encoded point is a valid, non-identity curve point.
    fn validate_point(&self, point: &[u8]) -> bool;
}

/// Carries a curve type so it can be handed around as a trait object.
struct CurveOps<C: CurveArithmetic>(PhantomData<C>);

impl<C: CurveArithmetic> CurveOps<C> {
    fn field_size() -> usize {
        return AsRef::<[u8]>::as_ref(&FieldBytes::<C>::default()).len();
    }

    /// Left-pad to a full field element.
    ///
    /// The PACE nonce is only as wide as the cipher's block size, so it is
    /// routinely shorter than the curve's field.
    fn to_field_bytes(value: &[u8]) -> Option<FieldBytes<C>> {
        let field_size = Self::field_size();
        if value.len() > field_size {
            return None;
        }
        let mut padded = vec![0u8; field_size];
        padded[field_size - value.len()..].copy_from_slice(value);
        return Array::try_from(padded.as_slice()).ok();
    }

    /// Interpret bytes as a scalar, reducing modulo the group order.
    fn to_scalar(value: &[u8]) -> Option<C::Scalar> {
        let field_bytes = Self::to_field_bytes(value)?;
        return Some(<C::Scalar as Reduce<FieldBytes<C>>>::reduce(&field_bytes));
    }

    fn encode_point(point: &C::ProjectivePoint) -> Option<Vec<u8>> {
        // The identity has no affine coordinates to encode, and is never a
        // legitimate PACE public key or mapped generator.
        if bool::from(point.is_identity()) {
            return None;
        }
        let affine: C::AffinePoint = (*point).into();
        return Some(
            vec![
                [UNCOMPRESSED_POINT_TAG].as_slice(),
                AsRef::<[u8]>::as_ref(&affine.x()),
                AsRef::<[u8]>::as_ref(&affine.y()),
            ]
            .concat(),
        );
    }

    fn decode_point(bytes: &[u8]) -> Option<C::ProjectivePoint> {
        let field_size = Self::field_size();
        if bytes.len() != 1 + 2 * field_size || bytes[0] != UNCOMPRESSED_POINT_TAG {
            return None;
        }
        return Self::point_from_xy(&bytes[1..1 + field_size], &bytes[1 + field_size..]);
    }

    fn point_from_xy(x: &[u8], y: &[u8]) -> Option<C::ProjectivePoint> {
        let x = Self::to_field_bytes(x)?;
        let y = Self::to_field_bytes(y)?;
        // from_coordinates rejects anything off the curve, which is the
        // validation PACE needs on every point the chip sends us.
        let affine = Option::<C::AffinePoint>::from(C::AffinePoint::from_coordinates(&x, &y))?;
        let point: C::ProjectivePoint = affine.into();
        if bool::from(point.is_identity()) {
            return None;
        }
        return Some(point);
    }
}

impl<C: CurveArithmetic> EcCurveOps for CurveOps<C> {
    fn field_size(&self) -> usize {
        return Self::field_size();
    }

    fn generator(&self) -> Vec<u8> {
        return Self::encode_point(&C::ProjectivePoint::generator())
            .expect("The curve generator is never the identity.");
    }

    fn generate_keypair(&self, generator: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let generator = Self::decode_point(generator)?;
        let secret = <C::Scalar as Generate>::generate_from_rng(&mut rand::rng());
        let public = generator * secret;
        let secret_bytes: FieldBytes<C> = secret.into();
        return Some((
            AsRef::<[u8]>::as_ref(&secret_bytes).to_vec(),
            Self::encode_point(&public)?,
        ));
    }

    fn multiply(&self, point: &[u8], scalar: &[u8]) -> Option<Vec<u8>> {
        let point = Self::decode_point(point)?;
        let scalar = Self::to_scalar(scalar)?;
        return Self::encode_point(&(point * scalar));
    }

    fn map_generic(&self, nonce_s: &[u8], secret: &[u8], peer_point: &[u8]) -> Option<Vec<u8>> {
        let secret = Self::to_scalar(secret)?;
        let peer_point = Self::decode_point(peer_point)?;
        let nonce_s = Self::to_scalar(nonce_s)?;

        // H = KA(SK_map_ifd, PK_map_ic), the anonymous key agreement.
        let h = peer_point * secret;
        // G_hat = s * G + H
        let mapped = (C::ProjectivePoint::generator() * nonce_s) + h;
        return Self::encode_point(&mapped);
    }

    fn shared_secret(&self, secret: &[u8], peer_point: &[u8]) -> Option<Vec<u8>> {
        let secret = Self::to_scalar(secret)?;
        let peer_point = Self::decode_point(peer_point)?;
        let shared = peer_point * secret;
        if bool::from(shared.is_identity()) {
            return None;
        }
        // ICAO 9303 p11 section 9.7.1: for ECKA the x-coordinate of the
        // generated point is the shared secret.
        let affine: C::AffinePoint = shared.into();
        return Some(AsRef::<[u8]>::as_ref(&affine.x()).to_vec());
    }

    fn point_from_coordinates(&self, x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
        return Self::encode_point(&Self::point_from_xy(x, y)?);
    }

    fn validate_point(&self, point: &[u8]) -> bool {
        return Self::decode_point(point).is_some();
    }
}

/// Get the operations for a curve, if passauf implements it.
pub fn ops_for(curve: EcCurve) -> Option<Box<dyn EcCurveOps>> {
    return Some(match curve {
        EcCurve::NistP256 => Box::new(CurveOps::<p256::NistP256>(PhantomData)),
        EcCurve::NistP384 => Box::new(CurveOps::<p384::NistP384>(PhantomData)),
        EcCurve::NistP521 => Box::new(CurveOps::<p521::NistP521>(PhantomData)),
        EcCurve::BrainpoolP256r1 => Box::new(CurveOps::<bp256::BrainpoolP256r1>(PhantomData)),
        EcCurve::BrainpoolP384r1 => Box::new(CurveOps::<bp384::BrainpoolP384r1>(PhantomData)),
        // The curves with no Rust implementation behind them.
        _ => return None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything in ICAO 9303 p11 Appendix G.1 is on BrainpoolP256r1.
    fn bp256() -> Box<dyn EcCurveOps> {
        return ops_for(EcCurve::BrainpoolP256r1).unwrap();
    }

    fn hex(text: &str) -> Vec<u8> {
        return (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
    }

    /// Build the SEC1 encoding of a point from its two coordinates.
    fn point(x: &str, y: &str) -> Vec<u8> {
        return vec![vec![0x04], hex(x), hex(y)].concat();
    }

    #[test]
    fn ops_exist_exactly_for_supported_curves() {
        for curve in [
            EcCurve::NistP256,
            EcCurve::NistP384,
            EcCurve::NistP521,
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
        ] {
            assert!(ops_for(curve).is_some(), "{} should be supported", curve);
            assert!(curve.is_supported());
        }
        for curve in [
            EcCurve::NistP192,
            EcCurve::NistP224,
            EcCurve::BrainpoolP192r1,
            EcCurve::BrainpoolP224r1,
            EcCurve::BrainpoolP320r1,
            EcCurve::BrainpoolP512r1,
        ] {
            assert!(ops_for(curve).is_none(), "{} should be unsupported", curve);
            assert!(!curve.is_supported());
        }
    }

    #[test]
    fn field_sizes_match_the_curves() {
        assert_eq!(ops_for(EcCurve::NistP256).unwrap().field_size(), 32);
        assert_eq!(ops_for(EcCurve::BrainpoolP256r1).unwrap().field_size(), 32);
        assert_eq!(ops_for(EcCurve::NistP384).unwrap().field_size(), 48);
        assert_eq!(ops_for(EcCurve::BrainpoolP384r1).unwrap().field_size(), 48);
        // P-521 is 521 bits, so 66 bytes rather than 65.
        assert_eq!(ops_for(EcCurve::NistP521).unwrap().field_size(), 66);
    }

    /// ICAO 9303 p11 Appendix G.1, the Map Nonce step.
    ///
    /// Feeding in the terminal's mapping private key, the chip's mapping public
    /// key and the decrypted nonce must reproduce the mapped generator exactly.
    #[test]
    fn generic_mapping_matches_worked_example() {
        let nonce_s = hex("3F00C4D39D153F2B2A214A078D899B22");
        let terminal_mapping_secret =
            hex("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99");
        let chip_mapping_public = point(
            "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57",
            "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54",
        );
        let expected_mapped_generator = point(
            "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2",
            "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522",
        );

        assert_eq!(
            bp256()
                .map_generic(&nonce_s, &terminal_mapping_secret, &chip_mapping_public)
                .unwrap(),
            expected_mapped_generator
        );
    }

    /// The mapping is symmetric: the chip computes the same generator from its
    /// own secret and our public key.
    #[test]
    fn generic_mapping_agrees_from_both_sides() {
        let nonce_s = hex("3F00C4D39D153F2B2A214A078D899B22");
        let chip_mapping_secret =
            hex("498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560");
        let terminal_mapping_public = point(
            "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E",
            "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D",
        );
        let expected_mapped_generator = point(
            "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2",
            "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522",
        );

        assert_eq!(
            bp256()
                .map_generic(&nonce_s, &chip_mapping_secret, &terminal_mapping_public)
                .unwrap(),
            expected_mapped_generator
        );
    }

    /// ICAO 9303 p11 Appendix G.1, the Perform Key Agreement step.
    #[test]
    fn key_agreement_matches_worked_example() {
        let terminal_secret =
            hex("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595");
        let chip_public = point(
            "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB",
            "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094",
        );
        // Only the x-coordinate is the shared secret.
        let expected_shared_secret =
            hex("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925");

        assert_eq!(
            bp256()
                .shared_secret(&terminal_secret, &chip_public)
                .unwrap(),
            expected_shared_secret
        );
    }

    /// Both sides of the key agreement reach the same secret.
    #[test]
    fn key_agreement_agrees_from_both_sides() {
        let chip_secret = hex("107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A");
        let terminal_public = point(
            "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C",
            "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462",
        );
        let expected_shared_secret =
            hex("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925");

        assert_eq!(
            bp256()
                .shared_secret(&chip_secret, &terminal_public)
                .unwrap(),
            expected_shared_secret
        );
    }

    /// The public keys in Appendix G.1 must be recognized as on-curve, and
    /// tampering with one must be caught.
    #[test]
    fn rejects_points_that_are_not_on_the_curve() {
        let valid = point(
            "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57",
            "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54",
        );
        assert!(bp256().validate_point(&valid));

        // Flip one bit of the y-coordinate.
        let mut tampered = valid.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!bp256().validate_point(&tampered));

        // A compressed point, which PACE never uses.
        let mut compressed = valid.clone();
        compressed[0] = 0x02;
        assert!(!bp256().validate_point(&compressed));

        // Truncated.
        assert!(!bp256().validate_point(&valid[..valid.len() - 1]));
        // Empty.
        assert!(!bp256().validate_point(&[]));
    }

    /// A freshly generated key pair has to satisfy PK = SK * generator.
    #[test]
    fn generated_keypairs_are_consistent() {
        for curve in [
            EcCurve::NistP256,
            EcCurve::NistP384,
            EcCurve::NistP521,
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
        ] {
            let ops = ops_for(curve).unwrap();
            let generator = ops.generator();
            assert!(ops.validate_point(&generator));

            let (secret, public) = ops.generate_keypair(&generator).unwrap();
            assert_eq!(secret.len(), ops.field_size());
            assert!(ops.validate_point(&public));
            assert_eq!(ops.multiply(&generator, &secret).unwrap(), public);

            // Two key pairs must differ, i.e. the RNG is actually being used.
            let (other_secret, _) = ops.generate_keypair(&generator).unwrap();
            assert_ne!(secret, other_secret);
        }
    }

    /// A full Diffie-Hellman exchange over a mapped generator agrees on both
    /// sides, for every curve we support.
    #[test]
    fn ephemeral_exchange_agrees_on_every_curve() {
        for curve in [
            EcCurve::NistP256,
            EcCurve::NistP384,
            EcCurve::NistP521,
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
        ] {
            let ops = ops_for(curve).unwrap();
            let generator = ops.generator();

            // Derive a mapped generator the way Generic Mapping would.
            let (map_secret_a, map_public_a) = ops.generate_keypair(&generator).unwrap();
            let (map_secret_b, map_public_b) = ops.generate_keypair(&generator).unwrap();
            let nonce_s = [0x5Au8; 16];
            let mapped_a = ops
                .map_generic(&nonce_s, &map_secret_a, &map_public_b)
                .unwrap();
            let mapped_b = ops
                .map_generic(&nonce_s, &map_secret_b, &map_public_a)
                .unwrap();
            assert_eq!(mapped_a, mapped_b);

            // Then agree a secret over it.
            let (secret_a, public_a) = ops.generate_keypair(&mapped_a).unwrap();
            let (secret_b, public_b) = ops.generate_keypair(&mapped_a).unwrap();
            assert_eq!(
                ops.shared_secret(&secret_a, &public_b).unwrap(),
                ops.shared_secret(&secret_b, &public_a).unwrap()
            );
        }
    }

    /// Coordinates that describe a real point round-trip; ones that don't are
    /// rejected. The Integrated Mapping depends on this.
    #[test]
    fn builds_points_from_coordinates() {
        let x = hex("824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57");
        let y = hex("30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54");
        assert_eq!(
            bp256().point_from_coordinates(&x, &y).unwrap(),
            point(
                "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57",
                "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54",
            )
        );
        // Not a curve point.
        assert!(bp256().point_from_coordinates(&[0x01], &[0x02]).is_none());
    }
}
