///! Password Authenticated Connection Establishment (ICAO 9303 p11 section 4.4)
pub mod dh;
pub mod domain;
pub mod ecdh;
pub mod mapping;
pub mod oids;
pub mod password;

use iso7816_tlv::ber;
use simplelog::{debug, info, warn};
use std::collections::HashMap;

use crate::helpers;
use crate::iso7816;
use crate::pace::domain::{DomainParameter, EcCurve};
use crate::pace::oids::{KeyAgreement, Mapping, PaceAlgorithm};
use crate::pace::password::Password;
use crate::secure_messaging::{cbc_decrypt_zero_iv, kdf, SecureMessaging, SmAlgorithm};
use crate::smartcard_abstractions::Smartcard;
use crate::types::ef_cardaccess::PaceInfo;

/// Context specific tags of the Dynamic Authentication Data object
/// (ICAO 9303 p11 Table 4).
const TAG_DYNAMIC_AUTHENTICATION_DATA: u16 = 0x7C;
const TAG_ENCRYPTED_NONCE: u16 = 0x80;
const TAG_MAPPING_DATA_OUT: u16 = 0x81;
const TAG_MAPPING_DATA_IN: u16 = 0x82;
const TAG_EPHEMERAL_PUBLIC_KEY_OUT: u16 = 0x83;
const TAG_EPHEMERAL_PUBLIC_KEY_IN: u16 = 0x84;
const TAG_AUTHENTICATION_TOKEN_OUT: u16 = 0x85;
const TAG_AUTHENTICATION_TOKEN_IN: u16 = 0x86;
/// Only present when Chip Authentication Mapping is used.
const TAG_ENCRYPTED_CHIP_AUTHENTICATION_DATA: u16 = 0x8A;

/// Tag of the public key data object the authentication token is computed over
/// (ICAO 9303 p11 section 9.4.5).
const TAG_PUBLIC_KEY: u16 = 0x7F49;
/// Within it, the object identifier and the ephemeral public key. ECDH points
/// sit under tag 0x86, DH integers under tag 0x84.
const TAG_PUBLIC_KEY_OID: u8 = 0x06;
const TAG_PUBLIC_KEY_POINT: u8 = 0x86;
const TAG_PUBLIC_KEY_INTEGER: u8 = 0x84;

/// What went wrong, when PACE cannot be run or does not complete.
#[derive(Debug)]
pub enum PaceError {
    /// The document offered no PACE variant we implement.
    NoSupportedAlgorithm(String),
    /// The chip rejected a step, or sent something we could not use.
    Protocol(String),
    /// A cryptographic operation failed, e.g. an invalid public key.
    Crypto(String),
    /// The chip's authentication token did not verify, which normally means
    /// the password was wrong.
    AuthenticationFailed,
}

impl std::fmt::Display for PaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return match self {
            PaceError::NoSupportedAlgorithm(detail) => {
                write!(f, "No supported PACE algorithm: {}", detail)
            }
            PaceError::Protocol(detail) => write!(f, "PACE protocol error: {}", detail),
            PaceError::Crypto(detail) => write!(f, "PACE cryptographic error: {}", detail),
            PaceError::AuthenticationFailed => write!(
                f,
                "PACE authentication failed, the password is most likely wrong"
            ),
        };
    }
}

/// A Chip Authentication Mapping check that is waiting on the chip's static
/// public key.
///
/// PACE-CAM gives us the chip's Chip Authentication Data during the handshake,
/// but verifying it needs the static key from DG14, which only becomes readable
/// once secure messaging is up. So the check is carried out of PACE and run
/// afterwards.
#[derive(Debug)]
pub struct PendingChipAuthentication {
    curve: EcCurve,
    /// The decrypted `CA_IC = SK_IC^-1 * SK_Map,IC mod n`.
    chip_authentication_data: Vec<u8>,
    /// The chip's ephemeral mapping public key from step 2.
    chip_mapping_public_key: Vec<u8>,
}

impl PendingChipAuthentication {
    /// Verify `PK_Map,IC = KA(CA_IC, PK_IC)` (ICAO 9303 p11 section 4.4.3.5.2).
    ///
    /// A pass proves the chip holds the private key belonging to `public_key`.
    /// It says nothing about whether that key is itself trustworthy, which is
    /// what Passive Authentication is for.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let ops = match ecdh::ops_for(self.curve) {
            Some(ops) => ops,
            None => return false,
        };
        // Reject a key that isn't even on the curve before multiplying by it.
        if !ops.validate_point(public_key) {
            return false;
        }
        return match ops.multiply(public_key, &self.chip_authentication_data) {
            Some(result) => result == self.chip_mapping_public_key,
            None => false,
        };
    }

    pub fn curve(&self) -> EcCurve {
        return self.curve;
    }
}

/// The key agreement in use, with its domain parameters resolved.
enum Agreement {
    Ec {
        ops: Box<dyn ecdh::EcCurveOps>,
        curve: EcCurve,
    },
    Dh(dh::DhGroupOps),
}

impl Agreement {
    fn standard_generator(&self) -> Vec<u8> {
        return match self {
            Agreement::Ec { ops, .. } => ops.generator(),
            Agreement::Dh(group) => group.generator(),
        };
    }

    fn generate_keypair(&self, generator: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        return match self {
            Agreement::Ec { ops, .. } => ops.generate_keypair(generator),
            Agreement::Dh(group) => group.generate_keypair(generator),
        };
    }

    fn map_generic(&self, nonce_s: &[u8], secret: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
        return match self {
            Agreement::Ec { ops, .. } => ops.map_generic(nonce_s, secret, peer),
            Agreement::Dh(group) => group.map_generic(nonce_s, secret, peer),
        };
    }

    fn shared_secret(&self, secret: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
        return match self {
            Agreement::Ec { ops, .. } => ops.shared_secret(secret, peer),
            Agreement::Dh(group) => group.shared_secret(secret, peer),
        };
    }

    /// Validate a public key received from the chip.
    fn validate_peer_key(&self, public_key: &[u8]) -> bool {
        return match self {
            Agreement::Ec { ops, .. } => ops.validate_point(public_key),
            Agreement::Dh(group) => group.validate_public_key(public_key),
        };
    }

    /// Tag the ephemeral public key takes inside the authentication token.
    fn public_key_tag(&self) -> u8 {
        return match self {
            Agreement::Ec { .. } => TAG_PUBLIC_KEY_POINT,
            Agreement::Dh(_) => TAG_PUBLIC_KEY_INTEGER,
        };
    }
}

/// Encode a BER-TLV with a one-byte context specific tag.
fn encode_tlv(tag: u16, value: Vec<u8>) -> Vec<u8> {
    return helpers::encode_ber(&[tag as u8], &value);
}

/// Send one GENERAL AUTHENTICATE and pull one data object out of the response.
///
/// `expected_tag` is the context specific tag the chip should answer with.
fn exchange_step(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    request: Vec<u8>,
    expected_tag: u16,
    is_last: bool,
) -> Result<Vec<u8>, PaceError> {
    let objects = exchange_step_objects(smartcard, request, is_last)?;
    return objects.get(&expected_tag).cloned().ok_or_else(|| {
        PaceError::Protocol(format!(
            "Response has no data object with tag {:02X}",
            expected_tag
        ))
    });
}

/// Send one GENERAL AUTHENTICATE and return every data object in the response.
///
/// The last step of PACE-CAM answers with more than one, so the caller needs
/// them all.
fn exchange_step_objects(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    request: Vec<u8>,
    is_last: bool,
) -> Result<HashMap<u16, Vec<u8>>, PaceError> {
    let mut apdu = iso7816::apdu_general_authenticate(request, is_last);
    let (rapdu, status_code) = apdu.exchange(smartcard, false);

    if status_code != iso7816::StatusCode::Ok as u16 {
        // 0x6300 is the chip saying authentication failed, which for PACE means
        // the password did not match.
        if status_code == iso7816::StatusCode::AuthFailed as u16 {
            return Err(PaceError::AuthenticationFailed);
        }
        return Err(PaceError::Protocol(format!(
            "GENERAL AUTHENTICATE returned status {:04X}",
            status_code
        )));
    }

    // The response is wrapped in a Dynamic Authentication Data object.
    let parsed = ber::Tlv::parse(&rapdu)
        .0
        .map_err(|error| PaceError::Protocol(format!("Could not parse response: {:?}", error)))?;
    if helpers::get_tlv_tag(&parsed) != TAG_DYNAMIC_AUTHENTICATION_DATA {
        return Err(PaceError::Protocol(
            "Response is not a Dynamic Authentication Data object.".to_string(),
        ));
    }

    let mut objects: HashMap<u16, Vec<u8>> = HashMap::new();
    for tlv in helpers::get_tlv_constructed_value(&parsed).iter() {
        objects.insert(helpers::get_tlv_tag(tlv), helpers::get_tlv_value_bytes(tlv));
    }
    return Ok(objects);
}

/// Build the public key data object the authentication token is computed over
/// (ICAO 9303 p11 sections 4.4.3.4 and 9.4.5).
///
/// It holds the protocol OID from MSE:Set AT and the *peer's* ephemeral public
/// key, with the domain parameters deliberately left out.
fn authentication_token_input(
    algorithm: &PaceAlgorithm,
    agreement: &Agreement,
    peer_public_key: &[u8],
) -> Vec<u8> {
    let oid_bytes = algorithm.to_oid_bytes();
    let mut inner = vec![];
    inner.extend_from_slice(&[TAG_PUBLIC_KEY_OID, oid_bytes.len() as u8]);
    inner.extend_from_slice(&oid_bytes);
    inner.extend_from_slice(&helpers::encode_ber(
        &[agreement.public_key_tag()],
        peer_public_key,
    ));
    // 0x7F49 is a two-byte constructed tag.
    return helpers::encode_ber(&TAG_PUBLIC_KEY.to_be_bytes(), &inner);
}

/// Pick the best PACEInfo we can actually run.
///
/// Collects why each rejected entry was rejected, so an unsupported document
/// says what it wanted rather than just failing to authenticate.
pub fn select_pace_info(pace_infos: &[&PaceInfo]) -> Result<PaceInfo, PaceError> {
    let mut rejections: Vec<String> = vec![];
    let mut usable: Vec<&PaceInfo> = vec![];

    for pace_info in pace_infos {
        if let Some(reason) = pace_info.algorithm.unsupported_reason() {
            rejections.push(format!("{}: {}", pace_info.algorithm, reason));
            continue;
        }

        // Without a parameter ID the document means explicit domain parameters,
        // carried in a PACEDomainParameterInfo we do not read.
        let parameter_id = match pace_info.parameter_id {
            Some(parameter_id) => parameter_id,
            None => {
                rejections.push(format!(
                    "{}: no standardized domain parameter ID, and explicit domain \
                     parameters are not supported",
                    pace_info.algorithm
                ));
                continue;
            }
        };

        let parameter = match domain::from_parameter_id(parameter_id) {
            Some(parameter) => parameter,
            None => {
                rejections.push(format!(
                    "{}: domain parameter {} is reserved for future use",
                    pace_info.algorithm, parameter_id
                ));
                continue;
            }
        };

        if let Some(reason) = parameter.unsupported_reason() {
            rejections.push(format!(
                "{} with {}: {}",
                pace_info.algorithm, parameter, reason
            ));
            continue;
        }

        // The key agreement named by the OID and the kind of domain parameter
        // have to agree with each other.
        let consistent = matches!(
            (&parameter, pace_info.algorithm.key_agreement),
            (DomainParameter::Ec(_), KeyAgreement::Ecdh)
                | (DomainParameter::Modp(_), KeyAgreement::Dh)
        );
        if !consistent {
            rejections.push(format!(
                "{}: domain parameter {} is for the other key agreement",
                pace_info.algorithm, parameter
            ));
            continue;
        }

        if let DomainParameter::Ec(curve) = parameter {
            if !curve.allows_mapping(pace_info.algorithm.mapping) {
                rejections.push(format!(
                    "{}: {} cannot be used with this mapping",
                    pace_info.algorithm, curve
                ));
                continue;
            }
        }

        usable.push(*pace_info);
    }

    // ICAO 9303 p11 Appendix J: "If supported by IC and terminal, PACE-CAM
    // should be used". It also proves the chip holds the private key for its
    // Chip Authentication key, which the other mappings do not, so take it
    // whenever the document offers it. Otherwise keep the document's order.
    let selected = usable
        .iter()
        .copied()
        .find(|candidate| candidate.algorithm.mapping == Mapping::ChipAuthentication)
        .or_else(|| usable.first().copied());

    return match selected {
        Some(pace_info) => Ok(pace_info.clone()),
        None => Err(PaceError::NoSupportedAlgorithm(if rejections.is_empty() {
            "the document offered none".to_string()
        } else {
            rejections.join("; ")
        })),
    };
}

/// Run PACE and return the secure messaging session it establishes.
/// Returns the session, plus a Chip Authentication check to run once DG14 has
/// been read, when the document used Chip Authentication Mapping.
pub fn do_pace_authentication(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    pace_info: &PaceInfo,
    pace_password: &Password,
) -> Result<(SecureMessaging, Option<PendingChipAuthentication>), PaceError> {
    let algorithm = pace_info.algorithm;
    let cipher = algorithm.cipher;
    info!("<d>Starting PACE with {}</>", algorithm);

    let parameter_id = pace_info
        .parameter_id
        .ok_or_else(|| PaceError::NoSupportedAlgorithm("no domain parameter ID".to_string()))?;
    let parameter = domain::from_parameter_id(parameter_id).ok_or_else(|| {
        PaceError::NoSupportedAlgorithm(format!("domain parameter {} is unassigned", parameter_id))
    })?;
    info!(
        "<d>Using {} with the {} password</>",
        parameter, pace_password
    );

    let agreement = match parameter {
        DomainParameter::Ec(curve) => Agreement::Ec {
            ops: ecdh::ops_for(curve).ok_or_else(|| {
                PaceError::NoSupportedAlgorithm(format!("{} is not implemented", curve))
            })?,
            curve,
        },
        DomainParameter::Modp(group) => Agreement::Dh(dh::DhGroupOps::new(group)),
    };

    // Step 0: MSE:Set AT selects the protocol, the password and the parameters.
    let mut apdu = iso7816::apdu_mse_set_at(
        &algorithm.to_oid_bytes(),
        pace_password.reference(),
        Some(parameter_id),
    );
    let (_, status_code) = apdu.exchange(smartcard, false);
    if status_code != iso7816::StatusCode::Ok as u16 {
        return Err(PaceError::Protocol(format!(
            "MSE:Set AT returned status {:04X}, the chip likely does not offer {}",
            status_code, algorithm
        )));
    }

    // Step 1: ask for the encrypted nonce and decrypt it with the password key.
    // The Dynamic Authentication Data object is empty for this step.
    let encrypted_nonce = exchange_step(smartcard, vec![], TAG_ENCRYPTED_NONCE, false)?;
    let kpi = pace_password.derive_kpi(cipher);
    if encrypted_nonce.is_empty() || encrypted_nonce.len() % cipher.block_size() != 0 {
        return Err(PaceError::Protocol(format!(
            "The encrypted nonce is {} bytes, which is not a whole number of blocks",
            encrypted_nonce.len()
        )));
    }
    // 4.4.3.3 encrypts the nonce in CBC mode with an all-zero IV, which is not
    // the session's IV rule, so this does not go through SecureMessaging.
    let nonce_s = cbc_decrypt_zero_iv(cipher, &kpi, &encrypted_nonce);
    debug!("nonce s: {:02x?}", nonce_s);

    // Step 2: map the nonce to a fresh generator. Chip Authentication Mapping
    // needs the chip's mapping key again in step 4.
    let mut chip_mapping_public_key: Option<Vec<u8>> = None;
    let mapped_generator = match algorithm.mapping {
        // 4.4.3.3.3: the mapping phase of PACE-CAM is identical to the Generic
        // Mapping's. CAM only differs in what the chip sends back in step 4,
        // which is checked against the mapping key kept here.
        Mapping::Generic | Mapping::ChipAuthentication => {
            let standard_generator = agreement.standard_generator();
            let (mapping_secret, mapping_public) = agreement
                .generate_keypair(&standard_generator)
                .ok_or_else(|| {
                    PaceError::Crypto("Could not generate a mapping key pair.".to_string())
                })?;

            let peer_mapping_public = exchange_step(
                smartcard,
                encode_tlv(TAG_MAPPING_DATA_OUT, mapping_public),
                TAG_MAPPING_DATA_IN,
                false,
            )?;
            if !agreement.validate_peer_key(&peer_mapping_public) {
                return Err(PaceError::Crypto(
                    "The chip's mapping public key is invalid.".to_string(),
                ));
            }
            chip_mapping_public_key = Some(peer_mapping_public.clone());

            agreement
                .map_generic(&nonce_s, &mapping_secret, &peer_mapping_public)
                .ok_or_else(|| {
                    PaceError::Crypto("The generic mapping produced no generator.".to_string())
                })?
        }
        Mapping::Integrated => {
            // The terminal picks the second nonce t, as wide as the cipher's key.
            let mut nonce_t = vec![0u8; cipher.key_length()];
            rand::RngExt::fill(&mut rand::rng(), nonce_t.as_mut_slice());

            // 4.4.5.2.2: the chip's 0x82 in reply to this is empty.
            exchange_step(
                smartcard,
                encode_tlv(TAG_MAPPING_DATA_OUT, nonce_t.clone()),
                TAG_MAPPING_DATA_IN,
                false,
            )?;

            map_integrated(&agreement, cipher, &nonce_s, &nonce_t)?
        }
    };
    debug!("mapped generator: {:02x?}", mapped_generator);

    // Step 3: agree a shared secret over the mapped generator.
    let (ephemeral_secret, ephemeral_public) = agreement
        .generate_keypair(&mapped_generator)
        .ok_or_else(|| {
            PaceError::Crypto("Could not generate an ephemeral key pair.".to_string())
        })?;

    let peer_ephemeral_public = exchange_step(
        smartcard,
        encode_tlv(TAG_EPHEMERAL_PUBLIC_KEY_OUT, ephemeral_public.clone()),
        TAG_EPHEMERAL_PUBLIC_KEY_IN,
        false,
    )?;
    if !agreement.validate_peer_key(&peer_ephemeral_public) {
        return Err(PaceError::Crypto(
            "The chip's ephemeral public key is invalid.".to_string(),
        ));
    }
    // 4.4.1 requires the two ephemeral public keys to differ; a chip echoing
    // ours back would hand an attacker a shared secret they already know.
    if peer_ephemeral_public == ephemeral_public {
        return Err(PaceError::Crypto(
            "The chip echoed our own ephemeral public key.".to_string(),
        ));
    }

    let shared_secret = agreement
        .shared_secret(&ephemeral_secret, &peer_ephemeral_public)
        .ok_or_else(|| PaceError::Crypto("The key agreement failed.".to_string()))?;

    let ks_enc = kdf(cipher, &shared_secret, 1);
    let ks_mac = kdf(cipher, &shared_secret, 2);
    debug!("KS.enc: {:02x?}", ks_enc);
    debug!("KS.mac: {:02x?}", ks_mac);

    // PACE always starts its send sequence counter at zero.
    let sm = SecureMessaging::new(cipher, ks_enc, ks_mac);

    // Step 4: exchange and verify the authentication tokens. Each side
    // authenticates the key it received, so this is the last link of the chain.
    let token_ifd = sm.mac_with_internal_padding(&authentication_token_input(
        &algorithm,
        &agreement,
        &peer_ephemeral_public,
    ));
    let expected_token_ic = sm.mac_with_internal_padding(&authentication_token_input(
        &algorithm,
        &agreement,
        &ephemeral_public,
    ));

    let response = exchange_step_objects(
        smartcard,
        encode_tlv(TAG_AUTHENTICATION_TOKEN_OUT, token_ifd),
        true,
    )?;

    let token_ic = response.get(&TAG_AUTHENTICATION_TOKEN_IN).ok_or_else(|| {
        PaceError::Protocol("Response carries no authentication token.".to_string())
    })?;
    if *token_ic != expected_token_ic {
        return Err(PaceError::AuthenticationFailed);
    }

    // 4.4.5: the Encrypted Chip Authentication Data must be present for CAM and
    // must not be present otherwise.
    let pending_chip_authentication = match algorithm.mapping {
        Mapping::ChipAuthentication => {
            let encrypted = response
                .get(&TAG_ENCRYPTED_CHIP_AUTHENTICATION_DATA)
                .ok_or_else(|| {
                    PaceError::Protocol(
                        "Chip Authentication Mapping was used but the chip sent no \
                         Encrypted Chip Authentication Data."
                            .to_string(),
                    )
                })?;
            let chip_authentication_data = sm
                .decrypt_chip_authentication_data(encrypted)
                .ok_or_else(|| {
                    PaceError::Protocol(
                        "Could not decrypt the Chip Authentication Data.".to_string(),
                    )
                })?;

            let curve = match parameter {
                DomainParameter::Ec(curve) => curve,
                // CAM is ECDH-only, and selection already enforced that the
                // OID and the domain parameters agree.
                DomainParameter::Modp(_) => {
                    return Err(PaceError::Crypto(
                        "Chip Authentication Mapping cannot be used with a MODP group.".to_string(),
                    ))
                }
            };

            Some(PendingChipAuthentication {
                curve,
                chip_authentication_data,
                // Recorded during the mapping step above.
                chip_mapping_public_key: chip_mapping_public_key.ok_or_else(|| {
                    PaceError::Crypto("The chip sent no mapping public key.".to_string())
                })?,
            })
        }
        _ => None,
    };

    info!("Successfully authenticated!");
    return Ok((sm, pending_chip_authentication));
}

/// The Integrated Mapping, for whichever key agreement is in use.
fn map_integrated(
    agreement: &Agreement,
    cipher: SmAlgorithm,
    nonce_s: &[u8],
    nonce_t: &[u8],
) -> Result<Vec<u8>, PaceError> {
    return match agreement {
        Agreement::Ec { ops, curve } => {
            let parameters = curve
                .parameters()
                .ok_or_else(|| PaceError::Crypto(format!("{} has no parameters", curve)))?;
            let field_element =
                mapping::pseudo_random_in_field(cipher, nonce_s, nonce_t, parameters.p);
            let (x, y) = mapping::point_encoding(parameters, &field_element)
                .ok_or_else(|| PaceError::Crypto("The point encoding failed.".to_string()))?;
            ops.point_from_coordinates(&x, &y).ok_or_else(|| {
                PaceError::Crypto("The point encoding produced an off-curve point.".to_string())
            })
        }
        Agreement::Dh(group) => {
            let field_element =
                mapping::pseudo_random_in_field(cipher, nonce_s, nonce_t, group.prime());
            group.map_integrated(&field_element).ok_or_else(|| {
                PaceError::Crypto("The integrated mapping produced no generator.".to_string())
            })
        }
    };
}

/// Try PACE, reporting why it could not be attempted when it cannot.
pub fn try_pace(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    pace_infos: &[&PaceInfo],
    pace_password: &Password,
) -> Option<(SecureMessaging, Option<PendingChipAuthentication>)> {
    let pace_info = match select_pace_info(pace_infos) {
        Ok(pace_info) => pace_info,
        Err(error) => {
            warn!("{}", error);
            return None;
        }
    };

    return match do_pace_authentication(smartcard, &pace_info, pace_password) {
        Ok(result) => Some(result),
        Err(error) => {
            warn!("{}", error);
            None
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect();
    }

    fn pace_info(mapping_arc: u8, cipher_arc: u8, parameter_id: Option<u64>) -> PaceInfo {
        let oid = vec![
            0x04,
            0x00,
            0x7F,
            0x00,
            0x07,
            0x02,
            0x02,
            0x04,
            mapping_arc,
            cipher_arc,
        ];
        return PaceInfo {
            algorithm: PaceAlgorithm::from_oid_bytes(&oid).unwrap(),
            version: 2,
            parameter_id,
        };
    }

    fn brainpool_agreement() -> Agreement {
        return Agreement::Ec {
            ops: ecdh::ops_for(EcCurve::BrainpoolP256r1).unwrap(),
            curve: EcCurve::BrainpoolP256r1,
        };
    }

    fn point(x: &str, y: &str) -> Vec<u8> {
        return vec![vec![0x04], hex(x), hex(y)].concat();
    }

    /// ICAO 9303 p11 Appendix G.1 quotes the token input data in full.
    #[test]
    fn authentication_token_input_matches_worked_example() {
        let algorithm = pace_info(0x02, 0x02, Some(13)).algorithm;
        let chip_public = point(
            "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB",
            "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094",
        );

        assert_eq!(
            authentication_token_input(&algorithm, &brainpool_agreement(), &chip_public),
            hex(
                "7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9
                 F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F
                 9CB852E111B768B326904B59A0193776F094"
            )
        );
    }

    /// And the tokens themselves, under the session keys the example derives.
    #[test]
    fn generic_mapping_tokens_match_worked_example() {
        let algorithm = pace_info(0x02, 0x02, Some(13)).algorithm;
        let agreement = brainpool_agreement();

        let shared_secret = hex("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925");
        let ks_enc = kdf(SmAlgorithm::Aes128, &shared_secret, 1);
        let ks_mac = kdf(SmAlgorithm::Aes128, &shared_secret, 2);
        assert_eq!(ks_enc, hex("F5F0E35C0D7161EE6724EE513A0D9A7F"));
        assert_eq!(ks_mac, hex("FE251C7858B356B24514B3BD5F4297D1"));

        let sm = SecureMessaging::new(SmAlgorithm::Aes128, ks_enc, ks_mac);

        let chip_public = point(
            "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB",
            "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094",
        );
        let terminal_public = point(
            "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C",
            "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462",
        );

        // T.IFD authenticates the chip's key, T.IC authenticates ours.
        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &chip_public
            )),
            hex("C2B0BD78D94BA866")
        );
        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &terminal_public
            )),
            hex("3ABB9674BCE93C08")
        );
    }

    /// ICAO 9303 p11 Appendix H.1's tokens, which carry the Integrated Mapping
    /// OID and so differ inside the token input.
    #[test]
    fn integrated_mapping_tokens_match_worked_example() {
        let algorithm = pace_info(0x04, 0x02, Some(13)).algorithm;
        let agreement = brainpool_agreement();

        let shared_secret = hex("4F150FDE1D4F0E38E95017B891BAE17133A0DF45B0D3E18B60BA7BEAFDC2C713");
        let ks_enc = kdf(SmAlgorithm::Aes128, &shared_secret, 1);
        let ks_mac = kdf(SmAlgorithm::Aes128, &shared_secret, 2);
        assert_eq!(ks_enc, hex("0D3FEB33251A6370893D62AE8DAAF51B"));
        assert_eq!(ks_mac, hex("B01E89E3D9E8719E586B50B4A7506E0B"));

        let sm = SecureMessaging::new(SmAlgorithm::Aes128, ks_enc, ks_mac);

        let chip_public = point(
            "67F78E5F7F7686082B293E8D087E056916D0F74BC01A5F8957D0DE45691E51E8",
            "932B69A962B52A0985AD2C0A271EE6A13A8ADDDCD1A3A994B9DED257F4D22753",
        );
        let terminal_public = point(
            "89CBA23FFE96AA18D824627C3E934E54A9FD0B87A95D1471DC1C0ABFDCD640D4",
            "6755DE9B7B778280B6BEBD57439ADFEB0E21FD4ED6DF42578C13418A59B34C37",
        );

        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &chip_public
            )),
            hex("450F02B86F6A0909")
        );
        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &terminal_public
            )),
            hex("75D4D96E8D5B0308")
        );
    }

    /// ICAO 9303 p11 Appendix I, the Chip Authentication step.
    ///
    /// Every value here is quoted by the appendix, so this exercises the whole
    /// CAM check: decrypt the chip's data under the session key, then confirm
    /// it maps the static key onto the mapping key.
    fn worked_example_chip_authentication() -> (PendingChipAuthentication, Vec<u8>) {
        let pending = PendingChipAuthentication {
            curve: EcCurve::BrainpoolP256r1,
            chip_authentication_data: hex(
                "85DC3FA93D0952BFA82F5FD189EE75BD82F11D1F0B8ED4BF5319AC9B53C426B3",
            ),
            chip_mapping_public_key: point(
                "A234236AA9B9621E8EFB73B5245C0E09D2576E5277183C1208BDD55280CAE8B3",
                "04F365713A356E65A451E165ECC9AC0AC46E3771342C8FE5AEDD092685338E23",
            ),
        };
        let static_public_key = point(
            "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8",
            "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F",
        );
        return (pending, static_public_key);
    }

    #[test]
    fn chip_authentication_verifies_worked_example() {
        let (pending, static_public_key) = worked_example_chip_authentication();
        assert!(pending.verify(&static_public_key));
    }

    /// A different key, or a tampered one, must not pass.
    #[test]
    fn chip_authentication_rejects_the_wrong_key() {
        let (pending, static_public_key) = worked_example_chip_authentication();

        // Another valid point on the same curve, from Appendix G.1.
        let unrelated = point(
            "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57",
            "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54",
        );
        assert!(!pending.verify(&unrelated));

        // A point that isn't on the curve at all.
        let mut off_curve = static_public_key.clone();
        let last = off_curve.len() - 1;
        off_curve[last] ^= 0x01;
        assert!(!pending.verify(&off_curve));

        // Garbage.
        assert!(!pending.verify(&[]));
        assert!(!pending.verify(&[0x04, 0x00]));
    }

    /// The full path: the encrypted blob the chip sent, decrypted under the
    /// session key from the appendix, must verify.
    #[test]
    fn chip_authentication_end_to_end_from_encrypted_data() {
        let ks_enc = hex("0A9DA4DB03BDDE39FC5202BC44B2E89E");
        let sm = SecureMessaging::new(SmAlgorithm::Aes128, ks_enc, vec![0x11u8; 16]);
        let encrypted = hex(
            "1EEA964DAAE372AC990E3EFDE6333353BFC89A6704D93DA8798CF77F5B7A54BD
             10CBA372B42BE0B9B5F28AA8DE2F4F92",
        );

        let pending = PendingChipAuthentication {
            curve: EcCurve::BrainpoolP256r1,
            chip_authentication_data: sm.decrypt_chip_authentication_data(&encrypted).unwrap(),
            chip_mapping_public_key: point(
                "A234236AA9B9621E8EFB73B5245C0E09D2576E5277183C1208BDD55280CAE8B3",
                "04F365713A356E65A451E165ECC9AC0AC46E3771342C8FE5AEDD092685338E23",
            ),
        };
        let static_public_key = point(
            "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8",
            "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F",
        );
        assert!(pending.verify(&static_public_key));
    }

    /// Appendix I's authentication tokens, which use the CAM OID.
    #[test]
    fn chip_authentication_mapping_tokens_match_worked_example() {
        let algorithm = pace_info(0x06, 0x02, Some(13)).algorithm;
        let agreement = brainpool_agreement();

        let shared_secret = hex("67950559D0C06B4D4B86972D14460837461087F8419FDBC36AAF6CEAAC462832");
        let ks_enc = kdf(SmAlgorithm::Aes128, &shared_secret, 1);
        let ks_mac = kdf(SmAlgorithm::Aes128, &shared_secret, 2);
        assert_eq!(ks_enc, hex("0A9DA4DB03BDDE39FC5202BC44B2E89E"));
        assert_eq!(ks_mac, hex("4B1C06491ED5140CA2B537D344C6C0B1"));

        let sm = SecureMessaging::new(SmAlgorithm::Aes128, ks_enc, ks_mac);
        let chip_public = point(
            "02AD566F3C6EC7F9324509AD50A51FA52030782A4968FCFEDF737DAEA9933331",
            "11C3B9B4C2287789BD137E7F8AA882E2A3C633CCD6ECC2C63C57AD401A09C2E1",
        );
        let terminal_public = point(
            "446C934084D9DAB863944F219520076C29EE3F7AE6722B11FF319EC1C7728F95",
            "5483400BFF60BF0C5929270009277DC2A515E12575010AD9BA916CF1BF86FEFC",
        );

        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &chip_public
            )),
            hex("E86BD06018A1CD3B")
        );
        assert_eq!(
            sm.mac_with_internal_padding(&authentication_token_input(
                &algorithm,
                &agreement,
                &terminal_public
            )),
            hex("8596CF055C67C1A3")
        );
    }

    /// MSE:Set AT must serialize exactly as Appendix G.1 shows it.
    #[test]
    fn mse_set_at_matches_worked_example() {
        // The example sends no 0x84, the document offering one parameter set.
        let apdu = iso7816::apdu_mse_set_at(
            &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02],
            0x01,
            None,
        );
        assert_eq!(
            apdu.serialize(),
            hex("0022C1A40F800A04007F00070202040202830101")
        );
    }

    /// With ambiguous domain parameters the 0x84 object has to appear.
    #[test]
    fn mse_set_at_carries_the_parameter_id_when_given() {
        let apdu = iso7816::apdu_mse_set_at(
            &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02],
            0x02,
            Some(13),
        );
        assert_eq!(
            apdu.serialize(),
            hex("0022C1A412800A04007F0007020204020283010284010D")
        );
    }

    /// The first GENERAL AUTHENTICATE carries an empty 0x7C and chains.
    #[test]
    fn first_general_authenticate_matches_worked_example() {
        let apdu = iso7816::apdu_general_authenticate(vec![], false);
        assert_eq!(apdu.serialize(), hex("10860000027C0000"));
    }

    /// The mapping step of Appendix G.1, which exercises the 0x81 object and
    /// the short-form lengths around a 65-byte point.
    #[test]
    fn mapping_general_authenticate_matches_worked_example() {
        let mapping_public = point(
            "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E",
            "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D",
        );
        let apdu = iso7816::apdu_general_authenticate(
            encode_tlv(TAG_MAPPING_DATA_OUT, mapping_public.clone()),
            false,
        );
        // 10 86 00 00 45 | 7C 43 | 81 41 <point> | 00
        let expected = vec![hex("10860000457C438141"), mapping_public, hex("00")].concat();
        assert_eq!(apdu.serialize(), expected);
    }

    /// A 2048-bit DH public key pushes the command past 255 bytes, which forces
    /// the extended length encoding.
    #[test]
    fn large_dh_keys_use_extended_lengths() {
        let public_key = vec![0xABu8; 256];
        let apdu = iso7816::apdu_general_authenticate(
            encode_tlv(TAG_EPHEMERAL_PUBLIC_KEY_OUT, public_key),
            false,
        );
        let serialized = apdu.serialize();

        // 0x83 wraps 256 bytes as 83 82 01 00 <256>, so 260 bytes, and 0x7C
        // wraps that as 7C 82 01 04 <260>, so a 264-byte data field.
        assert_eq!(serialized[..4], hex("10860000")[..]);
        // Extended Lc, big-endian: 264 is 0x0108.
        assert_eq!(serialized[4..7], hex("000108")[..]);
        // The trailing Le is two bytes once Lc has marked the command extended.
        assert_eq!(serialized[serialized.len() - 2..], hex("0100")[..]);
        assert_eq!(serialized.len(), 4 + 3 + 264 + 2);
    }

    /// The last one drops the chaining bit, as in the token exchange.
    #[test]
    fn last_general_authenticate_matches_worked_example() {
        let apdu = iso7816::apdu_general_authenticate(
            encode_tlv(TAG_AUTHENTICATION_TOKEN_OUT, hex("C2B0BD78D94BA866")),
            true,
        );
        assert_eq!(
            apdu.serialize(),
            hex("008600000C7C0A8508C2B0BD78D94BA86600")
        );
    }

    /// Selection skips what we cannot run and takes the first usable entry.
    #[test]
    fn selects_a_supported_variant() {
        // BrainpoolP512r1 has no Rust implementation, so the second entry wins.
        let unavailable_curve = pace_info(0x02, 0x02, Some(17));
        let generic = pace_info(0x02, 0x02, Some(13));
        let selected = select_pace_info(&[&unavailable_curve, &generic]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::Generic);
        assert_eq!(selected.parameter_id, Some(13));
    }

    /// Chip Authentication Mapping is implemented, so it is selectable rather
    /// than skipped.
    #[test]
    fn selects_chip_authentication_mapping() {
        let cam = pace_info(0x06, 0x02, Some(13));
        let selected = select_pace_info(&[&cam]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::ChipAuthentication);
    }

    /// ICAO 9303 p11 Appendix J says PACE-CAM should be used when both sides
    /// support it, and it proves more than the other mappings do, so it wins
    /// even when the document lists it second.
    ///
    /// This is the order a real Reiseausweis für Ausländer lists them in.
    #[test]
    fn prefers_chip_authentication_mapping_over_generic() {
        let generic = pace_info(0x02, 0x02, Some(13));
        let cam = pace_info(0x06, 0x02, Some(13));
        let selected = select_pace_info(&[&generic, &cam]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::ChipAuthentication);
    }

    /// But a document that offers no CAM still gets its own first choice.
    #[test]
    fn keeps_document_order_without_chip_authentication_mapping() {
        let generic = pace_info(0x02, 0x02, Some(13));
        let integrated = pace_info(0x04, 0x02, Some(13));
        let selected = select_pace_info(&[&generic, &integrated]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::Generic);

        let selected = select_pace_info(&[&integrated, &generic]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::Integrated);
    }

    /// A CAM entry we cannot run must not shadow one we can.
    #[test]
    fn skips_an_unusable_chip_authentication_mapping_entry() {
        // CAM on BrainpoolP512r1, which has no Rust implementation.
        let unusable_cam = pace_info(0x06, 0x02, Some(17));
        let generic = pace_info(0x02, 0x02, Some(13));
        let selected = select_pace_info(&[&unusable_cam, &generic]).unwrap();
        assert_eq!(selected.algorithm.mapping, Mapping::Generic);
        assert_eq!(selected.parameter_id, Some(13));
    }

    /// A document offering only variants we lack must say what it wanted.
    #[test]
    fn rejects_a_document_with_only_unsupported_variants() {
        // BrainpoolP512r1, which has no Rust implementation.
        let unavailable_curve = pace_info(0x02, 0x02, Some(17));
        // A parameter ID the standard reserves.
        let reserved = pace_info(0x02, 0x02, Some(5));
        let error = select_pace_info(&[&unavailable_curve, &reserved]).unwrap_err();
        let message = format!("{}", error);
        assert!(message.contains("BrainpoolP512r1"), "{}", message);
        assert!(message.contains("reserved for future use"), "{}", message);
    }

    /// An ECDH OID paired with a MODP group is nonsense and must be caught.
    #[test]
    fn rejects_mismatched_key_agreement_and_parameters() {
        let mismatched = pace_info(0x02, 0x02, Some(0));
        let error = select_pace_info(&[&mismatched]).unwrap_err();
        assert!(format!("{}", error).contains("other key agreement"));
    }

    /// NIST P-224 cannot be used with the Integrated Mapping.
    #[test]
    fn rejects_nist_p224_with_integrated_mapping() {
        let barred = pace_info(0x04, 0x02, Some(10));
        assert!(select_pace_info(&[&barred]).is_err());
        // It is only barred for that mapping, though it is unsupported anyway.
        assert!(EcCurve::NistP224.allows_mapping(Mapping::Generic));
    }

    #[test]
    fn rejects_a_missing_parameter_id() {
        let no_parameters = pace_info(0x02, 0x02, None);
        let error = select_pace_info(&[&no_parameters]).unwrap_err();
        assert!(format!("{}", error).contains("domain parameter"));
    }

    #[test]
    fn rejects_an_empty_document() {
        assert!(select_pace_info(&[]).is_err());
    }

    /// DH public keys go under tag 0x84 in the token, ECDH points under 0x86.
    #[test]
    fn public_key_tags_differ_by_key_agreement() {
        assert_eq!(brainpool_agreement().public_key_tag(), TAG_PUBLIC_KEY_POINT);
        assert_eq!(
            Agreement::Dh(dh::DhGroupOps::new(&domain::MODP_1024_160)).public_key_tag(),
            TAG_PUBLIC_KEY_INTEGER
        );
    }
}
