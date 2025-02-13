// handy: https://oid-rep.orange-labs.fr/get/0.4.0.127.0.7.2.2.2
// pub static PACE_DOMAIN_PARAMETERS_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01),
//     "ECDH_GM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02),
//     "DH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03),
//     "ECDH_IM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04),
//     "ECDH_CAM" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06),
// };

// pub static CHIP_AUTH_DOMAIN_PARAMETERS_OIDS: phf::Map<
//     &'static str,
//     &'static asn1::ObjectIdentifier,
// > = phf_map! {
//     "DH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01),
//     "ECDH" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02),
// };

// pub static PACEINFO_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01),
//     "DH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02),
//     "DH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03),
//     "DH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04),
//     "ECDH_GM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01),
//     "ECDH_GM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02),
//     "ECDH_GM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03),
//     "ECDH_GM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04),
//     "DH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01),
//     "DH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02),
//     "DH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03),
//     "DH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04),
//     "ECDH_IM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01),
//     "ECDH_IM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02),
//     "ECDH_IM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03),
//     "ECDH_IM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04),
//     "ECDH_CAM_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x01),
//     "ECDH_CAM_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02),
//     "ECDH_CAM_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x03),
//     "ECDH_CAM_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04),
// };

// pub static CHIPAUTH_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "DH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01),
//     "DH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x02),
//     "DH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x03),
//     "DH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x04),
//     "ECDH_3DES_CBC_CBC" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01),
//     "ECDH_AES_CBC_CMAC_128" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x02),
//     "ECDH_AES_CBC_CMAC_192" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x03),
//     "ECDH_AES_CBC_CMAC_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x03, 0x04, 0x02, 0x04),
// };

// // Pseudonymous Signature Authentication
// pub static PSA_OIDS: phf::Map<&'static str, &'static asn1::ObjectIdentifier> = phf_map! {
//     "ECDH_ECSCHNORR_SHA_256" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x03),
//     "ECDH_ECSCHNORR_SHA_384" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x04),
//     "ECDH_ECSCHNORR_SHA_512" => &asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x05),
// };

// // Terminal Authentication
// const TA_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02);

// // Privileged Terminal
// const PT_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x08);

// // BSI TR-03110 addons
// const CARD_INFO_OID: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x06);

// // BSI TR-03111 stuff for AlgorithmIdentifier
// const OID_EC_KEY_TYPE: asn1::ObjectIdentifier =
//     asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x01, 0x02);

// #[derive(Debug)]
// struct SecurityInfos {
//     // #[defined_by(OID_TA)]
//     pub terminal_authentication_info: Vec<TerminalAuthenticationInfo>,
//     // #[defined_by(OID_PT)]
//     pub privileged_terminal_info: Vec<PrivilegedTerminalInfo>,
//     // #[defined_by(OID_CA_DH_3DES_CBC_CBC)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_128)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_192)]
//     // #[defined_by(OID_CA_DH_AES_CBC_CMAC_256)]
//     // #[defined_by(OID_CA_ECDH_3DES_CBC_CBC)]
//     // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_128)]
//     // #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_192)]
//     pub chip_authentication_info: Vec<ChipAuthenticationInfo>,
//     // #[defined_by(OID_CA_DH)]
//     // #[defined_by(OID_CA_ECDH)]
//     pub chip_authentication_domain_parameter_info: Vec<ChipAuthenticationDomainParameterInfo>,
//     // #[defined_by(OID_PACE_DH_GM)]
//     // #[defined_by(OID_PACE_ECDH_GM)]
//     // #[defined_by(OID_PACE_DH_IM)]
//     // #[defined_by(OID_PACE_ECDH_IM)]
//     // #[defined_by(OID_PACE_ECDH_CAM)]
//     pub pace_domain_parameter_info: Vec<PACEDomainParameterInfo>,
//     // #[defined_by(OID_PACE_ECDH_IM_AES_CBC_CMAC_256)]
//     pub pace_info: Vec<PACEInfoParameters>,
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_256)]
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_384)]
//     // #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_512)]
//     pub pseudonymous_signature_authentication_info: Vec<PSAInfo>,
//     // #[defined_by(OID_CARD_INFO)]
//     pub card_info: Vec<CardInfo>,
//     // TODO: PasswordInfo (optional)
//     // TODO: PSMInfo (conditional)
//     // TODO: PSCInfo (conditional)
//     // TODO: ChipAuthenticationPublicKeyInfo
//     // TODO: PSPublicKeyInfo
//     // TODO: RestrictedIdentificationInfo
//     // TODO: RestrictedIdentificationDomainParameterInfo
//     // TODO: EIDSecurityInfo
// }

// #[derive(Debug)]
// struct FileID {
//     // ICAO 9303 part 11
//     pub fid: String,
//     pub sfid: Option<String>,
// }

// #[derive(Debug)]
// struct TerminalAuthenticationInfo {
//     pub version: u64, // ICAO 9303: should be 1, BSI TR-03110-3: MUST be 1 or 2
//     pub ef_cvca: Option<FileID>, // BSI TR-03110-3: MUST not be used for version 2
// }

// #[derive(Debug)]
// struct ChipAuthenticationInfo {
//     pub version: u64, // BSI TR-03110-3: MUST be 1, 2 or 3
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// pub struct PACEInfoParameters {
//     pub version: u64, // BSI TR-03110-3: SHOULD be 2
//     pub parameter_id: Option<u64>,
// }

// #[derive(Debug)]
// struct PSAInfo {
//     pub required_data: PSARequiredData, // BSI TR-03110-3: SHOULD be 2
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// struct PSARequiredData {
//     pub version: u64,       // BSI TR-03110-3: MUST be 1
//     pub ps1_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
//     pub ps2_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
// }

// #[derive(Debug)]
// struct PACEDomainParameterInfo {
//     pub domain_parameter: AlgorithmIdentifier,
//     pub parameter_id: Option<u64>,
// }

// #[derive(Debug)]
// struct ChipAuthenticationDomainParameterInfo {
//     pub domain_parameter: AlgorithmIdentifier,
//     pub key_id: Option<u64>,
// }

// #[derive(Debug)]
// struct AlgorithmIdentifier {
//     pub algorithm: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
//     // TODO: parameters here are algorithm dependent.
//     // Details on the parameters can be found in [X9.42] and [TR-03111]
//     pub key_type: u64,
// }

// #[derive(Debug)]
// struct PrivilegedTerminalInfo {
//     pub privileged_terminal_infos: Vec<SecurityInfos>,
// }

// #[derive(Debug)]
// struct CardInfo {
//     pub url_card_info: String,
//     pub optional_card_info_data: Option<ExtCardInfoData>,
// }

// #[derive(Debug)]
// struct SupportedTerminalTypes {
//     pub supported_terminal_type: asn1::ObjectIdentifier,
//     pub supported_authorizations: Option<Vec<asn1::ObjectIdentifier>>,
// }

// #[derive(Debug)]
// struct ExtCardInfoData {
//     pub ef_card_info: Option<FileID>,
//     pub supported_tr_version: Option<String>,
//     pub supp_terminal_types: Option<Vec<SupportedTerminalTypes>>,
//     pub max_sc_no: Option<u64>,
//     pub env_info: Option<bool>,
// }
