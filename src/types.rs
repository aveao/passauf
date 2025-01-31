use asn1;

// handy: https://oid-rep.orange-labs.fr/get/0.4.0.127.0.7.2.2.2
// PACE
const OID_PACE_DH_GM: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01);
const OID_PACE_DH_GM_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01);
const OID_PACE_DH_GM_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02);
const OID_PACE_DH_GM_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03);
const OID_PACE_DH_GM_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04);
const OID_PACE_ECDH_GM: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02);
const OID_PACE_ECDH_GM_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01);
const OID_PACE_ECDH_GM_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02);
const OID_PACE_ECDH_GM_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03);
const OID_PACE_ECDH_GM_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04);
const OID_PACE_DH_IM: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03);
const OID_PACE_DH_IM_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01);
const OID_PACE_DH_IM_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02);
const OID_PACE_DH_IM_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03);
const OID_PACE_DH_IM_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04);
const OID_PACE_ECDH_IM: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04);
const OID_PACE_ECDH_IM_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01);
const OID_PACE_ECDH_IM_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02);
const OID_PACE_ECDH_IM_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03);
const OID_PACE_ECDH_IM_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04);
const OID_PACE_ECDH_CAM: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06);
const OID_PACE_ECDH_CAM_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x01);
const OID_PACE_ECDH_CAM_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02);
const OID_PACE_ECDH_CAM_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x03);
const OID_PACE_ECDH_CAM_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04);
// Terminal Authentication
const OID_TA: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02);
// Chip Authentication
const OID_PT: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x08); // Privileged Terminal
const OID_CA_DH: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01);
const OID_CA_ECDH: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02);
const OID_CA_DH_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x01);
const OID_CA_DH_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x02);
const OID_CA_DH_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x03);
const OID_CA_DH_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01, 0x04);
const OID_CA_ECDH_3DES_CBC_CBC: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x01);
const OID_CA_ECDH_AES_CBC_CMAC_128: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02);
const OID_CA_ECDH_AES_CBC_CMAC_192: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x03);
const OID_CA_ECDH_AES_CBC_CMAC_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x04);
// Pseudonymous Signature Authentication
const OID_PSA_ECDH_ECSCHNORR_SHA_256: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x03);
const OID_PSA_ECDH_ECSCHNORR_SHA_384: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x04);
const OID_PSA_ECDH_ECSCHNORR_SHA_512: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x0b, 0x01, 0x02, 0x05);

// BSI TR-03111 stuff for AlgorithmIdentifier
const OID_EC_KEY_TYPE: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x01, 0x02);

// BSI TR-03110 addons
const OID_CARD_INFO: asn1::ObjectIdentifier =
    asn1::oid!(0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x06);

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct EFCardAccess<'a> {
    pub security_infos: asn1::SetOf<'a, SecurityInfos>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
pub struct SecurityInfos {
    pub protocol: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(protocol)]
    pub content: SecurityInfo,
}

#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, Debug)]
enum SecurityInfo {
    #[defined_by(OID_TA)]
    TerminalAuthenticationInfo,
    #[defined_by(OID_PT)]
    PrivilegedTerminalInfo,
    #[defined_by(OID_CA_DH_3DES_CBC_CBC)]
    #[defined_by(OID_CA_DH_AES_CBC_CMAC_128)]
    #[defined_by(OID_CA_DH_AES_CBC_CMAC_192)]
    #[defined_by(OID_CA_DH_AES_CBC_CMAC_256)]
    #[defined_by(OID_CA_ECDH_3DES_CBC_CBC)]
    #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_128)]
    #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_192)]
    #[defined_by(OID_CA_ECDH_AES_CBC_CMAC_256)]
    ChipAuthenticationInfo,
    #[defined_by(OID_CA_DH)]
    #[defined_by(OID_CA_ECDH)]
    ChipAuthenticationDomainParameterInfo,
    #[defined_by(OID_PACE_DH_GM)]
    #[defined_by(OID_PACE_ECDH_GM)]
    #[defined_by(OID_PACE_DH_IM)]
    #[defined_by(OID_PACE_ECDH_IM)]
    #[defined_by(OID_PACE_ECDH_CAM)]
    PACEDomainParameterInfo,
    // Note: I'm not sure adding multiple defines works :/
    #[defined_by(OID_PACE_ECDH_IM_AES_CBC_CMAC_256)]
    PACEInfo(PACEInfo),
    #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_256)]
    #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_384)]
    #[defined_by(OID_PSA_ECDH_ECSCHNORR_SHA_512)]
    PSAInfo,
    #[defined_by(OID_CARD_INFO)]
    CardInfo,
}

#[derive(asn1::Asn1Read, Debug)]
struct FileID {
    // ICAO 9303 part 11
    pub fid: String,
    pub sfid: Option<String>,
}

#[derive(asn1::Asn1Read, Debug)]
struct TerminalAuthenticationInfo {
    pub version: u64, // ICAO 9303: should be 1, BSI TR-03110-3: MUST be 1 or 2
    pub ef_cvca: Option<FileID>, // BSI TR-03110-3: MUST not be used for version 2
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct ChipAuthenticationInfo {
    pub version: u64, // BSI TR-03110-3: MUST be 1, 2 or 3
    pub key_id: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct PACEInfo {
    pub version: u64, // BSI TR-03110-3: SHOULD be 2
    pub parameter_id: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct PSAInfo {
    pub required_data: PSARequiredData, // BSI TR-03110-3: SHOULD be 2
    pub key_id: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct PSARequiredData {
    pub version: u64,       // BSI TR-03110-3: MUST be 1
    pub ps1_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
    pub ps2_auth_info: u64, // BSI TR-03110-3: MUST be 0, 1 or 2
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct PACEDomainParameterInfo {
    pub domain_parameter: AlgorithmIdentifier,
    pub parameter_id: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct ChipAuthenticationDomainParameterInfo {
    pub domain_parameter: AlgorithmIdentifier,
    pub key_id: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct AlgorithmIdentifier {
    pub algorithm: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(algorithm)]
    pub parameters: AlgorithmIdentifierParameters,
}

// TODO: implement this fully
// Details on the parameters can be found in [X9.42] and [TR-03111]
#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, Debug)]
enum AlgorithmIdentifierParameters {
    #[defined_by(OID_EC_KEY_TYPE)]
    AlgorithmIdentifierParametersKeyType,
}

// TODO: this one is guesswork
#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]
struct AlgorithmIdentifierParametersKeyType {
    pub key_type: u64,
}

// TODO: PasswordInfo (optional)
// TODO: PSMInfo (conditional)
// TODO: PSCInfo (conditional)
// TODO: ChipAuthenticationPublicKeyInfo
// TODO: PSPublicKeyInfo
// TODO: RestrictedIdentificationInfo
// TODO: RestrictedIdentificationDomainParameterInfo
// TODO: EIDSecurityInfo

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct PrivilegedTerminalInfo<'a> {
    pub privileged_terminal_infos: asn1::SetOf<'a, SecurityInfos>,
}

// #[derive(asn1::Asn1Read, Debug)]
// struct CardInfo {
//     pub url_card_info: String,
//     pub optional_card_info_data: Option<OptionalCardInfoData>,
// }

// #[derive(asn1::Asn1Read, Debug)]
// enum OptionalCardInfoData {
//     ef_card_info(FileID),
// }

#[derive(asn1::Asn1Read)]
struct CardInfo<'a> {
    pub url_card_info: String,
    pub optional_card_info_data: Option<OptionalCardInfoData<'a>>,
}

#[derive(asn1::Asn1Read)]
enum OptionalCardInfoData<'a> {
    ef_card_info(FileID),
    #[implicit(0)]
    ext_card_info_data(ExtCardInfoData<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct SupportedTerminalTypes<'a> {
    pub supported_terminal_type: asn1::ObjectIdentifier,
    pub supported_authorizations: Option<asn1::SetOf<'a, asn1::ObjectIdentifier>>,
}

#[derive(asn1::Asn1Read)]
struct ExtCardInfoData<'a> {
    pub ef_card_info: Option<FileID>,
    pub supported_tr_version: Option<asn1::Utf8String<'a>>,
    pub supp_terminal_types: Option<asn1::SetOf<'a, SupportedTerminalTypes<'a>>>,
    pub max_sc_no: Option<u64>,
    pub env_info: Option<bool>,
}
