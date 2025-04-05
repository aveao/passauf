use iso7816_tlv::ber;
use simplelog::{debug, error, trace};
use simplelog::{info, warn};
///! ISO 7816 APDU handlers (for ICAO 9303 only)
use std::cmp::min;
use strum::{FromRepr, IntoStaticStr};

use crate::helpers;
use crate::icao9303;
use crate::smartcard_abstractions::Smartcard;
use crate::types;

#[repr(u8)]
pub enum Command {
    ReadBinary = 0xB0,
    SelectFile = 0xA4,
    GetChallenge = 0x84,
    ExternalAuthentication = 0x82,
}

// Taken from https://github.com/RfidResearchGroup/proxmark3/blob/master/include/protocols.h#L502
// and extended from ISO/IEC 7816-4
#[repr(u16)]
#[derive(Debug, FromRepr, IntoStaticStr, PartialEq, Clone, Copy)]
pub enum StatusCode {
    Ok = 0x9000,
    BytesRemaining00 = 0x6100,
    WarningStateUnchanged = 0x6200,
    DataCorrupt = 0x6281,
    FileEof = 0x6282,
    InvalidDf = 0x6283,
    InvalidFile = 0x6284,
    FileTerminated = 0x6285,
    AuthFailed = 0x6300,
    FileFilled = 0x6381,
    MemoryFull = 0x6501,
    WriteMemoryErr = 0x6581,
    WrongLength = 0x6700,
    LogicalChannelNotSupported = 0x6881,
    SecureMessagingNotSupported = 0x6882,
    LastCommandExpected = 0x6883,
    CommandChainingNotSupported = 0x6884,
    TransactionFail = 0x6900,
    SelectFileErr = 0x6981,
    SecurityStatusNotSatisfied = 0x6982,
    FileInvalid = 0x6983,
    DataInvalid = 0x6984,
    ConditionsNotSatisfied = 0x6985,
    CommandNotAllowed = 0x6986,
    SmDataMissing = 0x6987,
    SmDataIncorrect = 0x6988,
    AppletSelectFailed = 0x6999,
    InvalidP1P2 = 0x6A00,
    WrongData = 0x6A80,
    FuncNotSupported = 0x6A81,
    FileNotFound = 0x6A82,
    RecordNotFound = 0x6A83,
    FileFull = 0x6A84,
    LcTlvConflict = 0x6A85,
    IncorrectP1P2 = 0x6A86,
    NcInconsistentWithP1P2 = 0x6A87,
    FileExists = 0x6A89,
    NotImplemented = 0x6AFF,
    WrongP1P2 = 0x6B00,
    CorrectLength00 = 0x6C00,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    Unknown = 0x6F00,
}

#[derive(Debug)]
pub struct ApduCommand {
    pub cla: u8,           // class
    pub ins: u8,           // instruction
    pub p1: u8,            // parameter 1
    pub p2: u8,            // parameter 2
    pub data: Vec<u8>,     // data
    pub max_resp_len: u16, // aka le
}

impl ApduCommand {
    fn get_field_len_vec(field: u16) -> Vec<u8> {
        let field_bytes = field.to_le_bytes();
        let field_len: Vec<u8> = match field {
            0 => vec![],
            1..256 => vec![field as u8],
            256.. => vec![0, field_bytes[0], field_bytes[1]],
        };
        return field_len;
    }

    /// Serialize the APDU to a byte stream
    pub fn serialize(&self) -> Vec<u8> {
        // https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit#APDU_message_command-response_pair
        // Lc: length of data
        let lc = Self::get_field_len_vec(self.data.len() as u16);
        // Le: length of expected response
        let le = Self::get_field_len_vec(self.max_resp_len);

        let apdu = vec![
            vec![self.cla, self.ins, self.p1, self.p2],
            lc,
            self.data.clone(),
            le,
        ]
        .concat();
        return apdu;
    }

    /// Serialize the APDU to a byte stream (as a secure APDU)
    pub fn bac_secure_serialize(
        &self,
        ssc: &mut u64,
        ks_enc: &Vec<u8>,
        ks_mac: &Vec<u8>,
    ) -> Vec<u8> {
        // Command APDU: [DO‘85’ or DO‘87’] [DO‘97’] DO‘8E’.
        // Relevant for BER-TLV: ISO 7816-4-2020+A1-2023: 10.2.3, Table 50 and surroundings

        // ICAO 9303 p11: "The command header MUST be included in the MAC calculation,
        // therefore the class byte CLA = 0x0C MUST be used."
        // Here we're masking the class byte with 0x0C, which is the proper approach.
        // We only ever use CLA=0x00 so we could hardcode this to 0x0C, but I want to be thorough.
        let cla = self.cla | 0x0C;

        // Le: length of expected response
        let base_le = Self::get_field_len_vec(self.max_resp_len);
        let cmd = vec![cla, self.ins, self.p1, self.p2];
        let padded_cmd = icao9303::padding_method_2_pad(&cmd);
        debug!("padded_cmd: {:02x?}", padded_cmd);

        // Padded Command + Data as BER-TLV (if set) + Padded Response Length as BER-TLV (if set) + MAC
        let mut secure_data: Vec<u8> = vec![];

        if !self.data.is_empty() {
            let padded_data = icao9303::padding_method_2_pad(&self.data);
            debug!("padded_data: {:02x?}", padded_data);

            // ICAO 9303 p11: "In case INS is even, DO‘87’ SHALL be used, and in case INS is odd, DO‘85’ SHALL be used."
            // BSI TR-03110 does not use DO'85' at all.
            // ISO 7816-4-2020+A1-2023: "When bit b1 of INS is set to 1 (odd INS code, see 5.5), the unsecured data
            // fields are encoded in ber-tlv and SM tags 'B2', 'B3', '84' and '85' shall be used for their encapsulation;
            // unless the use of tags '80', '81', '86' and '87' is specified at application level."
            // Only very few commands in ISO 7816-4 have odd INS numbers.
            // In this context we only use even commands so far, so having only DO'87' may be enough.

            // If instruction is an even number
            if self.ins % 2 == 0 {
                let encrypted_data = icao9303::tdes_enc(ks_enc, &padded_data);
                debug!("encrypted_data: {:02x?}", encrypted_data);
                // Tag is 0x87, "Padding-content indicator byte followed by cryptogram".
                let tag = ber::Tag::try_from(0x87).unwrap();
                // Value in DO'87' is data prepended with the Padding-content indicator byte.
                // 0x01 is padding method 2 according to ISO 7816-4-2020+A1-2023, Table 53.
                let value = vec![[0x01].as_slice(), &encrypted_data].concat();

                let do_87_tlv = ber::Tlv::new(tag, ber::Value::Primitive(value)).unwrap();
                debug!("do_87_tlv: {:02x?}", do_87_tlv);
                secure_data.extend_from_slice(&do_87_tlv.to_vec());
            // If instruction is an odd number
            } else {
                // Tag is 0x85, "Cryptogram (plain value encoded in ber-tlv, but not including SM DOs)".
                panic!("DO'85' is not implemented.");
            }
        }

        if self.max_resp_len != 0 {
            // Tag is 0x97, "One or two bytes encoding Le in the unsecured C-RP (possibly empty)"
            let tag = ber::Tag::try_from(0x97).unwrap();

            // Value is the original Le
            let do_97_tlv = ber::Tlv::new(tag, ber::Value::Primitive(base_le.clone())).unwrap();
            debug!("do_97_tlv: {:02x?}", do_97_tlv);
            secure_data.extend_from_slice(&do_97_tlv.to_vec());
        }

        *ssc += 1;
        debug!("post-bump ssc: {:02x?}", ssc);

        // Pad secure data so far with Padding Method 2
        debug!("unpadded secure_data: {:02x?}", secure_data);
        let padded_secure_data = icao9303::padding_method_2_pad(
            &vec![
                ssc.to_be_bytes().as_slice(),
                padded_cmd.as_slice(),
                secure_data.as_slice(),
            ]
            .concat(),
        );
        debug!("padded secure_data: {:02x?}", padded_secure_data);

        // Calculate the MAC for the secure data so far
        let secure_data_mac = icao9303::retail_mac(ks_mac, &padded_secure_data);
        debug!("secure_data_mac: {:02x?}", secure_data_mac);

        // Tag is 0x97, "One or two bytes encoding Le in the unsecured C-RP (possibly empty, see 10.5)"
        let tag = ber::Tag::try_from(0x8E).unwrap();
        // Value is the dynamic length of the MAC (should be 8 bytes)

        let do_8e_tlv = ber::Tlv::new(tag, ber::Value::Primitive(secure_data_mac.clone())).unwrap();
        debug!("do_8e_tlv: {:02x?}", do_8e_tlv);
        secure_data.extend_from_slice(&do_8e_tlv.to_vec());
        debug!("final secure_data: {:02x?}", secure_data);

        // Lc: length of data
        let lc = Self::get_field_len_vec(secure_data.len() as u16);

        // Outer Le is set to 0x00 to allow the full frame
        let le = vec![0x00];

        let apdu = vec![cmd, lc, secure_data, le].concat();
        return apdu;
    }

    /// Send APDU to the given smartcard
    ///
    /// Returns (RAPDU, status code)
    pub fn exchange(
        &mut self,
        smartcard: &mut Box<impl Smartcard + ?Sized>,
        assert_on_status: bool,
    ) -> (Vec<u8>, u16) {
        let (rapdu, status_code) =
            self.secure_exchange(smartcard, assert_on_status, false, &mut 0, &vec![], &vec![]);
        return (rapdu, status_code);
    }

    /// Send APDU to the given smartcard using secure communications
    ///
    /// Returns (RAPDU, status code)
    pub fn secure_exchange(
        &mut self,
        smartcard: &mut Box<impl Smartcard + ?Sized>,
        assert_on_status: bool,
        secure_comms: bool,
        ssc: &mut u64,
        ks_enc: &Vec<u8>,
        ks_mac: &Vec<u8>,
    ) -> (Vec<u8>, u16) {
        let mut done_exchanging = false;
        let mut rapdu_data: Vec<u8> = vec![];
        let mut status_code_bytes: Vec<u8> = vec![];
        while !done_exchanging {
            debug!("> APDU (secure: {:?}): {:x?}", secure_comms, self);
            let apdu_bytes = if secure_comms {
                self.bac_secure_serialize(ssc, ks_enc, ks_mac)
            } else {
                self.serialize()
            };

            rapdu_data = smartcard.exchange_apdu(&apdu_bytes).unwrap();
            status_code_bytes = get_status_code_bytes(&rapdu_data);

            // - 2 bytes for status code
            if secure_comms {
                match parse_secure_rapdu(&rapdu_data[..rapdu_data.len() - 2], ssc, ks_enc, ks_mac) {
                    Some(data) => {
                        rapdu_data = data;
                    }
                    None => {}
                };
            } else {
                rapdu_data = rapdu_data[..rapdu_data.len() - 2].to_vec();
            }

            // ISO/IEC 7816-4 says:
            // If SW1 is set to '6C', then the process is aborted and before issuing
            // any other command, the same command may be re-issued using SW2
            // (exact number of available data bytes) as short Le field.
            if status_code_bytes[0] == 0x6C {
                debug!(
                    "Got a SW1=6C, re-requesting {:?} with Le={:?}",
                    self, status_code_bytes[1]
                );
                self.max_resp_len = u16::from(status_code_bytes[1]);
            } else {
                done_exchanging = true;
            }
        }

        // TODO: validate hash
        let status_code = u16::from_be_bytes(status_code_bytes.try_into().unwrap());

        if assert_on_status {
            // Intentionally not checking 61 here.
            // One shouldn't use assert_on_status if you handle 61.
            assert!(status_code == StatusCode::Ok as u16);
        }

        return (rapdu_data, status_code);
    }
}

pub fn select_and_read_file(
    smartcard: &mut Box<impl Smartcard + ?Sized>,
    dg_info: &types::DataGroup,
    secure_comms: bool,
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> Option<Vec<u8>> {
    info!("<d>Selecting {} ({})</>", dg_info.name, dg_info.description);
    let mut apdu = apdu_select_file_by_ef(dg_info.file_id);
    let (_, status_code) =
        apdu.secure_exchange(smartcard, false, secure_comms, ssc, ks_enc, ks_mac);

    if status_code != StatusCode::Ok as u16 {
        warn!("{} not found (this is probably fine).", dg_info.name);
        return None;
    }

    info!("<d>Reading {} ({})</>", dg_info.name, dg_info.description);
    let mut total_data: Vec<u8> = vec![];
    let mut bytes_to_read = 0x05;
    let mut file_len: u16 = 0;
    while bytes_to_read > 0 {
        let mut apdu = apdu_read_binary(total_data.len() as u16, bytes_to_read);
        let (apdu_data, status_code) =
            apdu.secure_exchange(smartcard, false, secure_comms, ssc, ks_enc, ks_mac);
        let status_code_bytes = status_code.to_be_bytes();

        // Unfortunately, ICAO 9303 does not allow us to read file sizes.
        // We must, therefore, read the ASN.1 header to get the size.
        // I'd love to replace this with a better solution if I find one.
        if total_data.is_empty() && status_code_bytes[0] == 0x90 {
            // TODO: this does not account for non-ASN1 files. We can use .is_asn1.
            let (field_len, asn1_len) = helpers::asn1_parse_len(apdu_data[1..].to_vec());
            // TODO: rethink this u16.
            // We should account for u32 even tho its unlikely.
            // offset by 1 as we're skipping the initial tag.
            file_len = (1u32 + field_len as u32 + asn1_len) as u16;

            if file_len > 5_000 {
                info!(
                    "<d>{} seems quite large ({}b), this may take a bit.</>",
                    dg_info.name, file_len
                );
            }
        }

        debug!(
            "Reading file, file_len: {:?} total_data.len(): {:?} apdu_data.len(): {:?}",
            file_len,
            total_data.len(),
            apdu_data.len()
        );

        // ISO/IEC 7816-4 says:
        // If SW1 is set to '61', then the process is completed and before issuing
        // any other command, a get response command may be issued with the same CLA
        // and using SW2 (number of data bytes still available) as short Le field.
        if status_code_bytes[0] == 0x61 {
            bytes_to_read = u16::from(status_code_bytes[1]);
        } else if (((total_data.len() + apdu_data.len()) as u16) < file_len)
            && (status_code_bytes[0] == 0x90)
        {
            bytes_to_read = min(0x80, file_len - (total_data.len() + apdu_data.len()) as u16);
        } else {
            bytes_to_read = 0;
            // if the read failed at some point, return None
            // TODO: this'd be a good spot to report status code text
            if status_code_bytes[0] != 0x90 {
                return None;
            }
        }

        total_data.extend(apdu_data);
    }
    debug!("Read file ({:?}b): {:?}", total_data.len(), total_data);
    // only return data if it's not empty.
    return if total_data.is_empty() {
        None
    } else {
        Some(total_data)
    };
}

/// Parse a secure Response APDU
///
/// Currently supports DO'99', '87' and '8E'
/// Returns the decrypted data from DO'87'
pub fn parse_secure_rapdu(
    rapdu: &[u8],
    ssc: &mut u64,
    ks_enc: &Vec<u8>,
    ks_mac: &Vec<u8>,
) -> Option<Vec<u8>> {
    const SIGNATURE_CHECK_CONCAT_ORDER: [u16; 2] = [0x87, 0x99];
    // Increment SSC when we receive a secure RAPDU
    *ssc += 1;
    debug!("post-bump ssc: {:02x?}", ssc);
    let parsed_rapdu = ber::Tlv::parse_all(rapdu);
    debug!("parsed_rapdu: {:02x?}", parsed_rapdu);

    let rapdu_tlvs = helpers::sort_tlvs_by_tag(&parsed_rapdu);
    debug!("rapdu_tlvs: {:02x?}", rapdu_tlvs);

    if rapdu_tlvs.contains_key(&0x85) {
        panic!("DO'85' is not implemented.");
    }

    // Concat SSC + [DO'87'] + DO'99' + padding, to compare against DO'8E'
    let mut signature_check_data: Vec<u8> = ssc.to_be_bytes().to_vec();
    for tlv_tag_id in SIGNATURE_CHECK_CONCAT_ORDER {
        match rapdu_tlvs.get(&tlv_tag_id) {
            Some(tlv) => {
                signature_check_data.extend_from_slice(&tlv.to_vec());
            }
            None => {}
        }
    }
    signature_check_data = icao9303::padding_method_2_pad(&signature_check_data);
    debug!("signature_check_data: {:02x?}", signature_check_data);

    // Calculate the MAC for the data we received
    let signature_check_mac = icao9303::retail_mac(ks_mac, &signature_check_data);
    debug!("signature_check_mac: {:02x?}", signature_check_mac);

    // Extract the value of DO'8E' and compare to the MAC we calculated.
    let do_8e_tlv = rapdu_tlvs.get(&0x8E)?;
    let do_8e_value = helpers::get_tlv_value_bytes(do_8e_tlv.to_owned());
    assert!(signature_check_mac == do_8e_value);

    // Extract the value of DO'87' and return the encrypted data.
    // This assumes we don't have a DO'85' and that we always have DO'87'.
    if rapdu_tlvs.contains_key(&0x87) {
        let do_87_tlv = rapdu_tlvs.get(&0x87).unwrap();
        let mut do_87_value = helpers::get_tlv_value_bytes(do_87_tlv.to_owned());
        // We skip first byte due to it being the "Padding-content indicator byte".
        // ICAO 9303 only allows one value, so we don't need to think much about it.
        // Still, an assert is here.
        assert!(do_87_value[0] == 0x01);
        do_87_value = do_87_value[1..].to_vec();
        debug!("do_87_value: {:02x?}", do_87_value);
        let decrypted_data = icao9303::tdes_dec(ks_enc, &do_87_value);
        debug!("decrypted_data: {:02x?}", decrypted_data);
        let decrypted_unpadded_data = icao9303::padding_method_2_unpad(&decrypted_data);
        debug!("decrypted_unpadded_data: {:02x?}", decrypted_unpadded_data);
        return Some(decrypted_unpadded_data);
    }

    return None;
}

pub const P1_SELECT_BY_EF: u8 = 0x02;
pub const P1_SELECT_BY_NAME: u8 = 0x04;
pub const P2_PROPRIETARY: u8 = 0x0C;

pub fn get_status_code_bytes(data: &Vec<u8>) -> Vec<u8> {
    let status_code_start = data.len() - 2;
    return data[status_code_start..status_code_start + 2].to_vec();
}

pub fn get_status_code(data: &Vec<u8>) -> u16 {
    let status_code_bytes = get_status_code_bytes(data);
    return u16::from_be_bytes(status_code_bytes.try_into().unwrap());
}

pub fn get_status_code_repr(status_code_num: u16, panic_on_non_ok: bool) -> StatusCode {
    let status_code_repr = StatusCode::from_repr(status_code_num).unwrap();
    let status_code_name: &'static str = status_code_repr.into();
    trace!("Status code: {:x?} ({})", status_code_num, status_code_name);
    if panic_on_non_ok {
        error!("Status code: {:x?} ({})", status_code_num, status_code_name);
        assert!(status_code_repr == StatusCode::Ok);
    }
    return status_code_repr;
}

pub fn apdu_select_file_by_name(name: Vec<u8>) -> ApduCommand {
    return ApduCommand {
        cla: 0,
        ins: Command::SelectFile as u8,
        p1: P1_SELECT_BY_NAME,
        p2: P2_PROPRIETARY,
        data: name,
        max_resp_len: 0,
    };
}

pub fn apdu_select_file_by_ef(file_id: u16) -> ApduCommand {
    return ApduCommand {
        cla: 0,
        ins: Command::SelectFile as u8,
        p1: P1_SELECT_BY_EF,
        p2: P2_PROPRIETARY,
        data: file_id.to_be_bytes().to_vec(),
        max_resp_len: 0,
    };
}

pub fn apdu_read_binary(offset: u16, bytes_to_read: u16) -> ApduCommand {
    let offset_bytes = offset.to_be_bytes();
    return ApduCommand {
        cla: 0,
        ins: Command::ReadBinary as u8,
        p1: offset_bytes[0],
        p2: offset_bytes[1],
        data: vec![],
        max_resp_len: bytes_to_read,
    };
}

pub fn apdu_get_challenge() -> ApduCommand {
    return ApduCommand {
        cla: 0,
        ins: Command::GetChallenge as u8,
        p1: 0,
        p2: 0,
        data: vec![],
        max_resp_len: 8, // rnd.ic is 8 bytes
    };
}

pub fn apdu_external_authentication(data: Vec<u8>) -> ApduCommand {
    return ApduCommand {
        cla: 0,
        ins: Command::ExternalAuthentication as u8,
        p1: 0,
        p2: 0,
        data: data,
        // magic length from ICAO 9303 p11 (0x28)
        max_resp_len: 40,
    };
}
