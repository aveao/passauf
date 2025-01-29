use log::{error, trace};
use strum::{FromRepr, IntoStaticStr};

#[repr(u8)]
pub enum Command {
    ReadBinary = 0xB0,
    SelectFile = 0xA4,
    GetChallenge = 0x84,
    ExternalAuthentication = 0x82,
}

// Taken from https://github.com/RfidResearchGroup/proxmark3/blob/master/include/protocols.h#L502
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
}

pub const P1_SELECT_BY_EF: u8 = 0x02;
pub const P1_SELECT_BY_NAME: u8 = 0x04;
pub const P2_PROPRIETARY: u8 = 0x0C;

pub fn get_status_code_bytes(data: &Vec<u8>) -> Vec<u8> {
    let status_code_start = data.len() - 4;
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
        max_resp_len: 10, // 8 + SW for rnd_ic
    };
}

pub fn apdu_external_authentication(data: Vec<u8>) -> ApduCommand {
    return ApduCommand {
        cla: 0,
        ins: Command::ExternalAuthentication as u8,
        p1: 0,
        p2: 0,
        data: data,
        max_resp_len: 40, // 8 + SW for rnd_ic
    };
}
