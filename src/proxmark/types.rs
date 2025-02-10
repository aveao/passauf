use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use strum::{FromRepr, IntoStaticStr};

#[derive(Debug)]
pub struct CannotSelectError;

impl Error for CannotSelectError {}

impl fmt::Display for CannotSelectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not select a card in field.")
    }
}

#[derive(Debug)]
pub struct CRCMismatchError;

impl Error for CRCMismatchError {}

impl fmt::Display for CRCMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Got a wrong CRC/Postamble.")
    }
}

#[derive(Debug)]
pub struct DataTooLongError {
    pub found_len: usize,
    pub max_len: usize,
}

impl Error for DataTooLongError {}

impl fmt::Display for DataTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Given data ({}b) is too long (must be <{}b).",
            self.found_len, self.max_len
        )
    }
}

#[derive(Debug)]
pub struct PreambleMismatchError;

impl Error for PreambleMismatchError {}

impl fmt::Display for PreambleMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Got a wrong Preamble.")
    }
}

#[derive(Debug)]
pub struct CommandError {
    pub error_code: i8,
    pub error_name: Option<String>,
}

impl Error for CommandError {}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Put error name if we have it.
        let error_desc = if self.error_name.is_some() {
            format!(
                "{} ({:02x})",
                self.error_name.as_ref().unwrap(),
                self.error_code
            )
        } else {
            format!("{:02x}", self.error_code)
        };
        write!(f, "Got command error {} from Proxmark3.", error_desc)
    }
}

#[derive(Debug)]
pub struct UnexpectedResponse {
    pub additional_text: String,
}

impl Error for UnexpectedResponse {}

impl fmt::Display for UnexpectedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Got an unexpected response: {}", self.additional_text)
    }
}

// from: https://github.com/RfidResearchGroup/proxmark3/blob/e4430037336b86f0aa7a08d23b67efcab662c829/include/pm3_cmd.h#L877
#[repr(i8)]
#[derive(Debug, FromRepr, IntoStaticStr, PartialEq, Clone, Copy)]
pub enum Status {
    Success = 0,
    EUndef = -1,
    EInvArg = -2,
    EDevNotSupp = -3,
    ETimeout = -4,
    EOpAborted = -5,
    ENotImpl = -6,
    ERFTrans = -7,
    EIo = -8,
    EOvflow = -9,
    ESoft = -10,
    EFlash = -11,
    EMalloc = -12,
    EFile = -13,
    ENotty = -14,
    EInit = -15,
    EWrongAnswer = -16,
    EOutOfBound = -17,
    ECardExchange = -18,
    EApduEncodeFail = -19,
    EApduFail = -20,
    EFailed = -21,
    EPartial = -22,
    ETearoff = -23,
    ECrc = -24,
    EStaticNonce = -25,
    ENoPacs = -26,
    ELength = -27,
    ENoKey = -28,
    ENoData = -98,
    EFatal = -99,
    SQuit = -100,
    Reserved = -128,
}

// more at: https://github.com/RfidResearchGroup/proxmark3/blob/e4430037336b86f0aa7a08d23b67efcab662c829/include/pm3_cmd.h#L419
#[repr(u16)]
#[derive(Debug, FromRepr, IntoStaticStr, PartialEq, Clone, Copy)]
pub enum Command {
    DebugPrintString = 0x0100,
    Ping = 0x0109,
    Capabilities = 0x0112,
    QuitSession = 0x0113,
    Wtx = 0x0116, // Wait time extension
    Ack = 0x00ff,
    HfDropfield = 0x0430,
    HfIso14443AReader = 0x0385,
    HfIso14443BCommand = 0x0305,
}

#[derive(Serialize, Debug)]
pub(crate) struct PM3PacketCommandInternal {
    pub magic: u32,
    pub length_and_ng: u16, // length is 15b, ng is 1b
    pub cmd: u16,
    // data: Vec<u8>,
    // postamble: u16,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
#[repr(packed)] // If disabling this, hardcode data_offset to 10.
pub(crate) struct PM3PacketResponseMIXInternal {
    pub magic: u32,
    pub length_and_ng: u16, // length is 15b, ng is 1b
    pub status: i8,
    pub reason: i8,
    pub cmd: u16,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    // data: Vec<u8>,
    // postamble: u16,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
#[repr(packed)] // If disabling this, hardcode data_offset to 10.
pub(crate) struct PM3PacketResponseNGInternal {
    pub magic: u32,
    pub length_and_ng: u16, // length is 15b, ng is 1b
    pub status: i8,
    pub reason: i8,
    pub cmd: u16,
    // data: Vec<u8>,
    // postamble: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PM3PacketResponseNG {
    pub length: u16,
    pub ng: bool,
    pub status: i8,
    pub reason: i8,
    pub cmd: u16,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub data: Vec<u8>,
}
