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

// more at: https://github.com/RfidResearchGroup/proxmark3/blob/e4430037336b86f0aa7a08d23b67efcab662c829/include/pm3_cmd.h#L877
#[repr(i8)]
#[derive(Debug, FromRepr, IntoStaticStr, PartialEq, Clone, Copy)]
pub enum Status {
    Success = 0,
    EUndef = -1,
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
