use serde::{Deserialize, Serialize};
use strum::{FromRepr, IntoStaticStr};

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
}

#[derive(Serialize, Debug)]
pub(crate) struct PM3PacketCommandInternal {
    pub magic: u32,
    pub length_and_ng: u16, // length is 15b, ng is 1b
    pub cmd: u16,
}

#[derive(Deserialize, Debug)]
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
}

#[derive(Deserialize, Debug)]
#[repr(packed)] // If disabling this, hardcode data_offset to 10.
pub(crate) struct PM3PacketResponseNGInternal {
    pub magic: u32,
    pub length_and_ng: u16, // length is 15b, ng is 1b
    pub status: i8,
    pub reason: i8,
    pub cmd: u16,
}

#[derive(Debug)]
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

impl PM3PacketResponseNG {
    pub fn empty() -> PM3PacketResponseNG {
        return PM3PacketResponseNG {
            arg0: 0,
            arg1: 0,
            arg2: 0,
            cmd: 0,
            data: vec![],
            length: 0,
            ng: false,
            reason: 0,
            status: Status::EUndef as i8,
        };
    }
}
