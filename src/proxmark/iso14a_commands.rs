use super::base_commands;
use super::comms::send_and_get_command;
use super::helpers::convert_mix_args_to_ng;
use super::types::{Command, PM3PacketResponseNG, Status};
use bitflags::bitflags;

bitflags! {
    #[derive(Debug)]
    pub struct ISO14ACommand: u16 {
        const CONNECT = 1 << 0;
        const NO_DISCONNECT = 1 << 1;
        const APDU = 1 << 2;
        const RAW = 1 << 3;
        const REQUEST_TRIGGER = 1 << 4;
        const APPEND_CRC = 1 << 5;
        const SET_TIMEOUT = 1 << 6;
        const NO_SELECT = 1 << 7;
        const TOPAZMODE = 1 << 8;
        const NO_RATS = 1 << 9;
        const SEND_CHAINING = 1 << 10;
        const USE_ECP = 1 << 11;
        const USE_MAGSAFE = 1 << 12;
        const USE_CUSTOM_POLLING = 1 << 13;
        const CRYPTO1MODE = 1 << 14;
    }
}

pub fn exchange_command_14a(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    flags: u16,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    // We're expanding data here to account for it being the old format (not ng).
    let full_data = convert_mix_args_to_ng(data, u64::from(flags), data.len() as u64 & 0x1FF, 0);
    let response = send_and_get_command(port, Command::HfIso14443AReader, &full_data, false)?;

    assert!(response.status == Status::Success as i8);
    return Ok(response);
}

pub fn select_14a(
    port: &mut Box<dyn serialport::SerialPort>,
    disconnect: bool,
) -> Result<u8, Box<dyn std::error::Error>> {
    let flags = ISO14ACommand::CONNECT | ISO14ACommand::NO_DISCONNECT;
    let response = exchange_command_14a(port, &vec![], flags.bits())?;

    if disconnect {
        base_commands::hf_drop_field(port)?;
    }

    // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
    // TODO: no ATS is not currently implemented.
    assert!(response.arg0 == 1);
    return Ok(response.arg0 as u8);
}

pub fn exchange_apdu_14a(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    select: bool,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    if select {
        select_14a(port, false)?;
    }

    let flags = ISO14ACommand::APDU | ISO14ACommand::NO_DISCONNECT;
    let response = exchange_command_14a(port, data, flags.bits())?;

    assert!(response.status == Status::Success as i8);
    return Ok(response);
}
