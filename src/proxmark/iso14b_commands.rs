use super::comms::send_and_get_command;
use super::types::{Command, PM3PacketResponseNG, Status};
use bitflags::bitflags;
use simplelog::debug;

bitflags! {
    #[derive(Debug)]
    pub struct ISO14BCommand: u16 {
        const CONNECT = 1 << 0;
        const DISCONNECT = 1 << 1;
        const APDU = 1 << 2;
        const RAW = 1 << 3;
        const REQUEST_TRIGGER = 1 << 4;
        const APPEND_CRC = 1 << 5;
        const SELECT_STD = 1 << 6;
        const SELECT_SR = 1 << 7;
        const SET_TIMEOUT = 1 << 8;
        const SEND_CHAINING = 1 << 9;
        const SELECT_CTS = 1 << 10;
        const CLEARTRACE = 1 << 11;
        const SELECT_XRX = 1 << 12;
        const SELECT_PICOPASS = 1 << 13;
    }
}

pub fn serialize_14b_command(flags: u16, timeout: u32, data: &Vec<u8>) -> Vec<u8> {
    let packet = vec![
        flags.to_le_bytes().as_slice(),
        timeout.to_le_bytes().as_slice(),
        (data.len() as u16).to_le_bytes().as_slice(),
        data.as_slice(),
    ]
    .concat();
    debug!("serialized 14b command: {:x?}", packet);
    return packet;
}

pub fn switch_off_field_14b(
    port: &mut Box<dyn serialport::SerialPort>,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = serialize_14b_command(ISO14BCommand::DISCONNECT.bits(), 0, &vec![]);
    let response = send_and_get_command(port, Command::HfIso14443BCommand, &data, true)?;

    assert!(response.status == Status::Success as i8);
    return Ok(());
}

pub fn exchange_command_14b(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    flags: u16,
    timeout: u32,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    let raw_data = serialize_14b_command(flags, timeout, data);
    let response = send_and_get_command(port, Command::HfIso14443BCommand, &raw_data, true)?;

    assert!(response.status == Status::Success as i8);
    return Ok(response);
}

pub fn select_14b(
    port: &mut Box<dyn serialport::SerialPort>,
    disconnect: bool,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    // TODO: add more select types
    let flags = ISO14BCommand::CONNECT | ISO14BCommand::CLEARTRACE | ISO14BCommand::SELECT_STD;
    let response = exchange_command_14b(port, &vec![], flags.bits(), 0)?;

    if disconnect {
        switch_off_field_14b(port)?;
    }

    assert!(response.status == 0);
    return Ok(response);
}

pub fn exchange_apdu_14b(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    select: bool,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    if select {
        select_14b(port, false)?;
    }

    let flags = ISO14BCommand::APDU | ISO14BCommand::SET_TIMEOUT;
    // this magic number is from pm3 client :D
    let response = exchange_command_14b(port, data, flags.bits(), 420000)?;

    assert!(response.status == Status::Success as i8);
    return Ok(response);
}
