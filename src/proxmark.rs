use bincode;
use bitflags::bitflags;
use core::mem;
use serde::{Deserialize, Serialize};
use serialport;
use std::time::Duration;
use std::str;

static PM3_CMD_MAX_DATA_SIZE: usize = 512;
static PM3_CMD_MAX_FRAME_SIZE: usize = 544;
static PM3_BAUD: u32 = 115_200;
static SUPPORTED_CAPABILITIES_VERSION: u8 = 6;
// TODO: https://github.com/RfidResearchGroup/proxmark3/blob/e4430037336b86f0aa7a08d23b67efcab662c829/include/pm3_cmd.h#L877
pub static STATUS_SUCCESS: i8 = 0;
// more at: https://github.com/RfidResearchGroup/proxmark3/blob/e4430037336b86f0aa7a08d23b67efcab662c829/include/pm3_cmd.h#L419
pub static CMD_DEBUG_PRINT_STRING: u16 = 0x0100;
pub static CMD_PING: u16 = 0x0109;
pub static CMD_CAPABILITIES: u16 = 0x0112;
pub static CMD_QUIT_SESSION: u16 = 0x0113;
pub static CMD_WTX: u16 = 0x0116; // Wait time extension
pub static CMD_ACK: u16 = 0x00ff;
pub static CMD_HF_DROPFIELD: u16 = 0x0430;
pub const CMD_HF_ISO14443A_READER: u16 = 0x0385;
static COMMANDNG_PREAMBLE_MAGIC: u32 = 0x61334d50; // PM3a
static RESPONSENG_PREAMBLE_MAGIC: u32 = 0x62334d50; // PM3b
static COMMANDNG_POSTAMBLE_MAGIC: u16 = 0x3361; // a3
static RESPONSENG_POSTAMBLE_MAGIC: u16 = 0x3362; // b3

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

#[derive(Serialize, Debug)]
struct PM3PacketCommandInternal {
    magic: u32,
    length_and_ng: u16, // length is 15b, ng is 1b
    cmd: u16,
}

#[derive(Deserialize, Debug)]
#[repr(packed)] // If disabling this, hardcode data_offset to 10.
struct PM3PacketResponseMIXInternal {
    magic: u32,
    length_and_ng: u16, // length is 15b, ng is 1b
    status: i8,
    reason: i8,
    cmd: u16,
    arg0: u64,
    arg1: u64,
    arg2: u64,
}

#[derive(Deserialize, Debug)]
#[repr(packed)] // If disabling this, hardcode data_offset to 10.
struct PM3PacketResponseNGInternal {
    magic: u32,
    length_and_ng: u16, // length is 15b, ng is 1b
    status: i8,
    reason: i8,
    cmd: u16,
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

pub fn connect(path: &str) -> Box<dyn serialport::SerialPort> {
    // connect to the proxmark
    let mut port = open_serial_comms(&path);

    pm3_ping(&mut port);
    pm3_check_capabilities(&mut port);

    return port;
}

pub fn open_serial_comms(path: &str) -> Box<dyn serialport::SerialPort> {
    // connect to the proxmark
    let port = serialport::new(path, PM3_BAUD)
        .timeout(Duration::from_millis(2000))
        .open()
        .expect("Failed to open port");

    return port;
}

pub fn clear_input_buffer(port: &mut Box<dyn serialport::SerialPort>) {
    let _ = port.clear(serialport::ClearBuffer::Input);
}

#[allow(unused_parens)] // < I think the parentheses here are useful.
fn merge_len_and_ng(len: u16, ng: bool) -> u16 {
    // Encode length and ng together (Length is 15 bits and ng is 1 bit.)
    let mut length_and_ng: u16 = len;
    // Not actually needed as length can only be < 512 but eh.
    length_and_ng &= 0b0111111111111111;
    if (ng) {
        length_and_ng |= (1 << 15);
    }
    return length_and_ng;
}

fn split_len_and_ng(length_and_ng: u16) -> (u16, bool) {
    // Split length and ng (Length is 15 bits and ng is 1 bit.)
    let length: u16 = length_and_ng & 0b0111111111111111;
    let ng: bool = (length_and_ng >> 15) == 1;
    return (length, ng);
}

pub fn send_and_get_command(
    port: &mut Box<dyn serialport::SerialPort>,
    cmd: u16,
    data: &Vec<u8>,
    ng: bool,
) -> PM3PacketResponseNG {
    send_command(port, cmd, data, ng);
    let response = get_response(port, cmd);

    if response.cmd == CMD_DEBUG_PRINT_STRING {
        println!("{}", str::from_utf8(&response.data).unwrap());
    }

    let expected_command = if ng { cmd } else { CMD_ACK };
    assert!(response.cmd == expected_command);

    return response;
}

pub fn send_command(
    port: &mut Box<dyn serialport::SerialPort>,
    cmd: u16,
    data: &Vec<u8>,
    ng: bool,
) {
    let command = PM3PacketCommandInternal {
        cmd: cmd,
        length_and_ng: merge_len_and_ng(data.len() as u16, ng),
        magic: COMMANDNG_PREAMBLE_MAGIC,
    };
    println!("> command: {:x?} data: {:x?}", command, data);
    let partly_encoded_command = bincode::serialize(&command).unwrap();
    let postamble_vec = COMMANDNG_POSTAMBLE_MAGIC.to_le_bytes().to_vec();
    let serial_buf = vec![partly_encoded_command, data.clone(), postamble_vec].concat();

    // println!("> command (b): {:x?}", serial_buf);

    clear_input_buffer(port);
    port.write(serial_buf.as_slice()).expect("Write failed!");
}

fn get_response(port: &mut Box<dyn serialport::SerialPort>, sent_cmd: u16) -> PM3PacketResponseNG {
    // TODO: handle CMD_WTX
    // TODO: handle things better in case there's multiple queued responses
    let data_offset = mem::size_of::<PM3PacketResponseNGInternal>();
    let mut data_length: u16 = 0;
    let mut ng = false;

    let mut serial_buf: Vec<u8> = vec![0; PM3_CMD_MAX_FRAME_SIZE];
    let mut total_read: usize = 0;
    let mut expected_length: usize = 1;
    while total_read < expected_length {
        let read_size = port
            .read(&mut serial_buf[total_read..])
            .expect("Found no data!");
        if total_read == 0 {
            // assert that we're indeed at the start of the response
            assert!(serial_buf[0..4] == RESPONSENG_PREAMBLE_MAGIC.to_le_bytes().to_vec());

            // split len and ng, as they're 15 and 1 bit respectively.
            let length_and_ng = u16::from_le_bytes(serial_buf[4..6].try_into().unwrap());
            (data_length, ng) = split_len_and_ng(length_and_ng);

            // calculate the expected length so that we can read the entire response.
            // (2 bytes for the crc)
            expected_length = data_offset + (data_length as usize) + 2;
        }
        total_read += read_size;
        // println!("{:?}", &total_read);
    }
    // println!(
    //     "< response (b, {:?}): {:x?}",
    //     total_read,
    //     &serial_buf[0..total_read]
    // );

    // parse arg0/1/2 or not based on if we're on a NG command
    let response = if ng {
        map_ng_to_packet_response(serial_buf, data_length, sent_cmd)
    } else {
        map_mix_to_packet_response(serial_buf, data_length, sent_cmd)
    };

    println!("< response: {:x?}", response);

    return response;
}

fn map_ng_to_packet_response(serial_buf: Vec<u8>, data_length: u16, sent_cmd: u16) -> PM3PacketResponseNG {
    let data_offset = mem::size_of::<PM3PacketResponseNGInternal>();
    let partial_response: PM3PacketResponseNGInternal = bincode::deserialize(&serial_buf).unwrap();
    assert!(partial_response.magic == RESPONSENG_PREAMBLE_MAGIC);

    // println!("< partial_response: {:x?}", partial_response);

    let data_end = data_offset + data_length as usize;
    let data = serial_buf[data_offset..data_end].to_vec();
    let crc = u16::from_le_bytes(serial_buf[data_end..data_end + 2].try_into().unwrap());
    assert!(crc == RESPONSENG_POSTAMBLE_MAGIC);

    return PM3PacketResponseNG {
        length: data_length,
        ng: true,
        status: partial_response.status,
        reason: partial_response.reason,
        cmd: partial_response.cmd,
        data: data,
        arg0: 0,
        arg1: 0,
        arg2: 0,
    };
}

fn map_mix_to_packet_response(serial_buf: Vec<u8>, data_length: u16, sent_cmd: u16) -> PM3PacketResponseNG {
    let data_offset = mem::size_of::<PM3PacketResponseMIXInternal>();
    let partial_response: PM3PacketResponseMIXInternal = bincode::deserialize(&serial_buf).unwrap();
    assert!(partial_response.magic == RESPONSENG_PREAMBLE_MAGIC);

    // println!("< partial_response: {:x?}", partial_response);

    let actual_data_length: u16 = match sent_cmd {
        CMD_HF_ISO14443A_READER => partial_response.arg0 as u16,
        _ => data_length - 24,
    };

    // -24 here as 3x u64s for the args
    let data_end = data_offset + data_length as usize - 24 as usize;
    let actual_data_end = data_offset + actual_data_length as usize;
    let data = serial_buf[data_offset..actual_data_end].to_vec();
    let crc = u16::from_le_bytes(serial_buf[data_end..data_end + 2].try_into().unwrap());
    assert!(crc == RESPONSENG_POSTAMBLE_MAGIC);

    return PM3PacketResponseNG {
        length: data_length,
        ng: false,
        status: partial_response.status,
        reason: partial_response.reason,
        arg0: partial_response.arg0,
        arg1: partial_response.arg1,
        arg2: partial_response.arg2,
        cmd: partial_response.cmd,
        data: data,
    };
}

pub fn pm3_ping(port: &mut Box<dyn serialport::SerialPort>) {
    let mut data: Vec<u8> = vec![0; 32];
    for i in 0..data.len() {
        data[i] = (i & 0xFF) as u8;
    }

    let response = send_and_get_command(port, CMD_PING, &data, true);
    assert!(response.status == STATUS_SUCCESS);
    assert!(response.data == data);
}

pub fn pm3_check_capabilities(port: &mut Box<dyn serialport::SerialPort>) {
    let response = send_and_get_command(port, CMD_CAPABILITIES, &vec![], true);

    assert!(response.status == STATUS_SUCCESS);
    assert!(response.data[0] == SUPPORTED_CAPABILITIES_VERSION);
}

pub fn pm3_quit_session(port: &mut Box<dyn serialport::SerialPort>) {
    send_command(port, CMD_HF_DROPFIELD, &vec![], true);
    send_command(port, CMD_QUIT_SESSION, &vec![], true);
}

fn convert_mix_to_ng(data: &Vec<u8>, arg0: u64, arg1: u64, arg2: u64) -> Vec<u8> {
    // Various commands don't use ng yet, and require their args to be packed alongside data
    return vec![
        arg0.to_le_bytes().to_vec(),
        arg1.to_le_bytes().to_vec(),
        arg2.to_le_bytes().to_vec(),
        data.clone(),
    ]
    .concat();
}

pub fn pm3_exchange_14a_command(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    flags: u16,
) -> PM3PacketResponseNG {
    // We're expanding data here to account for it being the old format (not ng).
    let full_data = convert_mix_to_ng(data, u64::from(flags), (data.len() as u64 & 0x1FF), 0);
    let response = send_and_get_command(port, CMD_HF_ISO14443A_READER, &full_data, false);

    assert!(response.status == STATUS_SUCCESS);
    return response;
}

pub fn pm3_hf_drop_field(port: &mut Box<dyn serialport::SerialPort>) {
    send_command(port, CMD_HF_DROPFIELD, &vec![], true);
}

pub fn pm3_14a_select(port: &mut Box<dyn serialport::SerialPort>, disconnect: bool) {
    let flags = ISO14ACommand::CONNECT | ISO14ACommand::NO_DISCONNECT;
    let response = pm3_exchange_14a_command(port, &vec![], flags.bits());

    if disconnect {
        pm3_hf_drop_field(port);
    }

    // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
    // TODO: no ATS is not currently implemented.
    assert!(response.arg0 == 1);
}

pub fn pm3_exchange_apdu_14a(
    port: &mut Box<dyn serialport::SerialPort>,
    data: &Vec<u8>,
    select: bool,
) -> PM3PacketResponseNG {
    if select {
        pm3_14a_select(port, false);
    }

    let flags = ISO14ACommand::APDU | ISO14ACommand::NO_DISCONNECT;
    let response = pm3_exchange_14a_command(port, data, flags.bits());

    assert!(response.status == STATUS_SUCCESS);
    return response;
}
