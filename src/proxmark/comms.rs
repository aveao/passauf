use super::helpers::{merge_len_and_ng, split_len_and_ng};
use super::types::{
    Command, PM3PacketCommandInternal, PM3PacketResponseMIXInternal, PM3PacketResponseNG,
    PM3PacketResponseNGInternal,
};
use bincode;
use core::mem;
use log::{debug, trace, warn};
use serialport;
use std::str;
use std::time::Duration;

const CMD_MAX_DATA_SIZE: usize = 512;
const CMD_MAX_FRAME_SIZE: usize = 544;
const PM3_BAUD: u32 = 115_200;
const COMMANDNG_PREAMBLE_MAGIC: u32 = 0x61334d50; // PM3a
const RESPONSENG_PREAMBLE_MAGIC: u32 = 0x62334d50; // PM3b
const COMMANDNG_POSTAMBLE_MAGIC: u16 = 0x3361; // a3
const RESPONSENG_POSTAMBLE_MAGIC: u16 = 0x3362; // b3

pub fn open_serial_comms(
    path: &str,
) -> Result<Box<dyn serialport::SerialPort>, Box<dyn std::error::Error>> {
    // connect to the proxmark
    let port = serialport::new(path, PM3_BAUD)
        .timeout(Duration::from_millis(2000))
        .open()?;

    return Ok(port);
}

pub fn clear_input_buffer(
    port: &mut Box<dyn serialport::SerialPort>,
) -> Result<(), Box<dyn std::error::Error>> {
    return Ok(port.clear(serialport::ClearBuffer::Input)?);
}

pub fn send_and_get_command(
    port: &mut Box<dyn serialport::SerialPort>,
    cmd: Command,
    data: &Vec<u8>,
    ng: bool,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    send_command(port, cmd, data, ng)?;
    let response = get_response(port, cmd)?;

    if response.cmd == Command::DebugPrintString as u16 {
        warn!("{}", str::from_utf8(&response.data).unwrap());
    }

    let expected_command = (if ng { cmd } else { Command::Ack }) as u16;
    assert!(response.cmd == expected_command);

    return Ok(response);
}

pub fn send_command(
    port: &mut Box<dyn serialport::SerialPort>,
    cmd: Command,
    data: &Vec<u8>,
    ng: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure that we never send a message that's too long
    assert!(data.len() <= CMD_MAX_DATA_SIZE);

    let command = PM3PacketCommandInternal {
        cmd: cmd as u16,
        length_and_ng: merge_len_and_ng(data.len() as u16, ng),
        magic: COMMANDNG_PREAMBLE_MAGIC,
    };
    debug!("> command: {:x?} data: {:02x?}", command, data);
    let partly_encoded_command = bincode::serialize(&command)?;
    let postamble_vec = COMMANDNG_POSTAMBLE_MAGIC.to_le_bytes().to_vec();
    let serial_buf = vec![partly_encoded_command, data.clone(), postamble_vec].concat();

    trace!("> command (b): {:02x?}", serial_buf);

    clear_input_buffer(port)?;
    port.write(serial_buf.as_slice())?;
    return Ok(());
}

fn get_response(
    port: &mut Box<dyn serialport::SerialPort>,
    sent_cmd: Command,
) -> Result<PM3PacketResponseNG, Box<dyn std::error::Error>> {
    // TODO: handle CMD_WTX
    // TODO: handle things better in case there's multiple queued responses
    let data_offset = mem::size_of::<PM3PacketResponseNGInternal>();
    let mut data_length: u16 = 0;
    let mut ng = false;

    let mut serial_buf: Vec<u8> = vec![0; CMD_MAX_FRAME_SIZE];
    let mut total_read: usize = 0;
    let mut expected_length: usize = 1;
    while total_read < expected_length {
        let read_size = port.read(&mut serial_buf[total_read..])?;
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
        trace!("Total read: {:?}", &total_read);
    }
    trace!(
        "< response (b, {:?}): {:02x?}",
        total_read,
        &serial_buf[0..total_read]
    );

    // parse arg0/1/2 or not based on if we're on a NG command
    let response = if ng {
        map_ng_to_packet_response(serial_buf, data_length, sent_cmd)
    } else {
        map_mix_to_packet_response(serial_buf, data_length, sent_cmd)
    };

    debug!("< response: {:02x?}", response);

    return Ok(response);
}

fn map_ng_to_packet_response(
    serial_buf: Vec<u8>,
    data_length: u16,
    sent_cmd: Command,
) -> PM3PacketResponseNG {
    let mut data_length = data_length;
    let mut data_offset = mem::size_of::<PM3PacketResponseNGInternal>();
    let partial_response: PM3PacketResponseNGInternal = bincode::deserialize(&serial_buf).unwrap();
    assert!(partial_response.magic == RESPONSENG_PREAMBLE_MAGIC);

    trace!("< partial_response: {:02x?}", partial_response);

    // This is only here (not in MIX) because 14b is an NG command only.
    if sent_cmd == Command::HfIso14443BCommand {
        // response_byte (u8) + datalen (u16 LE)
        data_offset += 3;
        data_length -= 3;
    }

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

fn map_mix_to_packet_response(
    serial_buf: Vec<u8>,
    data_length: u16,
    sent_cmd: Command,
) -> PM3PacketResponseNG {
    let data_offset = mem::size_of::<PM3PacketResponseMIXInternal>();
    let partial_response: PM3PacketResponseMIXInternal = bincode::deserialize(&serial_buf).unwrap();
    assert!(partial_response.magic == RESPONSENG_PREAMBLE_MAGIC);

    trace!("< partial_response: {:02x?}", partial_response);

    // - 24 here as 3x u64s for the args
    let actual_data_length: u16 = match sent_cmd {
        Command::HfIso14443AReader => partial_response.arg0 as u16,
        _ => data_length - 24,
    };

    // - 24 here as 3x u64s for the args
    let data_field_end = data_offset + data_length as usize - 24 as usize;
    let actual_data_end = data_offset + actual_data_length as usize;
    let data = serial_buf[data_offset..actual_data_end].to_vec();
    let crc = u16::from_le_bytes(
        serial_buf[data_field_end..data_field_end + 2]
            .try_into()
            .unwrap(),
    );
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
