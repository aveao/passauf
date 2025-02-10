use super::comms::{open_serial_comms, send_and_get_command, send_command};
use super::helpers::check_response_status;
use super::types::{Command, UnexpectedResponse};

const SUPPORTED_CAPABILITIES_VERSION: u8 = 6;

pub fn connect(path: &str) -> Result<Box<dyn serialport::SerialPort>, Box<dyn std::error::Error>> {
    // connect to the proxmark
    let mut port = open_serial_comms(&path)?;

    ping(&mut port)?;
    check_capabilities(&mut port)?;

    return Ok(port);
}

pub fn ping(port: &mut Box<dyn serialport::SerialPort>) -> Result<(), Box<dyn std::error::Error>> {
    let mut data: Vec<u8> = vec![0; 32];
    for i in 0..data.len() {
        data[i] = (i & 0xFF) as u8;
    }

    let response = send_and_get_command(port, Command::Ping, &data, true)?;
    check_response_status(response.status)?;
    if response.data != data {
        return Err(Box::new(UnexpectedResponse {
            additional_text: format!(
                "Ping response ({:02x?}) does not match sent value ({:02x?}).",
                &response.data, &data
            ),
        }));
    }
    return Ok(());
}

pub fn check_capabilities(
    port: &mut Box<dyn serialport::SerialPort>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = send_and_get_command(port, Command::Capabilities, &vec![], true)?;

    check_response_status(response.status)?;
    if response.data[0] != SUPPORTED_CAPABILITIES_VERSION {
        return Err(Box::new(UnexpectedResponse {
            additional_text: format!(
                "Supported capabilities ({}) does not match our supported version ({}).",
                response.data[0], SUPPORTED_CAPABILITIES_VERSION
            ),
        }));
    }
    return Ok(());
}

pub fn quit_session(
    port: &mut Box<dyn serialport::SerialPort>,
) -> Result<(), Box<dyn std::error::Error>> {
    send_command(port, Command::QuitSession, &vec![], true)?;
    return Ok(());
}

pub fn hf_drop_field(
    port: &mut Box<dyn serialport::SerialPort>,
) -> Result<(), Box<dyn std::error::Error>> {
    send_command(port, Command::HfDropfield, &vec![], true)?;
    return Ok(());
}
