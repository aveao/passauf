use super::comms::{open_serial_comms, send_and_get_command, send_command};
use super::types::{Command, Status};

const SUPPORTED_CAPABILITIES_VERSION: u8 = 6;

pub fn connect(path: &str) -> Box<dyn serialport::SerialPort> {
    // connect to the proxmark
    let mut port = open_serial_comms(&path);

    ping(&mut port);
    check_capabilities(&mut port);

    return port;
}

pub fn ping(port: &mut Box<dyn serialport::SerialPort>) {
    let mut data: Vec<u8> = vec![0; 32];
    for i in 0..data.len() {
        data[i] = (i & 0xFF) as u8;
    }

    let response = send_and_get_command(port, Command::Ping, &data, true);
    assert!(response.status == Status::Success as i8);
    assert!(response.data == data);
}

pub fn check_capabilities(port: &mut Box<dyn serialport::SerialPort>) {
    let response = send_and_get_command(port, Command::Capabilities, &vec![], true);

    assert!(response.status == Status::Success as i8);
    assert!(response.data[0] == SUPPORTED_CAPABILITIES_VERSION);
}

pub fn quit_session(port: &mut Box<dyn serialport::SerialPort>) {
    send_command(port, Command::HfDropfield, &vec![], true);
    send_command(port, Command::QuitSession, &vec![], true);
}

pub fn hf_drop_field(port: &mut Box<dyn serialport::SerialPort>) {
    send_command(port, Command::HfDropfield, &vec![], true);
}
