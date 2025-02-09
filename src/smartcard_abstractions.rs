use serialport::SerialPort;

use crate::proxmark;

#[allow(drop_bounds, dead_code)]
pub trait Smartcard: Drop {
    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>>;
    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>>;
}

#[allow(drop_bounds)]
pub trait InterfaceDevice: Drop {
    fn connect(path: Option<&String>) -> impl InterfaceDevice;
    fn select(&mut self) -> Option<impl Smartcard>;
}

pub struct Proxmark14ASmartcard<'a> {
    interface: &'a mut ProxmarkInterface,
}

pub struct ProxmarkInterface {
    pub serial_port: Box<dyn SerialPort>,
}

impl Drop for ProxmarkInterface {
    fn drop(&mut self) {
        let _ = proxmark::quit_session(&mut self.serial_port);
    }
}

impl InterfaceDevice for ProxmarkInterface {
    fn connect(path: Option<&String>) -> impl InterfaceDevice {
        let port = proxmark::connect(path.unwrap()).unwrap();
        return ProxmarkInterface { serial_port: port };
    }

    fn select(&mut self) -> Option<impl Smartcard> {
        // TODO: handle result properly, also add 14b
        proxmark::select_14a(&mut self.serial_port, false).ok()?;
        return Some(Proxmark14ASmartcard { interface: self });
    }
}

impl Drop for Proxmark14ASmartcard<'_> {
    fn drop(&mut self) {
        let _ = proxmark::hf_drop_field(&mut self.interface.serial_port);
    }
}

impl Smartcard for Proxmark14ASmartcard<'_> {
    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_command_14a(&mut self.interface.serial_port, data, 0).ok()?;
        // TODO: check proxmark error state here
        return Some(response.data);
    }

    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_apdu_14a(&mut self.interface.serial_port, data, false).ok()?;
        // TODO: check proxmark error state here
        return Some(response.data);
    }
}
