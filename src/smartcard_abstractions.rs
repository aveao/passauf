#[cfg(feature = "proxmark")]
use serialport::SerialPort;
use simplelog::{info, warn};
use std::{fmt, str::FromStr};
use strum::IntoStaticStr;

use crate::{proxmark, types};

#[derive(Debug, Clone, IntoStaticStr)]
pub enum ReaderInterface {
    Proxmark,
    PCSC,
}

impl fmt::Display for ReaderInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReaderInterface::Proxmark => write!(f, "proxmark"),
            ReaderInterface::PCSC => write!(f, "pcsc"),
        }
    }
}

impl FromStr for ReaderInterface {
    type Err = types::ParseError;
    fn from_str(name: &str) -> Result<ReaderInterface, Self::Err> {
        match name {
            "proxmark" => Ok(ReaderInterface::Proxmark),
            "pcsc" => Ok(ReaderInterface::PCSC),
            _ => Err(types::ParseError {}),
        }
    }
}

impl ReaderInterface {
    pub fn connect<'a>(
        &self,
        path: &'a Option<String>,
    ) -> Option<Box<impl InterfaceDevice + use<'a>>> {
        match self {
            ReaderInterface::Proxmark => {
                let proxmark_interface = ProxmarkInterface::connect(path.as_ref()).unwrap();
                return Some(Box::new(proxmark_interface));
            }
            _ => {
                return None;
            }
        };
    }
}

#[allow(drop_bounds, dead_code)]
pub trait Smartcard: Drop {
    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>>;
    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>>;
}

#[allow(drop_bounds)]
pub trait InterfaceDevice: Drop {
    fn connect(path: Option<&String>) -> Option<impl InterfaceDevice>;
    fn select<'a>(&'a mut self) -> Option<Box<dyn Smartcard + 'a>>;
}

#[cfg(feature = "proxmark")]
pub struct Proxmark14ASmartcard<'a> {
    interface: &'a mut ProxmarkInterface,
}

#[cfg(feature = "proxmark")]
pub struct Proxmark14BSmartcard<'a> {
    interface: &'a mut ProxmarkInterface,
}

#[cfg(feature = "proxmark")]
pub struct ProxmarkInterface {
    pub(crate) serial_port: Box<dyn SerialPort>,
}

#[cfg(feature = "proxmark")]
impl Drop for ProxmarkInterface {
    fn drop(&mut self) {
        let _ = proxmark::quit_session(&mut self.serial_port);
    }
}

#[cfg(feature = "proxmark")]
impl InterfaceDevice for ProxmarkInterface {
    fn connect(input_path: Option<&String>) -> Option<impl InterfaceDevice> {
        // If no path was supplied, try to find it.
        let path = match input_path {
            Some(data) => data,
            None => &proxmark::find_proxmark_serial_port()?,
        };

        info!("Connecting to proxmark on {}...", path);
        let port = proxmark::connect(path).ok()?;
        return Some(ProxmarkInterface { serial_port: port });
    }

    fn select<'a>(&'a mut self) -> Option<Box<dyn Smartcard + 'a>> {
        // First drop the field, useful in case we're stuck on something.
        let _ = proxmark::hf_drop_field(&mut self.serial_port);

        // Select on 14A
        match proxmark::select_14a(&mut self.serial_port, false) {
            Ok(result) => {
                match result {
                    2 => {
                        info!("Got no ATR (Answer To Reset) while selecting, we're not handling this currently, will continue but rest of code may fail.")
                    }
                    3 => {
                        info!("Got a proprietary anticollision while selecting, will continue but rest of code may fail.")
                    }
                    _ => {}
                }
                return Some(Box::new(Proxmark14ASmartcard { interface: self }));
            }
            Err(_) => {
                warn!("Selecting on ISO/IEC 14443 Modulation A failed, trying B.")
            }
        }
        // Select on 14B
        match proxmark::select_14b(&mut self.serial_port, false) {
            Ok(_) => {
                return Some(Box::new(Proxmark14BSmartcard { interface: self }));
            }
            Err(_) => {
                warn!("Selecting on ISO/IEC 14443 Modulation B failed.")
            }
        }
        return None;
    }
}

#[cfg(feature = "proxmark")]
impl Drop for Proxmark14ASmartcard<'_> {
    fn drop(&mut self) {
        let _ = proxmark::hf_drop_field(&mut self.interface.serial_port);
    }
}

#[cfg(feature = "proxmark")]
impl Smartcard for Proxmark14ASmartcard<'_> {
    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_command_14a(&mut self.interface.serial_port, data, 0).ok()?;
        return Some(response.data);
    }

    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_apdu_14a(&mut self.interface.serial_port, data, false).ok()?;
        return Some(response.data);
    }
}

#[cfg(feature = "proxmark")]
impl Drop for Proxmark14BSmartcard<'_> {
    fn drop(&mut self) {
        let _ = proxmark::switch_off_field_14b(&mut self.interface.serial_port);
        let _ = proxmark::hf_drop_field(&mut self.interface.serial_port);
    }
}

#[cfg(feature = "proxmark")]
impl Smartcard for Proxmark14BSmartcard<'_> {
    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_command_14b(&mut self.interface.serial_port, data, 0, 0).ok()?;
        return Some(response.data);
    }

    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_apdu_14b(&mut self.interface.serial_port, data, false).ok()?;
        return Some(response.data);
    }
}
