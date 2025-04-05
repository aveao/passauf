#[cfg(feature = "pcsc")]
use pcsc::{Context, Scope};
#[cfg(feature = "proxmark")]
use serialport::SerialPort;
use simplelog::{debug, error, info, warn};
use std::{ffi::CString, fmt, str::FromStr};
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
                #[cfg(feature = "proxmark")]
                let proxmark_interface = ProxmarkInterface::connect(path.as_ref()).unwrap();
                #[cfg(feature = "proxmark")]
                return Some(Box::new(proxmark_interface));
                return None;
            }
            _ => {
                #[cfg(feature = "pcsc")]
                let pcsc_interface = PCSCInterface::connect(path.as_ref()).unwrap();
                #[cfg(feature = "pcsc")]
                return Some(Box::new(pcsc_interface));
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
        let response_without_hash = response.data[0..response.data.len() - 2].to_vec();
        return Some(response_without_hash);
    }

    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_apdu_14a(&mut self.interface.serial_port, data, false).ok()?;
        let response_without_hash = response.data[0..response.data.len() - 2].to_vec();
        return Some(response_without_hash);
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
        let response_without_hash = response.data[0..response.data.len() - 2].to_vec();
        return Some(response_without_hash);
    }

    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        let response =
            proxmark::exchange_apdu_14b(&mut self.interface.serial_port, data, false).ok()?;
        let response_without_hash = response.data[0..response.data.len() - 2].to_vec();
        return Some(response_without_hash);
    }
}

#[cfg(feature = "pcsc")]
pub struct PCSCInterface {
    pub(crate) context: Box<Context>,
    pub(crate) reader_name: String,
}

#[cfg(feature = "pcsc")]
impl Drop for PCSCInterface {
    fn drop(&mut self) {
        let _ = self.context.cancel();
    }
}

#[cfg(feature = "pcsc")]
impl InterfaceDevice for PCSCInterface {
    fn connect(input_path: Option<&String>) -> Option<impl InterfaceDevice> {
        // Establish a PC/SC context.
        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => {
                error!("Failed to establish context: {}", err);
                return None;
            }
        };

        // List available readers.
        let mut readers_buf = [0; 2048];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                error!("Failed to list readers: {}", err);
                return None;
            }
        };
        let mut reader_to_use: String = match input_path {
            Some(path) => path.to_string(),
            None => "".to_string(),
        };
        let mut desired_reader_found = false;
        for reader in readers {
            let reader_name = reader.to_str().ok()?.to_string();
            if input_path.is_none() {
                info!("PCSC smartcard reader found: \"{}\"", &reader_name);
            } else if input_path? == &reader_name {
                desired_reader_found = true;
            }
            if reader_to_use.len() == 0 {
                reader_to_use = reader_name.clone();
                desired_reader_found = true;
            }
        }
        if input_path.is_none() {
            info!("(Hint: You can select a specific reader with --reader)");
        }
        if desired_reader_found {
            info!("Using PCSC reader: {:?}", reader_to_use);
            return Some(PCSCInterface {
                context: Box::new(ctx),
                reader_name: reader_to_use,
            });
        }
        warn!("No suitable PCSC reader found.");
        return None;
    }

    fn select<'a>(&'a mut self) -> Option<Box<dyn Smartcard + 'a>> {
        match self.context.connect(
            &CString::new(self.reader_name.clone()).unwrap(),
            pcsc::ShareMode::Shared,
            pcsc::Protocols::ANY,
        ) {
            Ok(card) => {
                return Some(Box::new(PCSCSmartcard { card }));
            }
            Err(pcsc::Error::NoSmartcard) => {
                error!("A smartcard is not present in the reader.");
                return None;
            }
            Err(err) => {
                error!("Failed to connect to card: {}", err);
                return None;
            }
        };
    }
}

#[cfg(feature = "pcsc")]
pub struct PCSCSmartcard {
    card: pcsc::Card,
}

#[cfg(feature = "pcsc")]
impl Drop for PCSCSmartcard {
    fn drop(&mut self) {
        // Card implements Drop which automatically disconnects the card using Disposition::ResetCard.
        return;
    }
}

#[cfg(feature = "pcsc")]
impl Smartcard for PCSCSmartcard {
    fn exchange_apdu(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        debug!("Sending APDU: {:0x?}", data);
        let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
        let rapdu = match self.card.transmit(data, &mut rapdu_buf) {
            Ok(rapdu) => rapdu,
            Err(err) => {
                error!("Failed to transmit APDU command to card: {}", err);
                return None;
            }
        };
        debug!("Got RAPDU: {:0x?}", rapdu);

        return Some(rapdu.to_vec());
    }

    fn exchange_command(&mut self, data: &Vec<u8>) -> Option<Vec<u8>> {
        return self.exchange_apdu(data);
    }
}
