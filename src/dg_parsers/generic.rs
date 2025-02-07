use crate::icao9303;
use crate::types;
use simplelog::info;

pub fn parser(
    data: Vec<u8>,
    _data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    if print_data {
        info!("Read file ({:?}b): {:x?}", data.len(), data);
    }
    return None;
}
