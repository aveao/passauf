use std::{fs, io, path::Path};

use crate::dg_parsers::helpers as dg_helpers;
use crate::icao9303;
use crate::types;
use simplelog::info;

pub fn parser(
    data: &Vec<u8>,
    data_group: &icao9303::DataGroup,
    print_data: bool,
) -> Option<types::ParsedDataGroup> {
    if print_data {
        dg_helpers::print_section_intro(data_group);
        info!("(No parser available for {})", data_group.name);
        dg_helpers::print_option_binary_element(&format!("Raw data ({}b)", data.len()), &Some(data));
    }
    return None;
}

pub fn dumper(
    file_data: &Vec<u8>,
    _parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<(), io::Error> {
    let mut file_path = base_path.join(base_filename);
    file_path.set_extension("bin");

    // Create, write to and sync file.
    let mut f = fs::File::create(&file_path)?;
    io::Write::write_all(&mut f, &file_data)?;
    f.sync_all()?;

    info!("<magenta>Saved to {}</>", &file_path.to_string_lossy());
    return Ok(());
}
