use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[cfg(feature = "cli")]
use crate::dg_parsers::helpers as dg_helpers;
use crate::types;
use simplelog::info;

pub fn parser(
    #[cfg_attr(not(feature = "cli"), allow(unused_variables))] data: &Vec<u8>,
    #[cfg_attr(not(feature = "cli"), allow(unused_variables))] data_group: &types::DataGroup,
    #[cfg_attr(not(feature = "cli"), allow(unused_variables))] print_data: bool,
) -> Option<types::ParsedDataGroup> {
    #[cfg(feature = "cli")]
    if print_data {
        dg_helpers::print_section_intro(data_group);
        info!(
            "{:^pad_len$}",
            format!("<b>(No parser available for {})</>", data_group.name),
            // + 6 for bold
            pad_len = dg_helpers::SECTION_TITLE_PAD_TO_LEN + 6
        );
        dg_helpers::print_option_binary_element(
            &format!("Raw data ({}b)", data.len()),
            &Some(data),
        );
    }
    return None;
}

/// Write a file's raw contents out, returning where it landed.
///
/// Every dumper reports the paths it wrote so a caller that isn't watching the
/// log can still tell the user what it now has on disk.
pub fn dumper(
    file_data: &Vec<u8>,
    _parsed_data: &Option<types::ParsedDataGroup>,
    base_path: &Path,
    base_filename: &String,
) -> Result<Vec<PathBuf>, io::Error> {
    let mut file_path = base_path.join(base_filename);
    file_path.set_extension("bin");

    write_file(&file_path, file_data)?;

    info!("<magenta>Saved to {}</>", &file_path.to_string_lossy());
    return Ok(vec![file_path]);
}

/// Create, write to and sync a file.
pub(crate) fn write_file(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let mut f = fs::File::create(path)?;
    io::Write::write_all(&mut f, data)?;
    f.sync_all()?;
    return Ok(());
}
