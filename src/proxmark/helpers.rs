use super::CommandError;
use super::Status;

#[allow(unused_parens)] // < I think the parentheses here are useful.
pub(crate) fn merge_len_and_ng(len: u16, ng: bool) -> u16 {
    // Encode length and ng together (Length is 15 bits and ng is 1 bit.)
    let mut length_and_ng: u16 = len;
    // Not actually needed as length can only be < 512 but eh.
    length_and_ng &= 0b0111111111111111;
    if (ng) {
        length_and_ng |= (1 << 15);
    }
    return length_and_ng;
}

pub(crate) fn split_len_and_ng(length_and_ng: u16) -> (u16, bool) {
    // Split length and ng (Length is 15 bits and ng is 1 bit.)
    let length: u16 = length_and_ng & 0b0111111111111111;
    let ng: bool = (length_and_ng >> 15) == 1;
    return (length, ng);
}

pub fn convert_mix_args_to_ng(data: &Vec<u8>, arg0: u64, arg1: u64, arg2: u64) -> Vec<u8> {
    // Various commands don't use ng yet, and require their args to be packed alongside data
    return vec![
        arg0.to_le_bytes().to_vec(),
        arg1.to_le_bytes().to_vec(),
        arg2.to_le_bytes().to_vec(),
        data.clone(),
    ]
    .concat();
}

pub fn check_response_status<'a>(response_status: i8) -> Result<(), CommandError> {
    if response_status == Status::Success as i8 {
        return Ok(());
    }
    return Err(CommandError {
        error_code: response_status,
        error_name: {
            let status = Status::from_repr(response_status);
            if status.is_some() {
                let status_str: &'static str = status.unwrap().into();
                Some(status_str.into())
            } else {
                None
            }
        },
    });
}
