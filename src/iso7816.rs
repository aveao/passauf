pub static CMD_READ_BINARY: u8 = 0xB0;
pub static CMD_SELECT_FILE: u8 = 0xA4;
pub static CMD_GET_CHALLENGE: u8 = 0x84;
pub static CMD_EXTERNAL_AUTHENTICATION: u8 = 0x82;

pub static EMRTD_P1_SELECT_BY_EF: u8 = 0x02;
pub static EMRTD_P1_SELECT_BY_NAME: u8 = 0x04;
pub static EMRTD_P2_PROPRIETARY: u8 = 0x0C;

// https://github.com/RfidResearchGroup/proxmark3/blob/master/include/protocols.h#L502
pub static STATUS_OK: u16 = 0x9000;
pub static STATUS_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
pub static STATUS_APPLET_SELECT_FAILED: u16 = 0x6999;
pub static STATUS_FILE_NOT_FOUND: u16 = 0x6A82;

pub static EMRTD_AID_MRTD: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
pub static EMRTD_EF_CARDACCESS: [u8; 2] = [0x01, 0x1C];

fn apdu_get_field_len_vec(field: u16) -> Vec<u8> {
    let field_bytes = field.to_le_bytes();
    let field_len: Vec<u8> = match field {
        0 => vec![],
        1..256 => vec![field as u8],
        256.. => vec![0, field_bytes[0], field_bytes[1]],
    };
    return field_len;
}

pub fn check_status_code(data: &Vec<u8>) {
    let status_code = u16::from_be_bytes(data[0..2].try_into().unwrap());
    println!("{:?}", status_code);
    assert!(status_code == STATUS_OK);  // TODO: do this right
}

pub fn prepare_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &Vec<u8>,
    max_resp_len: u16,
) -> Vec<u8> {
    // https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit#APDU_message_command-response_pair
    let lc = apdu_get_field_len_vec(data.len() as u16);
    let le = apdu_get_field_len_vec(max_resp_len);

    let apdu = vec![vec![cla, ins, p1, p2], lc, data.clone(), le].concat();
    return apdu;
}

pub fn apdu_select_file_by_name(name: &Vec<u8>) -> Vec<u8> {
    return prepare_apdu(
        0,
        CMD_SELECT_FILE,
        EMRTD_P1_SELECT_BY_NAME,
        EMRTD_P2_PROPRIETARY,
        name,
        100,
    );
}

pub fn apdu_select_file_by_ef(file_id: &Vec<u8>) -> Vec<u8> {
    return prepare_apdu(
        0,
        CMD_SELECT_FILE,
        EMRTD_P1_SELECT_BY_EF,
        EMRTD_P2_PROPRIETARY,
        file_id,
        100,
    );
}

pub fn apdu_read_binary(offset: u16, bytes_to_read: u16) -> Vec<u8> {
    let offset_bytes = offset.to_le_bytes();
    return prepare_apdu(
        0,
        CMD_READ_BINARY,
        offset_bytes[0],
        offset_bytes[1],
        &vec![],
        bytes_to_read,
    );
}

pub fn apdu_get_challenge() -> Vec<u8> {
    return prepare_apdu(
        0,
        CMD_GET_CHALLENGE,
        0,
        0,
        &vec![],
        10,  // 8 + SW for rnd_ic
    );
}

pub fn apdu_external_authentication(data: &Vec<u8>) -> Vec<u8> {
    return prepare_apdu(
        0,
        CMD_EXTERNAL_AUTHENTICATION,
        0,
        0,
        data,
        40,
    );
}
