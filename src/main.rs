mod iso7816;
mod proxmark;

fn main() {
    // TODO: make this adjustable
    let mut port = proxmark::connect("/dev/ttyACM0");

    println!("Selecting EF_CardAccess");
    let command = iso7816::apdu_select_file_by_ef(&iso7816::EMRTD_EF_CARDACCESS.to_vec());
    let response = proxmark::pm3_exchange_apdu_14a(&mut port, &command, true);
    iso7816::check_status_code(&response.data);

    println!("Reading EF_CardAccess");
    let command = iso7816::apdu_read_binary(0, 128);
    proxmark::pm3_exchange_apdu_14a(&mut port, &command, false);

    println!("Selecting MRTD applet");
    let command = iso7816::apdu_select_file_by_name(&iso7816::EMRTD_AID_MRTD.to_vec());
    proxmark::pm3_exchange_apdu_14a(&mut port, &command, false);

    proxmark::pm3_quit_session(&mut port);
    drop(port);
}
