#![no_main]

pico_sdk::entrypoint!(main);
use pico_sdk::io::{commit, read_as};
use zktls_att_verification::verification_data::VerifyingDataOpt;

// load verifying data
fn get_verifying_data(json_content: String) -> VerifyingDataOpt {
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();
    verifying_data
}

pub fn main() {
    let verifying_key: String = read_as();
    let verifying_raw_data: String = read_as();
    let verifying_data = get_verifying_data(verifying_raw_data);

    let _ = verifying_data.verify(&verifying_key).is_ok();

    commit(&verifying_key);
    commit(&verifying_data.get_records());
}
