#![crate_name = "sample"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

// #[macro_use]
// extern crate log;
// #[macro_use]
// extern crate serde_derive;
extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// mod attestation_report;
// mod ias;

use hex;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::*;
use std::io::{BufReader, BufWriter, Read, Write};
use std::string::String;
use std::{env, str, vec::Vec};
use std::{net::TcpStream, sync::Arc};
// use sgx_tseal::SgxSealedData;
// use sgx_types::marker::ContiguousMemory;
// use std::{
//     u32,
//     vec::Vec,
//     mem::size_of,
//     string::{
//         String,
//         ToString,
//     },
// };

// pub const U32_NUM_BYTES: usize = 4;
// pub const MEGA_BYTE: usize = 1_000_000;
// pub const SCRATCH_PAD_SIZE: usize = 1 * MEGA_BYTE;

// #[no_mangle]
// extern "C" {
//     pub fn save_to_db(
//         ret_val: *mut sgx_status_t,
//         key_pointer: *mut u8,
//         key_size: *const u32,
//         sealed_log_size: *const u32,
//         scratch_pad_pointer: *mut u8,
//     ) -> sgx_status_t;

//     pub fn get_from_db(
//         ret_val: *mut sgx_status_t,
//         key_pointer: *mut u8,
//         key_size: *const u32,
//         value_pointer: *mut u8,
//         value_size: *const u32,
//     ) -> sgx_status_t;
// }

// #[derive(Serialize, Deserialize, Clone, Default, Debug)]
// struct DatabaseKeyAndValue {
//     key: Bytes,
//     value: Bytes,
// }

// impl DatabaseKeyAndValue {
//     pub fn new(key: Bytes, value: Bytes) -> Self {
//         DatabaseKeyAndValue { key, value }
//     }
// }

// fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(
//     sealed_data: &SgxSealedData<[T]>,
//     sealed_log: * mut u8,
//     sealed_log_size: u32
// ) -> Option<* mut sgx_sealed_data_t> {
//     unsafe {
//         sealed_data
//             .to_raw_sealed_data_t(
//                 sealed_log as * mut sgx_sealed_data_t,
//                 sealed_log_size
//             )
//     }
// }

// fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(
//     sealed_log: * mut u8,
//     sealed_log_size: u32
// ) -> Option<SgxSealedData<'a, [T]>> {
//     unsafe {
//         SgxSealedData::<[T]>::from_raw_sealed_data_t(
//             sealed_log as * mut sgx_sealed_data_t,
//             sealed_log_size
//         )
//     }
// }

// fn get_length_of_data_in_scratch_pad(scratch_pad: &Bytes) -> usize {
//     let mut length_of_data_arr = [0u8; U32_NUM_BYTES];
//     let bytes = &scratch_pad[..U32_NUM_BYTES];
//     length_of_data_arr.copy_from_slice(bytes);
//     u32::from_le_bytes(length_of_data_arr) as usize
// }

// fn get_data_from_scratch_pad(scratch_pad: &Bytes) -> Bytes {
//     let length_of_data = get_length_of_data_in_scratch_pad(scratch_pad);
//     scratch_pad[U32_NUM_BYTES..U32_NUM_BYTES + length_of_data].to_vec()
// }

// fn get_item_from_db(
//     mut key: Bytes,
//     scratch_pad: &mut Bytes,
// ) -> Result<sgx_status_t, String> {
//     info!("✔ [Enc] Getting item from external db...");
//     let key_pointer: *mut u8 = &mut key[0];
//     let enclave_scratch_pad_pointer: *mut u8 = &mut scratch_pad[0];
//     unsafe {
//         get_from_db(
//             &mut sgx_status_t::SGX_SUCCESS,
//             key_pointer,
//             key.len() as *const u32,
//             enclave_scratch_pad_pointer,
//             SCRATCH_PAD_SIZE as *const u32,
//         )
//     };
//     let mut data = get_data_from_scratch_pad(&scratch_pad);
//     info!("✔ [Enc] External data written to enclave's scratch pad!");
//     trace!("✔ [Enc] Retreived data length: {:?}", data.len());
//     let data_pointer: *mut u8 = &mut data[0];
//     let maybe_sealed_data = from_sealed_log_for_slice::<u8>(
//         data_pointer,
//         data.len() as u32
//     );
//     let sealed_data = match maybe_sealed_data {
//         Some(sealed_data) => sealed_data,
//         None => return Err(
//             sgx_status_t::SGX_ERROR_INVALID_PARAMETER.to_string()
//         )
//     };
//     trace!(
//         "✔ [Enc] Payload: {:?}",
//         sealed_data.get_payload_size()
//     );
//     trace!(
//         "✔ [Enc] Encrypted text: {:?}",
//         sealed_data.get_encrypt_txt()
//     );
//     trace!(
//         "✔ [Enc] Additional text: {:?}",
//         sealed_data.get_additional_txt()
//     );
//     let unsealed_data = match sealed_data.unseal_data() {
//         Ok(unsealed_data) => unsealed_data,
//         Err(e) => return Err(e.to_string())
//     };
//     let cbor_encoded_slice = unsealed_data.get_decrypt_txt();
//     let final_data: DatabaseKeyAndValue = serde_cbor::from_slice(
//         cbor_encoded_slice
//     ).unwrap();
//     //info!("✔ [Enc] Final unsealed data: {:?}", final_data);
//     info!("✔ [Enc] Final unsealed key: {:?}", final_data.key);
//     info!("✔ [Enc] Final unsealed value: {:?}", final_data.value);
//     Ok(sgx_status_t::SGX_SUCCESS)
// }

// fn seal_item_into_db(
//     mut key: Bytes,
//     value: Bytes,
//     scratch_pad_pointer: *mut u8,
// ) -> Result<sgx_status_t, String> {
//     info!("✔ [Enc] Sealing data...");
//     let data = DatabaseKeyAndValue::new(key.clone(), value);
//     info!("✔ [Enc] Key to seal: {:?}", data.key);
//     info!("✔ [Enc] Value to seal: {:?}", data.value);
//     let encoded_data = serde_cbor::to_vec(&data).unwrap();
//     let encoded_slice = encoded_data.as_slice();
//     let extra_data: [u8; 0] = [0u8; 0]; // TODO Abstract this away!
//     let sealing_result = SgxSealedData::<[u8]>::seal_data(
//         &extra_data,
//         encoded_slice,
//     );
//     let sealed_data = match sealing_result {
//         Ok(sealed_data) => sealed_data,
//         Err(sgx_error) => return Err(sgx_error.to_string())
//     };
//     trace!(
//         "✔ [Enc] Sealed-data additional data: {:?}",
//         sealed_data.get_additional_txt()
//     );
//     trace!(
//         "✔ [Enc] Sealed-data encrypted txt: {:?}",
//         sealed_data.get_encrypt_txt()
//     );
//     trace!(
//         "✔ [Enc] Sealed-data payload size: {:?}",
//         sealed_data.get_payload_size()
//     );
//     trace!("✔ [Enc] Raw sealed data size: {:?}",
//         SgxSealedData::<u8>::calc_raw_sealed_data_size(
//             sealed_data.get_add_mac_txt_len(),
//             sealed_data.get_encrypt_txt_len(),
//         )
//     );
//     trace!("✔ [Enc] Data sealed successfully!");
//     let sealed_log_size = size_of::<sgx_sealed_data_t>() + encoded_slice.len();
//     trace!("✔ [Enc] Sealed log size: {}", sealed_log_size);
//     let option = to_sealed_log_for_slice(
//         &sealed_data,
//         scratch_pad_pointer,
//         sealed_log_size as u32,
//     );
//     if option.is_none() {
//         return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER.to_string())
//     }
//     info!("✔ [Enc] Sealed data written into app's scratch-pad!");
//     info!("✔ [Enc] Sending db key & sealed data size via OCALL...");
//     let key_pointer: *mut u8 = &mut key[0];
//     unsafe {
//         save_to_db(
//             &mut sgx_status_t::SGX_SUCCESS,
//             key_pointer,
//             key.len() as *const u32,
//             sealed_log_size as *const u32,
//             scratch_pad_pointer,
//         )
//     };
//     Ok(sgx_status_t::SGX_SUCCESS)
// }

#[no_mangle]
pub extern "C" fn run_session(
    app_scratch_pad_pointer: *mut u8,
    _app_scratch_pad_size: u32,
    sock_fd: c_int,
) -> sgx_status_t {
    // let ias_key = env::var("IAS_KEY").expect("IAS_KEY is not set");
    // let spid_env = env::var("SPID").expect("SPID is not set");
    // let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    // let spid = decode_spid(&spid_env);

    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let mut stream = TcpStream::new(sock_fd).expect("stream error");
    // let response = format!("HTTP/1.1 302 Found\r\n\r\nLocation: https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&scope=email%20openid&client_id=1001771408255-pc3su16mforld2to3mmlur9i1p3s6c6o.apps.googleusercontent.com&redirect_uri=http://localhost:22222&nonce=abcde");

    let mut bufreader = BufReader::new(&stream);
    let mut bufwriter = BufWriter::new(&stream);

    // bufwriter.write(response.as_bytes()).expect("write error");
    // bufwriter.flush().expect("flush error");

    // get idpair
    let mut buf = String::new();

    let _ = bufreader.read_to_string(&mut buf).expect("read id error");
    let id = buf.clone();
    println!("id: {id}");

    // buf.clear();

    // let _ = bufreader.read_to_string(&mut buf).expect("read key error");
    // let key = buf.clone();

    // let mut enclave_scratch_pad: Vec<u8> = vec![0; SCRATCH_PAD_SIZE];
    // seal_item_into_db(id.as_bytes().clone(), as_bytes(), app_scratch_pad_pointer)
    //     .and_then(|_| get_item_from_db(id.as_bytes(), &mut enclave_scratch_pad))
    //     .unwrap()

    // println!("id: {id}\nkey: {key}");

    sgx_status_t::SGX_SUCCESS
}

pub fn decode_spid(hex: &str) -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let hex = hex.trim();

    if hex.len() < 16 * 2 {
        println!("Input spid file len ({}) is incorrect!", hex.len());
        return spid;
    }

    let decoded_vec = hex::decode(hex).unwrap();

    spid.id.copy_from_slice(&decoded_vec[..16]);

    spid
}
