extern crate sgx_types;
extern crate sgx_urts;
#[macro_use] extern crate lazy_static;
use anyhow::Result;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::os::fd::AsRawFd;
use tokio::net::TcpListener;
use std::collections::HashMap;
use std::{
    slice,
    sync::Mutex,
    ptr::copy_nonoverlapping,
};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

const MEGA_BYTE: usize = 1_000_000;
const SCRATCH_PAD_SIZE: usize = MEGA_BYTE * 1;

lazy_static! {
    static ref DATABASE: Mutex<HashMap<Vec<u8>, Vec<u8>>> = {
        let db = HashMap::new();
        Mutex::new(db)
    };
}

extern "C" {
    fn run_session(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        // scratch_pad_pointer: *mut u8,
        // scratch_pad_size: *const u8,
        sock_fd: c_int,
    ) -> sgx_status_t;
}

// #[no_mangle]
// pub extern "C"
// fn get_from_db(
//     key_pointer: *mut u8,
//     key_size: u32,
//     value_pointer: *mut u8,
//     _value_size: u32, // NOTE: Used only in EDL!
// ) -> sgx_status_t {
//     log::info!("✔ [App] Getting from database via OCALL...");
//     let db_key = unsafe {
//         slice::from_raw_parts(key_pointer, key_size as usize)
//     };
//     log::trace!("✔ [App] Database key to query: {:?}", db_key);
//     let mut data = DATABASE
//         .lock()
//         .unwrap()
//         [db_key]
//         .clone();
//     log::info!("✔ [App] Data retreived from database!");
//     let data_length = data.len() as u32;
//     let mut final_bytes_to_copy: Vec<u8> = data_length
//         .to_le_bytes()
//         .to_vec();
//     log::info!("✔ [App] Copying data into enclave...");
//     final_bytes_to_copy.append(&mut data);
//     unsafe {
//         copy_nonoverlapping(
//             &final_bytes_to_copy[0] as *const u8,
//             value_pointer,
//             final_bytes_to_copy.len()
//         )
//     }
//     sgx_status_t::SGX_SUCCESS
// }

// #[no_mangle]
// pub extern "C"
// fn save_to_db(
//     key_pointer: *mut u8,
//     key_size: u32,
//     sealed_log_size: u32,
//     scratch_pad_pointer: *mut u8,
// ) -> sgx_status_t {
//     let data_from_scratch_pad = unsafe {
//         slice::from_raw_parts(scratch_pad_pointer, sealed_log_size as usize)
//     };
//     log::info!("✔ [App] Saving sealed data into database...");
//     let db_key = unsafe {
//         slice::from_raw_parts(key_pointer, key_size as usize)
//     };
//     log::trace!("✔ [App] Database key: {:?}", db_key);
//     log::trace!("✔ [App] Sealed log size: {:?}", sealed_log_size);
//     DATABASE
//         .lock()
//         .unwrap()
//         .insert(
//             db_key.to_vec(),
//             data_from_scratch_pad.to_vec(),
//         );
//     log::info!("✔ [App] Sealed data saved to database successfully!");
//     sgx_status_t::SGX_SUCCESS
// }

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let mut scratch_pad: Vec<u8> = vec![0; SCRATCH_PAD_SIZE];
    let scratch_pad_pointer: *mut u8 = &mut scratch_pad[0];

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            anyhow::bail!("[-] Init Enclave Failed {}!", x.as_str());
        }
    };

    let listener = TcpListener::bind("localhost:54321").await?;
    let mut retval = sgx_status_t::SGX_SUCCESS;

    loop {
        let (sock, addr) = listener.accept().await?;
        let eid = enclave.geteid();

        println!("connection from: {addr}");
        let result =
            unsafe { run_session(eid, &mut retval, sock.as_raw_fd()) };
            // tokio::spawn(async move { unsafe { run_session(eid, &mut retval, scratch_pad_pointer, scratch_pad.len() as *const u8, sock.as_raw_fd()) } });

        match result {
            sgx_status_t::SGX_SUCCESS => {}
            e => {
                anyhow::bail!("[-] ECALL Enclave Failed {}!", e.as_str());
            }
        }
    }

    #[allow(unreachable_code)]
    {
        println!("[+] ecall_test success...");
        enclave.destroy();
        Ok(())
    }
}
