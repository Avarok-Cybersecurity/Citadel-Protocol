#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use crate::ffi_object::load_and_execute_ffi_static;
use ffi_helpers::null_pointer_check;
use hyxewave::ffi::KernelResponse;
use hyxewave::re_exports::{const_mutex, AccountManager, PRIMARY_PORT};
use parking_lot::Mutex;
use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::{ffi::CStr, os::raw};

const BIND_ADDR: &str = "0.0.0.0";

pub mod ffi_object;

macro_rules! error {
    ($result:expr) => {
        error!($result, 0);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                ffi_helpers::update_last_error(e);
                return $error;
            }
        }
    };
}

macro_rules! cstr {
    ($ptr:expr) => {
        cstr!($ptr, 0);
    };
    ($ptr:expr, $error:expr) => {{
        null_pointer_check!($ptr);
        error!(unsafe { CStr::from_ptr($ptr).to_str() }, $error)
    }};
}

#[no_mangle]
pub unsafe extern "C" fn last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

#[no_mangle]
pub unsafe extern "C" fn error_message_utf8(buf: *mut raw::c_char, length: i32) -> i32 {
    ffi_helpers::error_handling::error_message_utf8(buf, length)
}

#[no_mangle]
pub extern "C" fn load_page(port: i64, home_dir: *const raw::c_char) -> i32 {
    start_logger();
    load_and_execute_ffi_static(port, cstr!(home_dir))
}

static BACKGROUND_PROCESSOR_INSTANCE: Mutex<Option<AccountManager>> = const_mutex(None);
#[no_mangle]
/// Meant to be executed by background isolates needing access to the account manager (e.g., FCM)
pub unsafe extern "C" fn background_processor(
    packet: *const raw::c_char,
    home_dir: *const raw::c_char,
) -> *mut raw::c_char {
    start_logger();
    let packet = CStr::from_ptr(packet).to_str().unwrap();
    let home_dir = CStr::from_ptr(home_dir).to_str().unwrap();
    log::info!("[Rust BG processor] Received packet: {:?}", &packet);
    log::info!(
        "Primary instance existent in memory? {}",
        hyxewave::ffi::ffi_entry::FFI_STATIC.lock().is_some()
    ); // for debug to monitor behavior
    let mut lock = BACKGROUND_PROCESSOR_INSTANCE.lock();
    if lock.is_none() {
        // setup
        log::info!("[Rust BG processor] Setting up background processor ...");
        // TODO: Since it's possible this gets called multiple times per program (for whatever reason), make sure that the CNAC gets
        // saved after EVERY alteration made to a CNAC in processor
        match AccountManager::new_local(
            SocketAddr::new(IpAddr::from_str(BIND_ADDR).unwrap(), PRIMARY_PORT),
            Some(home_dir.to_string()),
        ) {
            Ok(acc_mgr) => {
                log::info!("[Rust BG processor] Success setting-up account manager");
                *lock = Some(acc_mgr);
            }

            Err(err) => {
                let err = err.to_string();
                return CString::new(
                    KernelResponse::Error(0, err.into_bytes())
                        .serialize_json()
                        .unwrap(),
                )
                .unwrap()
                .into_raw();
            }
        }
    }

    let acc_mgr = lock.as_ref().unwrap();
    let fcm_res = KernelResponse::from(
        hyxewave::re_exports::fcm_packet_processor::blocking_process(packet, acc_mgr),
    );
    CString::new(fcm_res.serialize_json().unwrap())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn send_to_kernel(packet: *const raw::c_char) -> *mut raw::c_char {
    let packet = CStr::from_ptr(packet).to_str().unwrap();
    log::info!("[Rust] Received packet: {:?}", &packet);

    let packet: Vec<u8> = Vec::from(packet);

    let kernel_response = KernelResponse::from(
        hyxewave::ffi::command_handler::on_ffi_bytes_received(packet),
    );

    //log::info!("Kernel response: {:?}", &kernel_response);
    let ret = kernel_response.serialize_json().unwrap();
    let ptr = CString::new(ret).unwrap();
    ptr.into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn memfree(ptr: *const raw::c_char) -> i32 {
    if ptr.is_null() {
        -1
    } else {
        std::mem::drop(CString::from_raw(ptr as *mut raw::c_char));
        0
    }
}

fn start_logger() {
    #[cfg(target_os = "android")]
    {
        use android_logger::{Config, FilterBuilder};
        use log::Level;

        android_logger::init_once(
            Config::default().with_min_level(Level::Trace).with_filter(
                FilterBuilder::default()
                    .parse("trace,hyxewave=trace")
                    .build(),
            ),
        );

        log::info!("Starting Android Logger");
    }
}
