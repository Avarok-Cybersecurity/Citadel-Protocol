#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use crate::ffi_object::load_and_execute_ffi_static;
use ffi_helpers::null_pointer_check;
use hyxewave::ffi::KernelResponse;
use hyxewave::re_exports::{AccountManager, BackendType, PRIMARY_PORT, AccountError, AssertSendSafeFuture};
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
pub extern "C" fn execute(
    port: i64,
    home_dir: *const raw::c_char,
    database: *const raw::c_char,
) -> i32 {
    start_logger();
    load_and_execute_ffi_static(port, cstr!(home_dir), cstr!(database))
}

#[no_mangle]
pub extern "C" fn is_kernel_loaded() -> i32 {
    if hyxewave::ffi::ffi_entry::kernel_ready() {
        1
    } else {
        0
    }
}

#[no_mangle]
/// Meant to be executed by background isolates needing access to the account manager (e.g., FCM)
pub unsafe extern "C" fn fcm_process(
    packet: *const raw::c_char,
    home_dir: *const raw::c_char,
    database: *const raw::c_char,
) -> *mut raw::c_char {
    start_logger();
    let packet = CStr::from_ptr(packet).to_str().unwrap();
    let home_dir = CStr::from_ptr(home_dir).to_str().unwrap();
    let database = CStr::from_ptr(database).to_str().unwrap();
    log::info!("[Rust BG processor] Received packet: {:?}", &packet);

    // if the primary instance is in memory already, don't bother using the account manager. Delegate to "peer fcm-parse <packet/raw>"
    if hyxewave::ffi::ffi_entry::FFI_STATIC.lock().is_some() {
        log::info!(
            "FFI_STATIC exists, therefore, will route packet from BG to primary processor ..."
        );
        return kernel_response_into_raw(&*("fcm-process ".to_string() + packet));
    }

    // setup account manager. We MUST reload each time this gets called, because the main instance may have
    // experienced changes that wouldn't otherwise register in this background isolate
    log::info!("[Rust BG processor] Setting up background processor ...");
    match AccountManager::new_blocking(
        SocketAddr::new(IpAddr::from_str(BIND_ADDR).unwrap(), PRIMARY_PORT),
        Some(home_dir.to_string()),
        BackendType::SQLDatabase(database.to_string()),
    ) {
        Ok(acc_mgr) => {
            log::info!("[Rust BG processor] Success setting-up account manager");
            match hyxewave::re_exports::fcm_packet_processor::block_on_async(move || AssertSendSafeFuture::new(hyxewave::re_exports::fcm_packet_processor::process(packet, acc_mgr))) {
                Ok(res) => {
                    let fcm_res = KernelResponse::from(
                        res,
                    );

                    CString::new(fcm_res.serialize_json().unwrap())
                        .unwrap()
                        .into_raw()
                }

                Err(err) => {
                    response_err(err)
                }
            }
        }

        Err(err) => {
            response_err(err)
        }
    }
}

fn response_err(err: AccountError) -> *mut raw::c_char {
    CString::new(
        KernelResponse::Error(0, err.into_string().into_bytes())
            .serialize_json()
            .unwrap(),
    )
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn send_to_kernel(packet: *const raw::c_char) -> *mut raw::c_char {
    let packet = CStr::from_ptr(packet).to_str().unwrap();
    log::info!("[Rust] Received packet: {:?}", &packet);
    //let packet: Vec<u8> = Vec::from(packet);

    kernel_response_into_raw(packet)
}

fn kernel_response_into_raw(packet: &str) -> *mut raw::c_char {
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
