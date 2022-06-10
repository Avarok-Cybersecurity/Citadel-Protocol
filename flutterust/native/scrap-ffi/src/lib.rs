#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use crate::ffi_object::load_and_execute_ffi_static;
use ffi_helpers::null_pointer_check;
use hyxewave::ffi::KernelResponse;
use hyxewave::re_exports::{AccountManager, BackendType, PRIMARY_PORT, AccountError, AssertSendSafeFuture, ExternalService};
use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::{ffi::CStr, os::raw};
use hyxewave::app_config::{TomlConfig, HypernodeConfig, BackendTomlConfig};

const BIND_ADDR: &str = "0.0.0.0";

fn generate_backend_config(url: &str) -> BackendTomlConfig {
    BackendTomlConfig {
        url: url.to_string(),
        max_connections: None,
        min_connections: None,
        connect_timeout_sec: None,
        idle_timeout_sec: Some(30),
        max_lifetime_sec: Some(30),
        car_mode: None
    }
}

pub(crate) fn generate_app_config(home_dir: &str, database_url: &str) -> TomlConfig {
    let backend = generate_backend_config(database_url);

    let node = HypernodeConfig {
        alias: "default".to_string(),
        local_bind_addr: None,
        override_home_dir: Some(home_dir.to_string()),
        tls: None,
        backend: Some(backend),
        kernel_threads: Some(2),
        daemon_mode: None,
        argon: None,
        external_services: None
    };

    TomlConfig {
        default_node: "default".to_string(),
        hypernodes: vec![node]
    }
}

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
        cstr!($ptr, 0)
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

    let backend_cfg = generate_backend_config(database);
    let backend_type = BackendType::sql_with(&backend_cfg.url, (&backend_cfg).into());

    log::trace!(target: "lusna", "[Rust BG processor] Received packet: {:?}", &packet);

    // if the primary instance is in memory already, don't bother using the account manager. Delegate to "peer fcm-parse <packet/raw>"
    if hyxewave::ffi::ffi_entry::FFI_STATIC.lock().is_some() {
        log::info!(
            "FFI_STATIC exists, therefore, will route packet from BG to primary processor ..."
        );
        return kernel_response_into_raw(&*("external-process --rtdb --input ".to_string() + packet));
    }

    // setup account manager. We MUST reload each time this gets called, because the main instance may have
    // experienced changes that wouldn't otherwise register in this background isolate
    log::trace!(target: "lusna", "[Rust BG processor] Setting up background processor ...");

    let home_dir = home_dir.to_string();

    let task = async move {
        match AccountManager::new(SocketAddr::new(IpAddr::from_str(BIND_ADDR).unwrap(), PRIMARY_PORT),Some(home_dir.to_string()), backend_type, None, None).await {
            Ok(acc_mgr) => {
                log::trace!(target: "lusna", "[Rust BG processor] Success setting-up account manager");
                let fcm_res = hyxewave::re_exports::fcm_packet_processor::process(packet, acc_mgr, ExternalService::Rtdb).await;

                KernelResponse::from(fcm_res)
            }

            Err(err) => {
                KernelResponse::Error(0, err.into_string().into_bytes())
            }
        }
    };

    let task = AssertSendSafeFuture::new(task);

    match hyxewave::re_exports::fcm_packet_processor::block_on_async(|| task) {
        Ok(res) => CString::new(res.serialize_json().unwrap())
            .unwrap()
            .into_raw(),
        Err(err) => response_err(err)
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
    log::trace!(target: "lusna", "[Rust] Received packet: {:?}", &packet);
    //let packet: Vec<u8> = Vec::from(packet);

    kernel_response_into_raw(packet)
}

fn kernel_response_into_raw(packet: &str) -> *mut raw::c_char {
    let kernel_response = KernelResponse::from(
        hyxewave::ffi::command_handler::on_ffi_bytes_received(packet),
    );

    //log::trace!(target: "lusna", "Kernel response: {:?}", &kernel_response);
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

        log::trace!(target: "lusna", "Starting Android Logger");
    }
}
