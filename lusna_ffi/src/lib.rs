use android_logger::{Config, FilterBuilder};
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jbyteArray, jstring};
//use std::sync::Mutex;
use lazy_static::lazy_static;
use log::Level;

use hyxewave::ffi::KernelResponse;
use hyxewave::re_exports::Mutex;

use crate::ffi_object::FFIObject;
use hyxewave::console_error::ConsoleError;

/// A type to communicate between FFI boundaries. Other languages must have a mirror version to this
pub mod ffi_object;

lazy_static! {
    pub static ref FFI_OBJECT: Mutex<Option<FFIObject>> = Mutex::new(None);
}

#[no_mangle]
pub extern "system" fn Java_com_lusna_svc_LusnaService_start_1rust_1subsystem(env: JNIEnv<'static>, clazz: JClass<'static>, home_dir: jbyteArray) -> jstring {
    let output = format!("Powered by Rust 1.47 nightly ({} {})", std::env::consts::ARCH, std::env::consts::OS);
    let home_dir = env.convert_byte_array(home_dir).unwrap();
    start_lusnanet(&env, &clazz, home_dir);
    // send_to_java(&[1, 2, 3]);
    log::info!("Successfully executed Lusna's rust kernel");

    env.new_string(output).unwrap().into_inner()
}

/// This function should not be called until start_rust_subsystem is executed.
///
/// This function executes a command against the kernel, then takes the result, wraps it into a vector, and converts the vec into
/// a jbyteArray. From there, it gets sent back to the FFI
#[no_mangle]
pub extern "system" fn Java_com_lusna_svc_LusnaService_send_1data(env: JNIEnv<'static>, _: JClass<'static>, array: jbyteArray) -> jbyteArray {
    let data = env.convert_byte_array(array).unwrap();
    let kernel_response = KernelResponse::from(hyxewave::ffi::command_handler::on_ffi_bytes_received(data));
    env.byte_array_from_slice(serialize(kernel_response).as_slice()).unwrap()
}

/// The Rust side of the codebase should call this when attempting to send raw bytes through the FFI
///
/// For more info on call_method and its parameters, read: http://journals.ecs.soton.ac.uk/java/tutorial/native1.1/implementing/method.html
pub fn send_to_java<T: AsRef<[u8]>>(arr: T) {
    let lock = FFI_OBJECT.lock();
    let ffi = &*lock.as_ref().unwrap();
    log::info!("About to send {:?} to java", arr.as_ref());
    ffi.execute(move |env, clazz| {
        let arr = JValue::Object(JObject::from(env.byte_array_from_slice(arr.as_ref()).unwrap()));
        log::info!("Array packed. Going to call java method");
        if let Err(err) = env.call_method(clazz, "ffiCallback", "([B)V", &[arr]) {
            log::error!("Unable to call java method: {}", err.to_string());
        }
    })
}

/// Format: [0] => type
/// [1..9] => ticket (0 if none)
/// [10..] payload
fn serialize(input: KernelResponse) -> Vec<u8> {
    log::info!("res_to_vec: {:?}", &input);
    input.serialize_json().unwrap()
}

/*
fn pack_string_to_vec(flag: u8, ticket: Option<Ticket>, msg: String) -> Vec<u8> {
    let vals = msg.as_bytes();
    let mut ret = Vec::with_capacity(1 + 8 + vals.len());
    ret.put_u8(flag);
    ret.put_u64(ticket.unwrap_or(Ticket(0)).0);
    ret.put(vals);
    ret
}
*/

fn get_rust_to_native_fn() -> Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + 'static> {
    Box::new(|res| {
        send_to_java(serialize(KernelResponse::from(res)))
    })
}

/// When the java module called get_rust_version on init, this function gets called.
#[allow(unused_results)]
fn start_lusnanet(env: &JNIEnv<'static>, clazz: &JClass<'static>, home_dir: Vec<u8>) {
    (*FFI_OBJECT).lock().replace(FFIObject::new(env, clazz));

    // start android logger
    start_logger();
    let home_dir = String::from_utf8(home_dir).unwrap();
    let args = format!("--bind 0.0.0.0 --home {}", home_dir);
    log::info!("Will execute the Lusna Kernel with: {}", &args);

    // spawn a new thread to not block the FFI call
    std::thread::spawn(move || {
        log::info!("Starting thread ...");
        if let Err(err) = hyxewave::ffi::ffi_entry::execute_lusna_kernel(args, get_rust_to_native_fn()) {
            log::error!("Err executing kernel: {}", err.into_string());
        }
    });
}

fn start_logger() {
    android_logger::init_once(
        Config::default().with_min_level(Level::Trace).with_filter(FilterBuilder::default()
            .parse("trace,hyxewave=trace").build()))
}