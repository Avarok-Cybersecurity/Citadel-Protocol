use crate::BIND_ADDR;
use allo_isolate::{IntoDart, Isolate};
use hyxewave::console_error::ConsoleError;
use hyxewave::ffi::KernelResponse;
use parking_lot::{const_mutex, Mutex};
use std::sync::Arc;

pub(crate) static FFI_STATIC: Mutex<Option<FFIObject>> = const_mutex(None);

/// This spawns a new thread wherein blocking occurs. This function returns after
/// starting the hyxewave kernel
pub fn load_and_execute_ffi_static(port: i64, home_dir: &str) -> i32 {
    let obj = FFIObject::from(port);
    let old_opt = FFI_STATIC.lock().replace(obj);
    if let Some(_) = old_opt {
        log::warn!("FFI_STATIC has been replaced! Check the calling program's logic");

        return -1;
    }

    obj.execute_once(home_dir);

    1
}

#[derive(Copy, Clone, Debug)]
pub struct FFIObject {
    isolate: Isolate,
}

impl FFIObject {
    pub fn get_kernel_to_this_function(
    ) -> Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>
    {
        Arc::new(Box::new(|res| {
            log::info!("About to send {:?}", &res);
            let json_packet = KernelResponse::from(res).serialize_json().unwrap();
            match FFI_STATIC
                .lock()
                .as_ref()
                .unwrap()
                .send_to_dart(json_packet)
            {
                true => {
                    log::info!("Successfully sent FFI Message")
                }

                false => {
                    log::error!("Unable to send to dart! [FATAL]");
                }
            }
        }))
    }

    pub fn send_to_dart(&self, packet: impl IntoDart) -> bool {
        self.isolate.post(packet)
    }

    fn execute_once(&self, home_dir: &str) {
        let args = format!("--bind {} --home {} --kthreads 2", BIND_ADDR, home_dir);
        log::info!("Will execute the CLI/FFI NetKernel with: {}", &args);
        let to_ffi_frontier = FFIObject::get_kernel_to_this_function();

        // spawn a new thread to not block the FFI call
        std::thread::spawn(move || {
            log::info!("Started SatoriNET main thread ...");
            if let Err(err) =
                hyxewave::ffi::ffi_entry::execute_lusna_kernel(args, to_ffi_frontier.clone())
            {
                log::error!("Err executing kernel: {:?}", &err);
                (to_ffi_frontier)(Ok(Some(KernelResponse::KernelShutdown(
                    err.into_string().into_bytes(),
                ))))
            }
        });
    }
}

impl From<i64> for FFIObject {
    fn from(isolate: i64) -> Self {
        FFIObject {
            isolate: Isolate::new(isolate),
        }
    }
}
