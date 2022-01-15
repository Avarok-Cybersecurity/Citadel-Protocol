use crate::console_error::ConsoleError;
use crate::{shutdown_sequence, setup_shutdown_hook};
use crate::hdp_initiator::execute;
use crate::ffi::{FFIIO, KernelResponse};
use parking_lot::Mutex;
use crate::console::console_context::ConsoleContext;
use hyxe_net::hdp::hdp_server::NodeRemote;
use tokio::runtime::Handle;
use crate::re_exports::const_mutex;
use crate::console::virtual_terminal::INPUT_ROUTER;
use std::sync::Arc;
use crate::app_config::TomlConfig;

pub static FFI_STATIC: Mutex<Option<(ConsoleContext, NodeRemote, FFIIO, Handle)>> = const_mutex(None);

/// This should be called by higher-level programs that want to communicate with lusna using FFI
pub fn execute_lusna_kernel(opts: TomlConfig, to_ffi_frontier: Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>) -> Result<(), ConsoleError> {
    (to_ffi_frontier)(Ok(Some(KernelResponse::Message("Beginning execution phase of the Lusna Kernel".to_string().into_bytes()))));
    let ffi_object = FFIIO::from(to_ffi_frontier);
    setup_shutdown_hook();
    log::info!("About to parse config ...");
    let mut cfg = opts.parse_config(None)?;
    cfg.is_ffi = true;
    cfg.ffi_io = Some(ffi_object);

    log::info!("Obtained information from console. Now beginning instantiation of HdpServer ...");
    INPUT_ROUTER.init(true)?;

    execute(cfg).map_err(|err| ConsoleError::Generic(err.to_string()))
        .and_then(|_| {
            log::info!("Shutting down HdpServer");
            shutdown_sequence(0);
            Ok(())
        })
}

/// This should be called before running the kernel via FFI to determine if the kernel needs to be executed or not
pub fn kernel_ready() -> bool {
    FFI_STATIC.lock().is_some()
}