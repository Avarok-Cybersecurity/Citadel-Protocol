use crate::console_error::ConsoleError;
use crate::{shutdown_sequence, setup_shutdown_hook};
use crate::hdp_initiator::execute;
use crate::primary_terminal::parse_command_line_arguments_into_app_config;
use crate::ffi::{FFIIO, KernelResponse};
use parking_lot::Mutex;
use crate::console::console_context::ConsoleContext;
use hyxe_net::hdp::hdp_server::HdpServerRemote;
use tokio::runtime::Handle;
use crate::re_exports::const_mutex;

pub static FFI_STATIC: Mutex<Option<(ConsoleContext, HdpServerRemote, FFIIO, Handle)>> = const_mutex(None);

/// This should be called by higher-level programs that want to communicate with lusna using FFI
///
/// `execute_args`: Pretend you are going to use the CLI version of Lusna, and pass the command line arguments
/// herein (e.g., "--type pure_server --bind 127.0.0.1"
pub fn execute_lusna_kernel<T: ToString>(execute_args: T, to_ffi_frontier: Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>) -> Result<(), ConsoleError> {
    (to_ffi_frontier)(Ok(Some(KernelResponse::Message("Beginning execution phase of the Lusna Kernel".to_string()))));
    let ffi_object = FFIIO::from(to_ffi_frontier);
    setup_shutdown_hook();
    let cfg = parse_command_line_arguments_into_app_config(Some(execute_args.to_string()), Some(ffi_object))?;
    log::info!("Obtained information from console. Now beginning instantiation of HdpServer ...");
    execute(cfg).map_err(|err| ConsoleError::Generic(err.to_string()))
        .and_then(|_| {
            log::info!("Shutting down HdpServer");
            shutdown_sequence(0);
            Ok(())
        })
}