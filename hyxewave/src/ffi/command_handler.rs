use hyxe_net::hdp::hdp_server::HdpServerRemote;
use crate::console::console_context::ConsoleContext;
use crate::console_error::ConsoleError;
use crate::console::virtual_terminal::handle;
use tokio::runtime::Handle;
use crate::ffi::{KernelResponse, FFIIO};

/// This will immediately return an answer to the caller. Any future answers will be returned
/// via the FFI_STATIC's FFIIO
pub fn on_ffi_bytes_received<T: AsRef<str>>(input: T) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut lock = super::ffi_entry::FFI_STATIC.lock();
    let opt = lock.as_mut();
    if let Some((ctx, server_remote, ffi_io, rt_handle)) = opt {
        handle_ffi_payload(server_remote, ctx, ffi_io.clone(), input.as_ref(), rt_handle)
    } else {
        Err(ConsoleError::Default("Context and server remote not yet set!"))
    }
}

/// Checks the first byte, enters the tokio context thereafter
fn handle_ffi_payload(server_remote: &mut HdpServerRemote, ctx: &ConsoleContext, ffi_io: FFIIO, input: &str, rt_handle: &Handle) -> Result<Option<KernelResponse>, ConsoleError> {
    //let buffer = String::from_utf8(input)?;
    let parts = input.split(" ").collect::<Vec<&str>>();
    let clap = &super::super::console::virtual_terminal::CLAP_APP;

    // The following function MUST be called with a tokio context. If it does not, MIO registrations
    // will fail since they require Handle::current(), resulting in a panic
    rt_handle.block_on(async move {
        handle(clap.lock().await, parts, server_remote, ctx, Some(ffi_io)).await
    })
}