use std::convert::TryFrom;

use tokio::runtime::Handle;

use hyxe_net::hdp::hdp_server::HdpServerRemote;

use crate::console::console_context::ConsoleContext;
use crate::console::virtual_terminal::handle;
use crate::console_error::ConsoleError;
use crate::ffi::{FFIIO, KernelResponse};

/// This will immediately return an answer to the caller. Any future answers will be returned
/// via the FFI_STATIC's FFIIO
pub fn on_ffi_bytes_received(input: Vec<u8>) -> Result<Option<KernelResponse>, ConsoleError> {
    let lock = super::ffi_entry::FFI_STATIC.lock();
    let opt = lock.as_ref();
    if let Some((ctx, server_remote, ffi_io, rt_handle)) = opt {
        handle_ffi_payload(server_remote, ctx, ffi_io.clone(), input, rt_handle)
    } else {
        Err(ConsoleError::Default("Context and server remote not yet set!"))
    }
}

/// Checks the first byte, enters the tokio context thereafter
fn handle_ffi_payload(server_remote: &HdpServerRemote, ctx: &ConsoleContext, ffi_io: FFIIO, input: Vec<u8>, rt_handle: &Handle) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut package = FFIPackage::try_from(input).map_err(|_| ConsoleError::Default("Bad package command"))?;
    match package.command {
        FFICommand::StandardInput => {
            let input = package.get_adjusted_payload();
            let buffer = String::from_utf8(input.to_vec())?;
            let parts = buffer.split(" ").collect::<Vec<&str>>();
            let clap = &super::super::console::virtual_terminal::CLAP_APP;

            // The following function MUST be called with a tokio context. If it does not, MIO registrations
            // will fail since they require Handle::current(), resulting in a panic
            let _guard = rt_handle.enter();
            handle(clap.0.lock(), parts, server_remote, ctx, Some(ffi_io))
        }
    }
}

struct FFIPackage {
    command: FFICommand,
    payload: Vec<u8>
}

#[derive(Copy, Clone, Debug)]
enum FFICommand {
    // meant to go straight into the console
    StandardInput
}

impl FFIPackage {
    pub fn get_adjusted_payload(&mut self) -> Vec<u8> {
        self.payload.split_off(1)
    }
}

impl TryFrom<Vec<u8>> for FFIPackage {
    type Error = ();

    fn try_from(payload: Vec<u8>) -> Result<Self, Self::Error> {
        if payload.len() != 0 {
            let command = FFICommand::try_from(payload[0])?;
            Ok(Self { command, payload })
        } else {
            Err(())
        }
    }
}

impl TryFrom<u8> for FFICommand {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => {
                Ok(FFICommand::StandardInput)
            }

            _ => {
                Err(())
            }
        }
    }
}