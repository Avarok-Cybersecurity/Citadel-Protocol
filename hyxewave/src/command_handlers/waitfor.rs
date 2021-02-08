use super::imports::*;
use parking_lot::MutexGuard;
use clap::App;
use std::sync::mpsc::SyncSender;

/// This will BLOCK the calling thread if the command returns a ticket
pub fn handle<'a>(matches: &ArgMatches<'a>, clap: MutexGuard<'_, App<'static, 'static>>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let message_parts = matches.values_of("command").unwrap().collect::<Vec<&str>>();
    let timeout = usize::from_str(matches.value_of("timeout").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;

    // create a custom FFI_IO that calls the tx
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let custom_chan = get_custom_ffi_io(tx);

    match crate::console::virtual_terminal::handle(clap, message_parts, server_remote, ctx, Some(custom_chan)) {
        Ok(Some(KernelResponse::ResponseTicket(ticket))) => {
            log::info!("[Blocking wait] Waiting for ticket {} for up to {}ms ...", ticket, timeout);
            // the custom_chan will be used to notify this once the response occurs
            rx.recv_timeout(Duration::from_millis(timeout as u64)).map_err(|err| ConsoleError::Generic(err.to_string()))?
        }

        val => val
    }
}

#[allow(unused_must_use)]
fn get_custom_ffi_io(input: SyncSender<Result<Option<KernelResponse>, ConsoleError>>) -> FFIIO {
    FFIIO::from(Box::new(move |res| {
        input.send(res);
    }) as Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>)
}