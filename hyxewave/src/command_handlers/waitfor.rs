use super::imports::*;
//use std::sync::mpsc::SyncSender;
use tokio::sync::mpsc::{Sender, channel};
use tokio::sync::MutexGuard;
use async_recursion::async_recursion;
use std::sync::Arc;

/// This will BLOCK the calling thread if the command returns a ticket
#[async_recursion(?Send)]
pub async fn handle<'a>(matches: &ArgMatches<'a>, clap: MutexGuard<'a, AppThreadSafe>, server_remote: &'a mut NodeRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let message_parts = matches.values_of("command").unwrap().collect::<Vec<&str>>();
    let timeout = usize::from_str(matches.value_of("timeout").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;

    // create a custom FFI_IO that calls the tx
    let (tx, mut rx) = channel(1);
    let custom_chan = get_custom_ffi_io(tx);

    match crate::console::virtual_terminal::handle(clap, message_parts, server_remote, ctx, Some(custom_chan)).await {
        Ok(Some(KernelResponse::ResponseTicket(ticket))) => {
            log::info!("[Blocking wait] Waiting for ticket {} for up to {}ms ...", ticket, timeout);
            // the custom_chan will be used to notify this once the response occurs
            //rx.recv_timeout(Duration::from_millis(timeout as u64)).map_err(|err| ConsoleError::Generic(err.to_string()))?
            tokio::time::timeout(Duration::from_millis(timeout as u64), rx.recv()).await?.ok_or(ConsoleError::Default("NoneError on waitfor"))?
        }

        val => val
    }
}

#[allow(unused_must_use)]
fn get_custom_ffi_io(input: Sender<Result<Option<KernelResponse>, ConsoleError>>) -> FFIIO {
    FFIIO { to_ffi_frontier: Arc::new(Box::new(move |res| {
        input.blocking_send(res);
    })) }
}