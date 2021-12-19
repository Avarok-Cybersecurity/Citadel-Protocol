use crate::console::console_context::ConsoleContext;
use crate::ffi::{FFIIO, KernelResponse};
use hyxe_net::hdp::hdp_server::{NodeRemote, HdpServerRequest};
use crate::console_error::ConsoleError;
use std::time::Duration;
use crate::ticket_event::CallbackStatus;
use hyxe_net::hdp::peer::peer_layer::PeerResponse;

pub async fn handle(ctx: &ConsoleContext, ffi_io: Option<FFIIO>, server_remote: &mut NodeRemote) -> Result<Option<KernelResponse>, ConsoleError> {
    let ticket = server_remote.send(HdpServerRequest::GetActiveSessions).await?;

    ctx.register_ticket(ticket, Duration::from_secs(2), 0, move |ctx, _, resp| {
        match resp {
            PeerResponse::RegisteredCids(cids_registered, _) => {
                let ctx = ctx.clone();
                let ffi_io = ffi_io.clone();

                let task = async move {
                    let mut write = ctx.sessions.write().await;
                    write.retain(|stored_cid, _| {
                        cids_registered.iter().find(|online_in_hdp_server| **online_in_hdp_server == *stored_cid).is_some()
                    });

                    if let Some(ref ffi_io) = ffi_io {
                        (ffi_io)(Ok(Some(KernelResponse::ResponseTicket(ticket.0))))
                    } else {
                        printf_ln!(colour::yellow!("\rResync complete\n"));
                    }
                };

                let _  = tokio::task::spawn(task);
            }

            _ => {}
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
}