use super::imports::*;
use bytes::BytesMut;

pub async fn handle<'a>(matches: &ArgMatches<'a>, _server_remote: &'a NodeRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let message = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
    let cid = ctx.get_active_cid();
    let _security_level = parse_security_level(matches)?;

    if let Some(session) = ctx.sessions.write().await.get_mut(&cid) {
        log::info!("About to send: {}", &message);
            if let Some(udp_tx) = session.udp_channel_tx_opt.as_ref() {
                // TODO: UDP security levels. Let the developer decide how big they want their packets
                udp_tx.unbounded_send(BytesMut::from(message.as_bytes()))?;
                Ok(Some(KernelResponse::Confirmation))
            } else {
                Err(ConsoleError::Default("UDP is not engaged for this session"))
            }

    } else {
        Err(ConsoleError::Default("Please make sure you have switched to an active session, and then try again"))
    }
}