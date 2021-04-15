use super::imports::*;
use hyxe_crypt::sec_bytes::SecBuffer;

pub async fn handle<'a>(matches: &ArgMatches<'a>, _server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let message = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
    let cid = ctx.get_active_cid();
    let security_level = parse_security_level(matches)?;

    if let Some(session) = ctx.sessions.write().await.get_mut(&cid) {
        log::info!("About to send: {}", &message);
        session.channel_tx.set_security_level(security_level);
        session.channel_tx.send_unbounded(SecBuffer::from(message))?;
        Ok(Some(KernelResponse::ResponseTicket(session.channel_tx.channel_id().0)))
    } else {
        Err(ConsoleError::Default("Please make sure you have switched to an active session, and then try again"))
    }
}