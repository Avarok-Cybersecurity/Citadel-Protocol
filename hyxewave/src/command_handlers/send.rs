use super::imports::*;
use hyxe_crypt::sec_bytes::SecBuffer;

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let message = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
    let cid = ctx.get_active_cid();

    if let Some(_session) = ctx.sessions.write().await.get(&cid) {
        log::info!("About to send: {}", &message);
        let security_level = parse_security_level(matches)?;
        let target_type = VirtualTargetType::HyperLANPeerToHyperLANServer(cid);
        let request = HdpServerRequest::SendMessage(SecBuffer::from(message), cid, target_type, security_level);
        let ticket = server_remote.unbounded_send(request)?;
        //session.tickets.insert(ticket);
        Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
    } else {
        Err(ConsoleError::Default("Please make sure you have switched to an active session, and then try again"))
    }
}