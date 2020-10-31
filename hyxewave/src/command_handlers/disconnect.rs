use super::imports::*;

#[derive(Serialize, Debug)]
pub enum DisconnectResponse {
    // ticket, implicated cid
    HyperLANPeerToHyperLANServer(u64, u64),
    HyperLANPeerToHyperLANPeer(u64, u64, u64)
}

pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let all = matches.is_present("all");
    if all {
        printf_ln!(colour::red!("Disconnecting ALL concurrent sessions ..."));
        ctx.disconnect_all(server_remote, false);
        return Ok(None);
    }

    let account = matches.value_of("account").unwrap();
    let cnac = ctx.account_manager.get_client_by_username(account)
        .ok_or_else(|| ConsoleError::Generic(format!("Username {} does not exist", account)))?;
    let cid = cnac.get_id();

    // TODO: Handle WAN connection types
    let ticket = ctx.disconnect_session(cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(cid), server_remote)?;
    printf_ln!(colour::green!("Successfully initiated disconnect sequence for {} (CID: {})", account, cid));
    Ok(Some(ticket))
}