use super::imports::*;

#[derive(Serialize, Debug)]
pub enum DisconnectResponse {
    // ticket, implicated cid
    HyperLANPeerToHyperLANServer(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64),
    HyperLANPeerToHyperLANPeer(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64)
}

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let all = matches.is_present("all");
    if all {
        printf_ln!(colour::red!("Disconnecting ALL concurrent sessions ..."));
        ctx.disconnect_all(server_remote, false).await;
        return Ok(None);
    }

    let account = matches.value_of("account").unwrap();
    let cnac = get_cid_from_str(&ctx.account_manager, account).await?;
    let cid = cnac.get_id();

    let ticket = ctx.disconnect_session(cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(cid), server_remote).await?;
    printf_ln!(colour::green!("Successfully initiated disconnect sequence for {} (CID: {})\n", account, cid));
    Ok(Some(ticket))
}