use super::imports::*;

pub async fn handle<'a>(matches: &ArgMatches<'a>, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let json_input: String = matches.values_of("input").unwrap().collect::<Vec<&str>>().join(" ");
    let res = hyxe_user::external_services::fcm::fcm_packet_processor::process(json_input, ctx.account_manager.clone()).await;
    log::info!("[FCM] Done processing json input");
    Ok(Some(res.into()))
}