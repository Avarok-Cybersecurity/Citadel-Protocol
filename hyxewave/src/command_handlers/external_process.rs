use super::imports::*;
use hyxe_user::external_services::ExternalService;

pub async fn handle<'a>(matches: &ArgMatches<'a>, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let use_fcm = matches.is_present("fcm");
    let use_rtdb = matches.is_present("rtdb");

    if !use_fcm && !use_rtdb {
        return Err(ConsoleError::Default("This command expects either an --fcm or --rtdb flag"))
    }

    let outbound_service = if use_fcm { ExternalService::Fcm } else { ExternalService::Rtdb };

    let json_input: String = matches.values_of("input").unwrap().collect::<Vec<&str>>().join(" ");
    let res = hyxe_user::external_services::fcm::fcm_packet_processor::process(json_input, ctx.account_manager.clone(), outbound_service).await;
    log::info!("[FCM] Done processing json input");
    Ok(Some(res.into()))
}