use super::imports::*;

pub fn handle<'a>(matches: &ArgMatches<'a>, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    let json_input: String = matches.values_of("input").unwrap().collect::<Vec<&str>>().join(" ");
    let res = hyxe_user::fcm::fcm_packet_processor::blocking_process(json_input, &ctx.account_manager);
    log::info!("[FCM] Done processing json input");
    Ok(Some(res.into()))
}