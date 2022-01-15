use super::imports::*;

pub fn handle<'a>(matches: &ArgMatches<'a>, ctx: &ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    if let Some(matches) = matches.subcommand_matches("remove") {
        let id = matches.value_of("id").unwrap();
        let id = id.parse::<u64>().map_err(|err| ConsoleError::Generic(err.to_string()))?;
        let ticket_queue = ctx.ticket_queue.as_ref().ok_or(ConsoleError::Default("Ticket queue not loaded"))?;
        return if ticket_queue.remove_ticket(id.into()) {
            Ok(Some(KernelResponse::Confirmation))
        } else {
            Err(ConsoleError::Default("Requested ticket did not exist"))
        }
    }

    Err(ConsoleError::Default("Bad subcommand config"))
}