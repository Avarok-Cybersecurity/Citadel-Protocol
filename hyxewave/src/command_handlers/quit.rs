use super::imports::*;

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<KernelResponse>, ConsoleError> {
    if matches.is_present("force_quit") {
        colour::dark_red_ln!("\rHyxeWave is force shutting down");
        shutdown_sequence(0)
    } else {
        // TODO: Safe shutdown
        ctx.disconnect_all(server_remote, true).await;
        colour::green_ln!("\rHyxeWave initiating safe shutdown subroutine ... alerting all concurrent connections ...");
        std::thread::spawn(move || {
            // give 300ms for system to send disconnect signals
            std::thread::sleep(Duration::from_millis(300));
            shutdown_sequence(0)
        });
    }

    Ok(None)
}