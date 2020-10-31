use super::imports::*;
use parking_lot::MutexGuard;
use clap::App;

pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>, clap: MutexGuard<'_, App<'static, 'static>>) -> Result<Option<KernelResponse>, ConsoleError> {
    let session_username = matches.value_of("session").unwrap();
    if ctx.user_is_connected(None, Some(session_username)) {
        if let Some(cnac) = ctx.account_manager.get_client_by_username(session_username) {
            let cid = cnac.get_id();
            ctx.set_active_cid(cid);
            *ctx.active_user.write() = session_username.to_string();

            colour::green!("{} ({}) ", session_username, cid);
            colour::green!("is now your active session. Type ");
            colour::dark_yellow!("send <message> ");
            colour::green!("to communicate\n");

            if matches.is_present("command") {
                let message = matches.values_of("command").unwrap().collect::<Vec<&str>>();
                // recursively call this function again
                return super::super::console::virtual_terminal::handle(clap, message, server_remote, ctx, ffi_io);
            }

            Ok(None)
        } else {
            Err(ConsoleError::Generic(format!("We were able to find the active session corresponding to {}, but not its CNAC. Please submit a bug report", session_username)))
        }
    } else {
        Err(ConsoleError::Generic(format!("{} is not an active session", session_username)))
    }
}