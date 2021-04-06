use super::imports::*;
use tokio::sync::MutexGuard;
use async_recursion::async_recursion;

#[async_recursion(?Send)]
pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>, clap: MutexGuard<'a, AppThreadSafe>) -> Result<Option<KernelResponse>, ConsoleError> {
    let cnac = get_cid_from_str(&ctx.account_manager, matches.value_of("session").unwrap()).await?;
    if ctx.user_is_connected(Some(cnac.get_cid()), None).await || ffi_io.is_some() {
        let cid = cnac.get_id();
        let session_username = cnac.get_username();
        ctx.set_active_cid(cid);
        *ctx.active_user.write() = session_username.clone();

        colour::green!("{} ({}) ", session_username, cid);
        colour::green!("is now your active session\n");

        if matches.is_present("command") {
            let message = matches.values_of("command").unwrap().collect::<Vec<&str>>();
            // recursively call this function again
            return super::super::console::virtual_terminal::handle(clap, message, server_remote, ctx, ffi_io).await;
        }

        Ok(None)
    } else {
        Err(ConsoleError::Generic(format!("{} is not an active session", cnac.get_cid())))
    }
}