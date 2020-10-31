use super::imports::*;

#[allow(unused_results)]
pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let do_purge = matches.is_present("purge");

    if do_purge {
        let value = INPUT_ROUTER.read_line(ctx, Some(|| colour::white!("Are you sure you wish to purge all users? [y/n]: ")));
        let value = value.to_lowercase();
        if value.contains("y") {
            printfs!({
                colour::red_ln!("Disconnecting and purging all local personal/impersonal users ...");
                // end all session
                ctx.disconnect_all(server_remote, false);
                let count = ctx.account_manager.purge();
                colour::green_ln!("Complete! Purged {} client(s) from local storage", count);
            });
        }

        return Ok(None);
    }

    let username = matches.value_of("account").unwrap();
    let force = matches.is_present("force");

    if let Some(cnac) = ctx.account_manager.get_client_by_username(username) {
        let cid = cnac.get_id();
        let write = ctx.sessions.write();
        if write.contains_key(&cid) {
            let request = HdpServerRequest::DeregisterFromHypernode(cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(cid));
            let ticket = server_remote.unbounded_send(request);
            std::mem::drop(write);
            let username = username.to_string();

            ctx.register_ticket(ticket, DEREGISTER_TIMEOUT, cid, move |ctx, _ticket, response| {
                match response {
                    PeerResponse::Ok(_) => {
                        let mut write = ctx.sessions.write();
                        // remove the session
                        write.remove(&cid);
                        // locally already removed
                        printf_ln!(colour::green!("Deregistration of CNAC {} success!\n", cid));
                    }

                    _ => {
                        if force {
                            if ctx.account_manager.delete_client_by_cid(cid) {
                                printf_ln!(colour::yellow!("Deregistration of {} success on local node, but failure on the adjacent node", cid));
                            } else {
                                printf_ln!(colour::red!("Force deregistration failure of {}. Please try again", cid));
                            }
                        } else {
                            printfs!({
                                        colour::red!("\nDeregistration for CNAC {} failure. Consider using ");
                                        colour::yellow!("deregister cnac {} --force ", username);
                                        colour::red!("in order to remove this account without depending on the adjacent server's execution phase\n");
                                    });
                        }
                    }
                }

                CallbackStatus::TaskComplete
            });

            Ok(Some(ticket))
        } else {
            if force {
                if ctx.account_manager.delete_client_by_cid(cid) {
                    printf_ln!(colour::green!("Force deregistration of CNAC {} was a success\n", cid));
                    Ok(None)
                } else {
                    Err(ConsoleError::Generic(format!("We were unable to force remove CNAC {}. Please report this error to the developers", cid)))
                }
            } else {
                Err(ConsoleError::Generic(format!("You must first login in order to deregister. Consider using --force if you want to remove {}'s CNAC locally without a proper sequence (will render future login attempts null and void)", username)))
            }
        }
    } else {
        Err(ConsoleError::Default("Supplied username does not exist locally"))
    }
}