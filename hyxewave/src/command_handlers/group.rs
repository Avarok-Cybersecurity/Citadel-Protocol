use super::imports::*;
use hyxe_net::hdp::peer::message_group::MessageGroupKey;
use hyxe_crypt::sec_bytes::SecBuffer;

pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let ctx_cid = ctx.get_active_cid();
    let ref cnac = ctx.get_cnac_of_active_session().ok_or(ConsoleError::Default("Session CNAC missing"))?;

    if let Some(matches) = matches.subcommand_matches("accept-invite") {
        return handle_accept_invite(matches, server_remote, ctx);
    }

    if let Some(_matches) = matches.subcommand_matches("invites") {
        return handle_invites(ctx, cnac)
    }

    if let Some(matches) = matches.subcommand_matches("create") {
        return handle_create(matches, server_remote, ctx, cnac, ctx_cid);
    }

    if let Some(matches) = matches.subcommand_matches("end") {
        return handle_end(matches, server_remote, ctx);
    }

    if let Some(matches) = matches.subcommand_matches("add") {
        return handle_add(matches, server_remote, ctx, cnac);
    }

    if let Some(matches) = matches.subcommand_matches("kick") {
        return handle_kick(matches, server_remote, ctx, cnac);
    }

    if let Some(_) = matches.subcommand_matches("list") {
        return handle_list(ctx, cnac, ctx_cid);
    }

    if let Some(matches) = matches.subcommand_matches("leave") {
        return handle_leave(matches, server_remote, ctx);
    }

    if let Some(matches) = matches.subcommand_matches("send") {
        return handle_send(matches, server_remote, ctx, cnac);
    }

    Ok(None)
}

fn handle_leave<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let signal = GroupBroadcast::LeaveRoom(key.key);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);
    let ticket = server_remote.unbounded_send(request)?;

    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, key.implicated_cid, move |_ctx, _ticket, peer_response| {
        match peer_response {
            PeerResponse::Group(GroupBroadcast::LeaveRoomResponse(key, success, response)) => {
                if success {
                    printf_ln!(colour::green!("{}\n", &response));
                } else {
                    printf_ln!(colour::red!("Unable to leave group {} ({}:{}). Reason: {}\n", gid, key.cid, key.mgid, &response));
                }
            }

            _ => {
                printf_ln!(colour::red!("Unable to leave group {} ({}:{})\n", gid, key.key.cid, key.key.mgid));
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

fn handle_accept_invite<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let mail_id = usize::from_str(matches.value_of("mid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    let mut write = ctx.unread_mail.write();
    return if let Some(invitation) = write.remove_group_request(mail_id) {
        let ticket = invitation.ticket;
        let implicated_local_cid = invitation.implicated_local_cid;
        let key = invitation.key;

        let signal = GroupBroadcast::AcceptMembership(key);
        let request = HdpServerRequest::GroupBroadcastCommand(implicated_local_cid, signal);

        server_remote.send_with_custom_ticket(ticket, request)?;
        std::mem::drop(write);

        // track request
        ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, implicated_local_cid, move |ctx, _ticket, signal| {
            match signal {
                PeerResponse::Group(signal) => {
                    match signal {
                        GroupBroadcast::AcceptMembershipResponse(success) => {
                            if success {
                                printfs!({
                                    colour::green_ln!("Membership accept success! You may now message within {:?}\n", key);
                                    let new_group_id = ctx.add_message_group_local(key, implicated_local_cid);
                                    colour::yellow_ln!("To interact with the group, use group ID: {}\n", new_group_id);
                                });
                            } else {
                                printf_ln!(colour::red!("Membership accept failed for {:?}", key))
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }

            CallbackStatus::TaskComplete
        });

        Ok(Some(ticket))
    } else {
        Err(ConsoleError::Default("Invalid Invite ID Specified (not found)"))
    }
}

fn handle_invites<'a>(ctx: &'a ConsoleContext, cnac: &'a ClientNetworkAccount) -> Result<Option<Ticket>, ConsoleError> {
    let read = ctx.unread_mail.read();
    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "Invite ID", "Owner Username", "Owner CID", "MGID"]);
    let mut count = 0;
    read.visit_group_requests(|invite_id, entry| {
        if let Some(owner_peer) = cnac.get_hyperlan_peer(entry.key.cid) {
            let username = owner_peer.username.unwrap_or(String::from("INVALID"));
            table.add_row(prettytable::row![c => invite_id, username, entry.key.cid, entry.key.mgid]);
            count += 1;
        }
    });

    if count != 0 {
        printf!(table.printstd());
    } else {
        printf_ln!(colour::white!("No pending invites exist locally\n"));
    }

    Ok(None)
}

fn handle_create<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, cnac: &ClientNetworkAccount, ctx_cid: u64) -> Result<Option<Ticket>, ConsoleError> {
    let target_cids = if let Some(target_cids) = matches.values_of("target_cids") {
        target_cids.filter_map(|res| get_peer_cid_from_cnac(cnac, res).ok()).collect::<Vec<u64>>()
    } else {
        Vec::with_capacity(0)
    };

    printfs!({
        if target_cids.is_empty() {
            colour::white_ln!("Will create new broadcast group with no initial peers (add later)\n");
        } else {
            colour::white_ln!("Will create new broadcast group with these provided peers:\n");
            for cid in target_cids.iter() {
                colour::yellow!("\r{}\n", *cid)
            }
        }
    });

    let signal = GroupBroadcast::Create(target_cids);
    let request = HdpServerRequest::GroupBroadcastCommand(ctx_cid, signal);

    let ticket = server_remote.unbounded_send(request)?;
    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, ctx_cid, move |ctx, _ticket, signal| {
        match signal {
            PeerResponse::Group(broadcast_signal) => {
                match broadcast_signal {
                    GroupBroadcast::CreateResponse(key) => {
                        if let Some(key) = key {
                            printf_ln!(colour::green!("The HyperLAN Server created a new group: {}\n", key));
                            // create a new entry
                            let next_gid = ctx.message_group_incrementer.fetch_add(1, Ordering::SeqCst);
                            let mut write = ctx.message_groups.write();

                            if write.insert(next_gid, MessageGroupContainer::new(key, ctx_cid)).is_some() {
                                log::warn!("Check program logic; the supplied key already existed locally in the map");
                            }
                        } else {
                            printf_ln!(colour::red!("The HyperLAN Server was unable to create create a group\n"));
                        }
                    }

                    _ => {
                        printf_ln!(colour::red!("Invalid response for CREATE_GROUP subroutine\n"));
                    }
                }
            }

            PeerResponse::Timeout => {
                printf_ln!(colour::red!("CREATE_GROUP request timed-out\n"));
            }

            _ => {
                printf_ln!(colour::red!("Invalid response for CREATE_GROUP subroutine\n"));
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

fn handle_end<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;

    printf_ln!(colour::white!("Will attempt to end the following broadcast group ({})\n", &key.key));

    let signal = GroupBroadcast::End(key.key);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.unbounded_send(request)?;
    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, key.implicated_cid, |_ctx, _ticket, signal| {
        match signal {
            PeerResponse::Group(broadcast_signal) => {
                match broadcast_signal {
                    GroupBroadcast::EndResponse(key, success) => {
                        if success {
                            printf_ln!(colour::green!("Successfully ended broadcast group {}\n", key))
                        } else {
                            printf_ln!(colour::red!("Unable to end broadcast group {}\n", key));
                        }
                    }

                    _ => {
                        printf_ln!(colour::red!("Invalid response for END_GROUP subroutine\n"));
                    }
                }
            }

            _ => {
                printf_ln!(colour::red_ln!("Invalid response for END_GROUP subroutine\n"));
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

fn handle_add<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, cnac: &ClientNetworkAccount) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let target_cids = matches.values_of("target_cids").unwrap().filter_map(|res| get_peer_cid_from_cnac(cnac, res).ok()).collect::<Vec<u64>>();

    printfs!({
        colour::white_ln!("\rWill attempt to add to the broadcast group ({}) with these provided peers:\n", &key.key);

        for cid in target_cids.iter() {
            colour::yellow!("{}\n", *cid)
        }
    });

    let signal = GroupBroadcast::Add(key.key, target_cids);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.unbounded_send(request)?;
    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, key.implicated_cid, |_ctx, _ticket, signal| {
        match signal {
            PeerResponse::Group(broadcast_signal) => {
                match broadcast_signal {
                    GroupBroadcast::AddResponse(key, failed_opt) => {
                        if let Some(failed) = failed_opt {
                            printfs!({
                                colour::red_ln!("\rFailed to add the following peers:");
                                for peer in failed {
                                    colour::red!("{}\n", peer)
                                }
                            });
                        } else {
                            printf_ln!(colour::green!("Successfully added peers for {}. Waiting for peers to accept ...\n", key));
                        }
                    }

                    _ => {
                        printf_ln!(colour::red!("Invalid response for ADD_GROUP subroutine\n"));
                    }
                }
            }

            _ => {
                printf_ln!(colour::red!("Invalid response for ADD_GROUP subroutine\n"));
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

fn handle_kick<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, cnac: &ClientNetworkAccount) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let target_cids = matches.values_of("target_cids").unwrap().filter_map(|res| get_peer_cid_from_cnac(cnac, res).ok()).collect::<Vec<u64>>();

    printfs!({
        colour::white_ln!("\rWill attempt to kick the provided peers from the broadcast group ({}):\n", &key.key);

        for cid in target_cids.iter() {
            colour::yellow!("{}\n", *cid)
        }
    });

    let signal = GroupBroadcast::Kick(key.key, target_cids);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.unbounded_send(request)?;
    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, key.implicated_cid, |_ctx, _ticket, signal| {
        match signal {
            PeerResponse::Group(broadcast_signal) => {
                match broadcast_signal {
                    GroupBroadcast::KickResponse(key, success) => {
                        if !success {
                            printf_ln!(colour::red!("Failed to kick all the peers\n"));
                        } else {
                            printf_ln!(colour::green!("Successfully kicked peers for {}\n", key));
                        }
                    }

                    _ => {
                        printf_ln!(colour::red!("Invalid response for KICK_GROUP subroutine\n"));
                    }
                }
            }

            _ => {
                printf_ln!(colour::red!("Invalid response for KICK_GROUP subroutine\n"));
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

fn handle_list(ctx: &ConsoleContext, cnac: &ClientNetworkAccount, ctx_cid: u64) -> Result<Option<Ticket>, ConsoleError> {
    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "GID", "Owner Username", "Owner CID", "MGID"]);
    let read = ctx.message_groups.read();
    let len = read.len();
    for (gid, key) in read.iter() {
        let username = if key.key.cid != ctx_cid {
            cnac.get_hyperlan_peer(key.key.cid).and_then(|res| res.username.clone())
                .unwrap_or(String::from("INVALID"))
        } else {
            ctx.active_user.read().clone()
        };

        table.add_row(prettytable::row![c => gid, username, key.key.cid, key.key.mgid]);
    }

    if len != 0 {
        printf!(table.printstd());
    } else {
        printf_ln!(colour::white!("No concurrent message groups found\n"));
    }

    Ok(None)
}

fn handle_send<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, cnac: &ClientNetworkAccount) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let message: String = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
    printf_ln!(colour::white!("Will send the following message to the broadcast group ({}): {}\n", &key.key, &message));
    let username = cnac.get_username();
    let signal = GroupBroadcast::Message(username.clone(), key.key, SecBuffer::from(message.clone()));
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.unbounded_send(request)?;

    // once the server broadcasts the message, the console will print-out the data
    ctx.register_ticket(ticket, CREATE_GROUP_TIMEOUT, key.implicated_cid, move |_ctx, _ticket, signal| {
        match signal {
            PeerResponse::Group(GroupBroadcast::MessageResponse(key, success)) => {
                if success {
                    printfs!({
                        colour::yellow!("\n\r[{}@{}:{}]: ", username, key.cid, key.mgid);
                        colour::white!("{}\n", message);
                    });
                } else {
                    printf_ln!(colour::red!("Failed broadcasting message {}\n", key));
                }
            }

            n => {
                printf_ln!(colour::red!("Invalid response for MESSAGE_GROUP subroutine\n"));
                log::info!("{:?}", &n)
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(ticket))
}

#[derive(Debug, Clone)]
pub struct MessageGroupContainer {
    pub key: MessageGroupKey,
    // note: the implicated CID is the session that is in the group, and not necessarily the CID in key.cid
    pub implicated_cid: u64
}

impl MessageGroupContainer {
    pub fn new(key: MessageGroupKey, implicated_cid: u64) -> Self {
        Self { key, implicated_cid }
    }
}