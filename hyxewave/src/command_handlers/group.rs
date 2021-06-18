use super::imports::*;
use hyxe_net::hdp::peer::message_group::MessageGroupKey;
use hyxe_crypt::sec_bytes::SecBuffer;
use multimap::MultiMap;

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let ctx_cid = ctx.get_active_cid();
    let ref cnac = ctx.get_cnac_of_active_session().await.ok_or(ConsoleError::Default("Session CNAC missing"))?;

    if let Some(matches) = matches.subcommand_matches("accept-invite") {
        return handle_accept_invite(matches, server_remote, ctx).await;
    }

    if let Some(_matches) = matches.subcommand_matches("invites") {
        return handle_invites(ctx).await
    }

    if let Some(matches) = matches.subcommand_matches("create") {
        return handle_create(matches, server_remote, ctx, ctx_cid).await;
    }

    if let Some(matches) = matches.subcommand_matches("end") {
        return handle_end(matches, server_remote, ctx).await;
    }

    if let Some(matches) = matches.subcommand_matches("add") {
        return handle_add(matches, server_remote, ctx, ctx_cid).await;
    }

    if let Some(matches) = matches.subcommand_matches("kick") {
        return handle_kick(matches, server_remote, ctx, ctx_cid).await;
    }

    if let Some(_) = matches.subcommand_matches("list") {
        return handle_list(ctx).await;
    }

    if let Some(matches) = matches.subcommand_matches("leave") {
        return handle_leave(matches, server_remote, ctx).await;
    }

    if let Some(matches) = matches.subcommand_matches("send") {
        return handle_send(matches, server_remote, ctx, cnac).await;
    }

    Ok(None)
}

async fn handle_leave<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let signal = GroupBroadcast::LeaveRoom(key.key);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);
    let ticket = server_remote.send(request).await?;

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

async fn handle_accept_invite<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let mail_id = usize::from_str(matches.value_of("mid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    let mut write = ctx.unread_mail.write();
    return if let Some(invitation) = write.remove_group_request(mail_id) {
        let ticket = invitation.ticket;
        let implicated_local_cid = invitation.implicated_local_cid;
        let key = invitation.key;

        let signal = GroupBroadcast::AcceptMembership(key);
        let request = HdpServerRequest::GroupBroadcastCommand(implicated_local_cid, signal);

        server_remote.send_with_custom_ticket(ticket, request).await?;
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

async fn handle_invites(ctx: &ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    struct GroupRow {
        invite_id: usize,
        entry_key_cid: u64,
        mgid: u8
    }

    let read = ctx.unread_mail.read();
    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "Invite ID", "Owner Username", "Owner CID", "MGID"]);
    let mut peers = MultiMap::new();
    read.visit_group_requests(|invite_id, entry| {
        peers.insert(entry.implicated_local_cid, GroupRow { invite_id, entry_key_cid: entry.key.cid, mgid: entry.key.mgid });
    });

    std::mem::drop(read);

    if peers.len() != 0 {
        for (implicated_cid, entries) in peers {
            for entry in entries {
                let username = ctx.account_manager.get_persistence_handler().get_hyperlan_peer_by_cid(implicated_cid, entry.entry_key_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.map(|r| r.username).flatten().unwrap_or_else(|| "INVALID".into());
                table.add_row(prettytable::row![c => entry.invite_id, username, entry.entry_key_cid, entry.mgid]);
            }
        }

        printf!(table.printstd());
    } else {
        printf_ln!(colour::white!("No pending invites exist locally\n"));
    }

    Ok(None)
}

async fn handle_create<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext, ctx_cid: u64) -> Result<Option<Ticket>, ConsoleError> {
    let target_cids = if let Some(target_cids) = matches.values_of("target_cids") {
        let mut ret = Vec::new();
        for target_cid in target_cids {
            ret.push(get_peer_cid_from_cnac(&ctx.account_manager, ctx_cid,target_cid).await?)
        }

        ret
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

    let ticket = server_remote.send(request).await?;
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

async fn handle_end<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;

    printf_ln!(colour::white!("Will attempt to end the following broadcast group ({})\n", &key.key));

    let signal = GroupBroadcast::End(key.key);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.send(request).await?;
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

async fn handle_add<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext, ctx_user: u64) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let values = matches.values_of("target_cids").unwrap();
    let mut target_cids = Vec::new();
    for target_cid in values {
        target_cids.push(get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid).await?)
    }

    printfs!({
        colour::white_ln!("\rWill attempt to add to the broadcast group ({}) with these provided peers:\n", &key.key);

        for cid in target_cids.iter() {
            colour::yellow!("{}\n", *cid)
        }
    });

    let signal = GroupBroadcast::Add(key.key, target_cids);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.send(request).await?;
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

async fn handle_kick<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext, ctx_user: u64) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let values = matches.values_of("target_cids").unwrap();
    let mut target_cids = Vec::new();
    for target_cid in values {
        target_cids.push(get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid).await?)
    }

    printfs!({
        colour::white_ln!("\rWill attempt to kick the provided peers from the broadcast group ({}):\n", &key.key);

        for cid in target_cids.iter() {
            colour::yellow!("{}\n", *cid)
        }
    });

    let signal = GroupBroadcast::Kick(key.key, target_cids);
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.send(request).await?;
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

async fn handle_list(ctx: &ConsoleContext) -> Result<Option<Ticket>, ConsoleError> {
    struct ListRow {
        gid: usize,
        key_cid: u64,
        mgid: u8,
        implicated_local_cid: u64
    }

    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "GID", "Owner Username", "Owner CID", "MGID"]);
    let read = ctx.message_groups.read();
    let rows = read.iter().map(|(gid, container)| ListRow { gid: *gid, key_cid: container.key.cid, mgid: container.key.mgid, implicated_local_cid: container.implicated_cid }).collect::<Vec<ListRow>>();
    std::mem::drop(read);

    if rows.len() != 0 {
        for row in rows {
            let username = ctx.account_manager.get_persistence_handler().get_hyperlan_peer_by_cid(row.implicated_local_cid, row.key_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.map(|r| r.username).flatten().unwrap_or_else(|| "INVALID".into());
            table.add_row(prettytable::row![c => row.gid, username, row.key_cid, row.mgid]);
        }

        printf!(table.printstd());
    } else {
        printf_ln!(colour::white!("No concurrent message groups found\n"));
    }

    Ok(None)
}

async fn handle_send<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext, cnac: &ClientNetworkAccount) -> Result<Option<Ticket>, ConsoleError> {
    let gid = usize::from_str(matches.value_of("gid").unwrap()).map_err(|err| ConsoleError::Generic(err.to_string()))?;
    // we must now map the gid to a key
    let key = ctx.message_groups.read().get(&gid).cloned().ok_or(ConsoleError::Default("Supplied GID does not map to a key"))?;
    let message: String = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
    printf_ln!(colour::white!("Will send the following message to the broadcast group ({}): {}\n", &key.key, &message));
    let username = cnac.get_username();
    let signal = GroupBroadcast::Message(username.clone(), key.key, SecBuffer::from(message.clone()));
    let request = HdpServerRequest::GroupBroadcastCommand(key.implicated_cid, signal);

    let ticket = server_remote.send(request).await?;

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