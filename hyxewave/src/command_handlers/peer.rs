use super::imports::*;
use hyxe_user::client_account::HYPERLAN_IDX;
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_user::fcm::kem::FcmPostRegister;
use hyxe_user::fcm::fcm_packet_processor::FcmProcessorResult;
use hyxe_user::fcm::data_structures::{base64_string, string};

#[derive(Debug, Serialize)]
pub struct PeerList {
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    is_onlines: Vec<bool>,
    #[serde(with = "string")]
    ticket: u64
}

impl From<Ticket> for PeerList {
    fn from(ticket: Ticket) -> Self {
        Self { cids: Vec::new(), is_onlines: Vec::new(), ticket: ticket.0 }
    }
}

#[derive(Serialize, Debug)]
pub struct PostRegisterRequest {
    #[serde(with = "string")]
    pub mail_id: u64,
    #[serde(with = "base64_string")]
    pub username: Vec<u8>,
    #[serde(with = "string")]
    pub peer_cid: u64,
    #[serde(with = "string")]
    pub implicated_cid: u64,
    #[serde(with = "string")]
    pub ticket: u64
}

#[derive(Serialize, Debug)]
pub struct PostRegisterResponse {
    #[serde(with = "string")]
    ticket: u64,
    accept: bool,
    #[serde(with = "base64_string")]
    username: Vec<u8>
}

pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let ctx_user = ctx.get_active_cid();

    if ctx_user != 0 {
        if let Some(matches) = matches.subcommand_matches("mail") {
            let mail_cmd = matches.value_of("mail_cmd").unwrap();
            match mail_cmd {
                "print" => {
                    let mut requests = Table::new();
                    let read = ctx.unread_mail.read();
                    requests.set_titles(prettytable::row![Fgcb => "Mail ID", "Request Type", "CID", "Username", "HyperLAN/WAN", "Age (s)"]);
                    let mut count = 0;
                    read.visit_requests(|mail_id, request| {
                        log::info!("visiting mail element {}", mail_id);
                        count += 1;
                        match request {
                            IncomingPeerRequest::Connection(_ticket, conn, recv_time, _endpoint_security_level) => {
                                match conn {
                                    PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
                                        requests.add_row(prettytable::row![c => mail_id, "Connection", *implicated_cid, "", "hLAN", recv_time.elapsed().as_secs()]);
                                    }

                                    PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, _target_cid) => {
                                        requests.add_row(prettytable::row![c => mail_id, "Connection", *implicated_cid, "", format!("hWAN ({})", *icid), recv_time.elapsed().as_secs()]);
                                    }
                                }
                            }

                            IncomingPeerRequest::Register(_ticket, username, conn, recv_time, _) => {
                                match conn {
                                    PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
                                        requests.add_row(prettytable::row![c => mail_id, "Register", *implicated_cid, username, "hLAN", recv_time.elapsed().as_secs()]);
                                    }

                                    PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, _target_cid) => {
                                        requests.add_row(prettytable::row![c => mail_id, "Register", *implicated_cid, username, format!("hWAN ({})", *icid), recv_time.elapsed().as_secs()]);
                                    }
                                }
                            }
                        }
                    });

                    if count != 0 {
                        printf!(requests.printstd());
                    } else {
                        printf_ln!(colour::yellow!("No peer mail for {} currently available\n", ctx_user));
                    }
                }

                "clear" => {
                    ctx.unread_mail.write().clear_mail();
                    printf_ln!(colour::yellow!("Cleared mailbox for all local sessions\n"));
                }

                _ => {
                    log::error!("mail command not accounted for");
                }
            }

            return Ok(None);
        }

        if let Some(matches) = matches.subcommand_matches("send") {
            let target_cid = matches.value_of("target_cid").unwrap();

            let security_level = parse_security_level(matches)?;

            let read = ctx.sessions.read();

            let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
            let cnac = sess.cnac.clone();
            // must drop here, otherwise get_peer_cid_from_cnac will fail
            std::mem::drop(read);

            let target_cid = get_peer_cid_from_cnac(&cnac, target_cid)?;

            let message: String = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
            let buf = SecBuffer::from(message);

            return if matches.is_present("fcm") {
                let fcm_client = ctx.account_manager.fcm_client();
                //let callback = ffi_io.map(|ffi_io| fcm_callback(ffi_io)).unwrap_or_else(fcm_console_callback);

                //let ticket = cnac.background_fcm_send_message_to(target_cid, buf, fcm_client, callback).map_err(|err| ConsoleError::Generic(err.into_string()))?;
                //Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Fcm(FcmResponse::MessageSent(ticket)))))
                let fcm_res = cnac.blocking_fcm_send_to(target_cid, buf, fcm_client).map_err(|err| ConsoleError::Generic(err.into_string()))?;
                Ok(Some(KernelResponse::from(fcm_res)))
            } else {
                // now, use the console context to send the message
                let _ticket = ctx.send_message_to_peer_channel(ctx_user, target_cid, security_level, buf)?;
                printf_ln!(colour::white!("Message sent through peer channel w/ {:?} security\n", security_level));
                Ok(None)
            }
        }

        if let Some(matches) = matches.subcommand_matches("fcm-parse") {
            let json_input: String = matches.values_of("input").unwrap().collect::<Vec<&str>>().join(" ");
            log::info!("[FCM] json input: {}", &json_input);
            let res = hyxe_user::fcm::fcm_packet_processor::blocking_process(json_input, &ctx.account_manager);
            log::info!("[FCM] Done parsing json");
            return Ok(Some(res.into()))
        }

        if let Some(matches) = matches.subcommand_matches("disconnect") {
            let target_cid = matches.value_of("target_cid").unwrap();
            let read = ctx.sessions.read();
            let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
            let ref cnac = sess.cnac;

            let target_cid = get_peer_cid_from_cnac(cnac, target_cid)?;

            std::mem::drop(read);
            let removed_conn = ctx.remove_peer_connection_from_kernel(ctx_user, target_cid)?;
            // now that the connection is removed locally, let's alert the server
            let signal = PeerSignal::Disconnect(removed_conn.cxn_type, None);
            let request = HdpServerRequest::PeerCommand(ctx_user, signal);

            let ticket = server_remote.unbounded_send(request)?;

            ctx.register_ticket(ticket, DISCONNECT_TIMEOUT, ctx_user, move |_ctx, _ticket, response| {
                match response {
                    PeerResponse::Ok(_) => {
                        printf_ln!(colour::green!("Disconnect from peer {} success!\n", target_cid));
                    }

                    PeerResponse::Err(err) => {
                        printfs!({
                            colour::red_ln!("\rUnable to fully disconnect from {}. However, the local session will require re-connection to send/receive information", target_cid);
                            if let Some(err) = err {
                                colour::red_ln!("Message: {}", &err);
                            }

                            println!()
                        });
                    }

                    _ => {}
                }

                CallbackStatus::TaskComplete
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(matches) = matches.subcommand_matches("deregister") {
            let target_cid_orig = matches.value_of("target_cid").unwrap();
            let ref cnac = ctx.get_cnac_of_active_session().ok_or(ConsoleError::Generic(format!("Context CNAC doesn't exist")))?;
            let target_cid = get_peer_cid_from_cnac(cnac, target_cid_orig)?;

            let signal = PeerSignal::Deregister(PeerConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid));
            let request = HdpServerRequest::PeerCommand(ctx_user, signal);
            let ticket = server_remote.unbounded_send(request)?;

            // the below is safe to unwrap since the existence is implies by the get_peer_cid_from_cnac
            let _ = cnac.remove_hyperlan_peer(target_cid).unwrap();

            let target_cid = target_cid.to_string();
            ctx.register_ticket(ticket, DISCONNECT_TIMEOUT, ctx_user, move |_ctx, _ticket, response| {
                let target_cid = target_cid.as_str();
                match response {
                    PeerResponse::ServerReceivedRequest => {
                        printf_ln!(colour::green!("Server successfully deregistered from {}\n", target_cid))
                    }

                    _ => {
                        printf_ln!(colour::red!("Unable to deregister from {}. Local node nonetheless will require re-registration with {} before sharing information\n", target_cid, target_cid));
                    }
                }

                CallbackStatus::TaskComplete
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(matches) = matches.subcommand_matches("transfer") {
            let target_cid = matches.value_of("target_cid").unwrap();
            let file_path = matches.values_of("file_path").unwrap().collect::<Vec<&str>>().join(" ");
            let (path, _) = super::os::cd::canonicalize_relative(ctx, file_path)?;
            // check to see that the path points to an existent file
            //let path = PathBuf::from_str(file_path.as_str()).map_err(|err| ConsoleError::Generic(err.to_string()))?;

            if !path.is_file() {
                return Err(ConsoleError::Generic(format!("{} is not a file", path.display())));
            }

            let read = ctx.sessions.read();

            let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
            let ref cnac = sess.cnac.clone();
            std::mem::drop(read);

            let vconn_type = if target_cid != "0" {
                let target_cid = get_peer_cid_from_cnac(cnac, target_cid)?;
                VirtualConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid)
            } else {
                VirtualConnectionType::HyperLANPeerToHyperLANServer(ctx_user)
            };

            let chunk_size = matches.value_of("chunk_size").map(|val| usize::from_str(val).unwrap_or(0));

            if let Some(chunk_size) = chunk_size.as_ref() {
                if *chunk_size < 1024 {
                    return Err(ConsoleError::Default("Invalid chunk size specified"));
                }
                printfs!({
                    colour::white!("File transfer type: {:?}\n", &vconn_type);
                    colour::yellow!("Custom chunk size: {} bytes\n", chunk_size);
                });
            } else {
                printf_ln!(colour::white!("File transfer type: {:?}\n", &vconn_type));
            }

            let request = HdpServerRequest::SendFile(path, chunk_size, ctx_user, vconn_type);
            let ticket = server_remote.unbounded_send(request)?;

            // TODO: Register callback to monitor for download state changes, interacting with FFI_IO, etc

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(_matches) = matches.subcommand_matches("list") {
            let list_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::GetRegisteredPeers(HypernodeConnectionType::HyperLANPeerToHyperLANServer(ctx_user), None));
            let ticket = server_remote.unbounded_send(list_request)?;
            ctx.register_ticket(ticket, GET_REGISTERED_USERS_TIMEOUT, ctx_user, move |_, ticket, response| {
                match response {
                    PeerResponse::RegisteredCids(cids, online_status) => {
                        // at least one user exists (the context user!)
                        if let Some(ref ffi_io) = ffi_io {
                            let mut peer_list = PeerList::from(ticket);
                            for (cid, is_online) in cids.into_iter().zip(online_status.into_iter()).filter(|(cid, _)| *cid != ctx_user) {
                                peer_list.cids.push(cid);
                                peer_list.is_onlines.push(is_online);
                            }

                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PeerList(peer_list)))))
                        } else {
                            if cids.len() > 1 {
                                let mut table = Table::new();
                                table.set_titles(prettytable::row![Fgcb => "CID", "Online"]);

                                for (cid, is_online) in cids.into_iter().zip(online_status) {
                                    if cid != ctx_user {
                                        table.add_row(prettytable::row![c => cid, is_online]);
                                    }
                                }

                                colour::white!("\n\r");
                                printf!(table.printstd());
                            } else {
                                printf_ln!(colour::yellow!("No other registered users exist on the HyperLAN server\n"));
                            }
                        }
                    }

                    PeerResponse::Timeout => {
                        let resp = format!("Timeout on list ticket {}", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::ResponseHybrid(ticket.0, resp.into_bytes()))))
                        } else {
                            printf_ln!(colour::red!("{}\n", resp));
                        }
                    }

                    _ => {
                        let resp = format!("GetRegisteredPeers (ticket {}) has failed", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::ResponseHybrid(ticket.0, resp.into_bytes()))))
                        } else {
                            printf_ln!(colour::red!("{}\n", resp));
                        }
                    }
                }

                CallbackStatus::TaskComplete
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(_matches) = matches.subcommand_matches("mutuals") {
            let get_consented_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::GetMutuals(HypernodeConnectionType::HyperLANPeerToHyperLANServer(ctx_user), None));
            let ticket = server_remote.unbounded_send(get_consented_request)?;
            ctx.register_ticket(ticket, GET_REGISTERED_USERS_TIMEOUT, ctx_user, move |ctx, ticket, success| {
                match success {
                    PeerResponse::RegisteredCids(cids, online_status) => {
                        // at least one user exists (the context user!)
                        if let Some(ref ffi_io) = ffi_io {
                            let mut peer_list = PeerList::from(ticket);
                            for (cid, is_online) in cids.into_iter().zip(online_status.into_iter()) {
                                peer_list.cids.push(cid);
                                peer_list.is_onlines.push(is_online);
                            }

                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PeerList(peer_list)))))
                        } else {
                            if cids.len() != 0 {
                                let _: Option<()> = ctx.account_manager.visit_cnac(ctx_user, move |cnac| {
                                    cnac.visit(move |cnac| {
                                        if let Some(hyperlan_peers) = cnac.mutuals.get_vec(&HYPERLAN_IDX) {
                                            let mut table = Table::new();
                                            table.set_titles(prettytable::row![Fgcb => "CID", "Username", "Online"]);

                                            for (cid, is_online) in cids.into_iter().zip(online_status) {
                                                let username = hyperlan_peers.iter().find(|peer| peer.cid == cid)
                                                    .map(|res| res.username.clone().unwrap_or_default()).unwrap_or_default();
                                                table.add_row(prettytable::row![c => cid, &username, is_online]);
                                            }

                                            colour::white!("\n\r");
                                            printf!(table.printstd());
                                        } else {
                                            printf_ln!(colour::red!("Server returned a set of HyperLAN peers, but was not synced locally. Report to developers\n"))
                                        }

                                        None
                                    })
                                });
                            } else {
                                printf_ln!(colour::yellow!("No other consensual users exist on the HyperLAN server\n"));
                            }
                        }
                    }

                    PeerResponse::Timeout => {
                        let resp = format!("Timeout on list ticket {}", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::ResponseHybrid(ticket.0, resp.into_bytes()))))
                        } else {
                            printf_ln!(colour::red!("{}\n", resp));
                        }
                    }

                    _ => {
                        let resp = format!("GetMutualPeers (ticket {}) has failed", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::ResponseHybrid(ticket.0, resp.into_bytes()))))
                        } else {
                            printf_ln!(colour::red!("{}\n", resp));
                        }
                    }
                }

                CallbackStatus::TaskComplete
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(_matches) = matches.subcommand_matches("channels") {
            // get the current context's session
            let ctx_username = ctx.active_user.read().clone();
            let read = ctx.sessions.read();
            return if let Some(sess) = read.get(&ctx_user) {
                if sess.concurrent_peers.len() != 0 {
                    let mut peers = Table::new();
                    peers.set_titles(prettytable::row![Fgcb => "Peer ID", "Username", "VConn type", "Age (s)"]);
                    let iter = sess.concurrent_peers.iter();
                    for (peer_cid, peer_sess) in iter {
                        let peer_username = peer_sess.peer_info.username.clone().unwrap_or_default();
                        peers.add_row(prettytable::row![c => peer_cid, peer_username, peer_sess.cxn_type,  peer_sess.init_time.elapsed().as_secs()]);
                    }

                    printf!(peers.printstd());
                } else {
                    printf_ln!(colour::yellow!("No concurrent virtual connection with user {}\n", ctx_username));
                }

                Ok(None)
            } else {
                Err(ConsoleError::Generic(format!("Peer {} is not in an active session", ctx_user)))
            };
        }

        if let Some(matches) = matches.subcommand_matches("post-register") {
            // This ONLY accepts u64s, and NOT usernames.
            let target = matches.value_of("target_cid").unwrap();
            let fcm = matches.is_present("fcm").then(||FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let username = ctx.active_user.read().clone();
            let target_cid = u64::from_str(target).map_err(|_err| ConsoleError::Default("Registration: CID only"))?;

            let ref cnac = ctx.get_cnac_of_active_session().ok_or_else(|| ConsoleError::Generic(format!("ClientNetworkAccount not loaded. Check program logic")))?;
            if cnac.hyperlan_peer_exists(target_cid) {
                return Err(ConsoleError::Generic(format!("Peer {} is already consented to connect with {}", target_cid, username.as_str())));
            }

            let post_register_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid), username, None, None, fcm));
            let ticket = server_remote.unbounded_send(post_register_request)?;
            ctx.register_ticket(ticket, POST_REGISTER_TIMEOUT, target_cid, move |ctx, ticket, response| {
                let res = match response {
                    PeerResponse::ServerReceivedRequest => {
                        printf_ln!(colour::white!("Hypernode received the request; awaiting for peer to accept registration ...\n"));
                        return CallbackStatus::TaskPending
                    }

                    PeerResponse::Accept(username) => {
                        // TODO: Make the enums cleaner.
                        let username = username.unwrap();

                        // TODO: pull this down to the networking layer to take responsibility off the kernel
                        if let Err(err) = ctx.account_manager.register_hyperlan_p2p_at_endpoints(ctx_user, target_cid, username.clone()) {
                            printf_ln!(colour::red!("Peer {} ({}) accepted your invitation, but we were unable to sync to the local filesystem. Reason: {:?}\n", &username, target_cid, err));
                        } else {
                            printf_ln!(colour::white!("Peer {} ({}) has accepted your invitation! You may now connect to their node\n", &username, target_cid));
                        }

                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PostRegisterResponse(PostRegisterResponse {
                                ticket: ticket.0,
                                accept: true,
                                username: username.into_bytes()
                            })))))
                        }

                        return CallbackStatus::TaskComplete
                    }

                    PeerResponse::Err(err_opt) => {
                        printfs!({
                            colour::red_ln!("\rPeer {} was unable to handle your registration", target_cid);
                            if let Some(err) = err_opt {
                                colour::red_ln!("{}", &err);
                            }
                            println!();
                        });

                        CallbackStatus::TaskComplete
                    }

                    PeerResponse::Timeout => {
                        printf_ln!(colour::red!("Timeout on post-register ticket {}\n", ticket));
                        CallbackStatus::TaskComplete
                    }

                    _ => {
                        printf_ln!(colour::red!("PostRegister (ticket {}) was unable to complete\n", ticket));
                        CallbackStatus::TaskComplete
                    }
                };

                // if we get here, request failed
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PostRegisterResponse(PostRegisterResponse {
                        ticket: ticket.0,
                        accept: false,
                        username: Vec::with_capacity(0)
                    })))))
                }

                res
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(matches) = matches.subcommand_matches("post-connect") {
            let target = matches.value_of("target_cid").unwrap();
            let security_level = parse_security_level(matches)?;
            let read = ctx.sessions.read();
            let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
            let ref cnac = sess.cnac;

            let target_cid = get_peer_cid_from_cnac(cnac, target)?;

            //check to see if the session doesn't already exist
            if sess.concurrent_peers.contains_key(&target_cid) {
                return Err(ConsoleError::Generic(format!("Peer {} is already connected to {}", target_cid, ctx_user)));
            }

            let post_connect_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid), None, None, security_level));
            let ticket = server_remote.unbounded_send(post_connect_request)?;
            ctx.register_ticket(ticket, POST_REGISTER_TIMEOUT, ctx_user, move |_ctx, ticket, response| {
                match response {
                    PeerResponse::Accept(welcome_message_opt) => {
                        printfs!({
                            colour::green!("\rSuccessfully forged connection between {} <-> {}. You may now engage in message-passing", ctx_user, target_cid);
                            if let Some(welcome_message) = welcome_message_opt {
                                colour::green_ln!("Welcome message: {}", &welcome_message);
                            }
                            println!()
                        });

                        CallbackStatus::TaskComplete
                    }

                    PeerResponse::ServerReceivedRequest => {
                        printf!(colour::white!("\rServer received request for post-connect ticket {}\n", ticket));
                        CallbackStatus::TaskPending
                    }

                    PeerResponse::Err(err_message_opt) => {
                        printf!(colour::red!("\rPostConnect (ticket {}) denied. Reason: {:?}\n", ticket, &err_message_opt));
                        CallbackStatus::TaskComplete
                    }

                    PeerResponse::Timeout => {
                        printf!(colour::red!("\rTimeout on post-connect ticket {}\n", ticket));
                        CallbackStatus::TaskComplete
                    }

                    _ => {
                        printf!(colour::magenta!("\rUnknown post-connect signal received\n"));
                        CallbackStatus::TaskComplete
                    }
                }
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)));
        }

        if let Some(matches) = matches.subcommand_matches("accept-register") {
            let use_fcm = matches.is_present("fcm");

            let mail_id_target = matches.value_of("mail_id").unwrap();
            let is_numeric = mail_id_target.chars().all(|val| char::is_numeric(val));
            if !is_numeric {
                return Err(ConsoleError::Default("The Mail ID must contain a numeric-only sequence"));
            }

            let mail_id = usize::from_str(mail_id_target).map_err(|err| ConsoleError::Generic(err.to_string()))?;

            return if use_fcm {
                let cnac = ctx.get_cnac_of_active_session().ok_or(ConsoleError::Default("Active session CNAC absent"))?;
                let fcm_post_register = cnac.fcm_prepare_accept_register(mail_id as u64, true).map_err(|err| ConsoleError::Generic(err.into_string()))?;
                let username = cnac.get_username();
                let response = PeerResponse::Accept(Some(username.clone()));
                let vconn = PeerConnectionType::HyperLANPeerToHyperLANPeer(cnac.get_cid(), mail_id as u64);
                let outbound_request = HdpServerRequest::PeerCommand(cnac.get_cid(), PeerSignal::PostRegister(vconn, username, None, Some(response), fcm_post_register));
                let ticket = server_remote.unbounded_send(outbound_request).map_err(|err| ConsoleError::Generic(err.into_string()))?;

                Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
            } else {
                let mut write = ctx.unread_mail.write();
                if let Some(request) = write.remove_request(mail_id) {
                    if !request.is_register() {
                        write.incoming_requests.insert(mail_id, request);
                        return Err(ConsoleError::Generic(format!("Mail item {} is not a registration request type", mail_id)));
                    }

                    // Registration accept is VALID. Now, register p2p locally
                    // we get the implicated_cid below, since the order has not yet been reversed
                    let peer_cid = request.get_implicated_cid();
                    let implicated_cid = request.get_target_cid();
                    let ctx_username = ctx.account_manager.get_username_by_cid(implicated_cid).ok_or(ConsoleError::Default("Implicated CID of request not found"))?;
                    let peer_username = request.assert_register_get_username().unwrap();
                    let ticket = request.get_ticket_assert_register().unwrap();
                    // TODO: Pull this down to the networking layer to take the responsiblity off the kernel
                    ctx.account_manager.register_hyperlan_p2p_at_endpoints(implicated_cid, peer_cid, &peer_username).map_err(|err| ConsoleError::Generic(err.into_string()))?;

                    // we MUST provide the username below
                    let response = PeerResponse::Accept(Some(ctx_username.clone()));
                    // this handles the flipping of the signal
                    let outbound_request = request.prepare_response_assert_register(response, ctx_username).unwrap();
                    // now, send the signal outbound and we are good to go
                    let peer_request = HdpServerRequest::PeerCommand(implicated_cid, outbound_request);
                    // use the same ticket
                    server_remote.send_with_custom_ticket(ticket, peer_request)?;
                    colour::white_ln!("Registration consent request sent back to peer");
                    // No registering tickets needed since this is just a registration request
                    Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
                } else {
                    Err(ConsoleError::Generic(format!("Mail ID {} does not map to a mail item", mail_id)))
                }
            }
        }

        if let Some(matches) = matches.subcommand_matches("accept-connect") {
            let mail_id_target = matches.value_of("mail_id").unwrap();
            let is_numeric = mail_id_target.chars().all(|val| char::is_numeric(val));
            if !is_numeric {
                return Err(ConsoleError::Default("The Mail ID must contain a numeric-only sequence"));
            }

            let mail_id = usize::from_str(mail_id_target).map_err(|err| ConsoleError::Generic(err.to_string()))?;
            let mut write = ctx.unread_mail.write();
            return if let Some(request) = write.remove_request(mail_id) {
                if !request.is_connect() {
                    write.incoming_requests.insert(mail_id, request); // put back in (TWSS)
                    return Err(ConsoleError::Generic(format!("Mail item {} is not a connection request type", mail_id)));
                }

                // NOTE: it is possible that ctx_user != implicated CID
                // also, it isn't flipped yet
                let implicated_cid = request.get_target_cid();
                let welcome_message = matches.value_of("welcome_message").map(|val| val.to_string());

                let ticket = request.get_ticket_assert_connect().unwrap();

                let response = PeerResponse::Accept(welcome_message);
                // this handles the flipping of the signal
                let outbound_request = request.prepare_response_assert_connection(response).unwrap();
                let peer_request = HdpServerRequest::PeerCommand(implicated_cid, outbound_request);
                server_remote.send_with_custom_ticket(ticket, peer_request)?;
                colour::white_ln!("Connection consent request sent back to peer\n");
                Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
            } else {
                Err(ConsoleError::Generic(format!("Mail ID {} does not map to a mail item", mail_id)))
            }
        }

        Ok(None)
    } else {
        Err(ConsoleError::Default("No currently active users. Please connect, or use 'switch <user>' if already logged-in"))
    }
}

#[allow(dead_code)]
fn fcm_callback(ffi_io: FFIIO) -> Box<dyn FnOnce(FcmProcessorResult) + Send + 'static> {
    Box::new(move |res| {
        (ffi_io)(Ok(Some(res.into())))
    })
}

#[allow(dead_code)]
fn fcm_console_callback() -> Box<dyn FnOnce(FcmProcessorResult) + Send + 'static> {
    Box::new(|result| {
        log::info!("FCM Console: Result {:?}", result)
    })
}