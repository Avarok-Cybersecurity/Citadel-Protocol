use super::imports::*;
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_user::fcm::kem::FcmPostRegister;
use hyxe_user::fcm::fcm_packet_processor::FcmProcessorResult;
use hyxe_user::fcm::data_structures::{base64_string, string, FcmTicket};
use crate::constants::{FCM_POST_REGISTER_TIMEOUT, FCM_FETCH_TIMEOUT};
use hyxe_user::prelude::Client;
use std::sync::Arc;
use hyxe_crypt::fcm::keys::FcmKeys;

#[derive(Debug, Serialize)]
pub struct PeerList {
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    is_onlines: Vec<bool>,
    #[serde(with = "string")]
    ticket: u64,
}

#[derive(Debug, Serialize)]
pub struct PeerMutuals {
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    usernames: Vec<String>,
    is_onlines: Vec<bool>,
    fcm_reachable: Vec<bool>,
    #[serde(with = "string")]
    implicated_cid: u64,
    #[serde(with = "string")]
    ticket: u64,
}

impl PeerMutuals {
    fn insert<T: Into<String>>(&mut self, cid: u64, username: T, is_online: bool, fcm_reachable: bool) {
        self.cids.push(cid);
        self.usernames.push(username.into());
        self.is_onlines.push(is_online);
        self.fcm_reachable.push(fcm_reachable);
    }
}

impl From<Ticket> for PeerList {
    fn from(ticket: Ticket) -> Self {
        Self { cids: Vec::new(), is_onlines: Vec::new(), ticket: ticket.0 }
    }
}

impl From<(Ticket, u64)> for PeerMutuals {
    fn from(this: (Ticket, u64)) -> Self {
        Self { cids: Vec::new(), usernames: Vec::new(), is_onlines: Vec::new(), fcm_reachable: Vec::new(), implicated_cid: this.1, ticket: this.0.0 }
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
    pub ticket: u64,
    pub fcm: bool,
}

#[derive(Serialize, Debug)]
pub struct PostRegisterResponse {
    #[serde(with = "string")]
    pub implicated_cid: u64,
    #[serde(with = "string")]
    pub peer_cid: u64,
    #[serde(with = "string")]
    pub ticket: u64,
    pub accept: bool,
    #[serde(with = "base64_string")]
    pub username: Vec<u8>,
    pub fcm: bool,
}

#[derive(Serialize, Debug)]
pub struct DeregisterResponse {
    #[serde(with = "string")]
    pub implicated_cid: u64,
    #[serde(with = "string")]
    pub peer_cid: u64,
    #[serde(with = "string")]
    pub ticket: u64,
    pub success: bool
}

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
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
            let use_fcm = matches.is_present("fcm");
            let security_level = parse_security_level(matches)?;

            let cnac = {
                if use_fcm {
                    ctx.account_manager.get_client_by_cid(ctx_user).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Client does not exist"))?
                } else {
                    let read = ctx.sessions.read().await;

                    let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
                    let cnac = sess.cnac.clone();
                    // must drop here, otherwise get_peer_cid_from_cnac will fail
                    std::mem::drop(read);
                    cnac
                }
            };


            let target_cid = get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid).await?;

            let message: String = matches.values_of("message").unwrap().collect::<Vec<&str>>().join(" ");
            let buf = SecBuffer::from(message);

            return if use_fcm {
                // TODO: NOTE: Due to a connection pool bug, we need to re-create the fcm client each time
                //let fcm_client = ctx.account_manager.fcm_client();
                let fcm_client = Arc::new(Client::new());
                let ticket = server_remote.get_next_ticket().0;
                let fcm_res = cnac.fcm_send_message_to(target_cid, buf, ticket, &fcm_client).await.map_err(|err| ConsoleError::Generic(err.into_string()))?;
                Ok(Some(KernelResponse::from(fcm_res)))
            } else {
                // now, use the console context to send the message
                let _ticket = ctx.send_message_to_peer_channel(ctx_user, target_cid, security_level, buf).await?;
                printf_ln!(colour::white!("Message sent through peer channel w/ {:?} security\n", security_level));
                Ok(None)
            };
        }

        if let Some(matches) = matches.subcommand_matches("disconnect") {
            let target_cid = matches.value_of("target_cid").unwrap();
            let read = ctx.sessions.read().await;

            let target_cid = get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid).await?;

            std::mem::drop(read);
            let removed_conn = ctx.remove_peer_connection_from_kernel(ctx_user, target_cid).await?;
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
            let use_fcm = matches.is_present("fcm");
            let target_cid_raw = get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid_orig).await?;

            let signal = PeerSignal::Deregister(PeerConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid_raw), use_fcm);
            let request = HdpServerRequest::PeerCommand(ctx_user, signal);

            let ticket = server_remote.unbounded_send(request)?;

            let target_cid = target_cid_raw.to_string();
            ctx.register_ticket(ticket, DISCONNECT_TIMEOUT, ctx_user, move |_ctx, _ticket, response| {
                let target_cid = target_cid.as_str();
                match response {
                    PeerResponse::ServerReceivedRequest => {
                        printf_ln!(colour::green!("Server successfully deregistered from {}\n", target_cid));
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::DeregisterResponse(DeregisterResponse { implicated_cid: ctx_user, peer_cid: target_cid_raw, ticket: ticket.0, success: true })))))
                        }
                    }

                    _ => {
                        printf_ln!(colour::red!("Unable to deregister from {}. Local node nonetheless will require re-registration with {} before sharing information\n", target_cid, target_cid));
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::DeregisterResponse(DeregisterResponse { implicated_cid: ctx_user, peer_cid: target_cid_raw, ticket: ticket.0, success: false})))))
                        }
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



            let vconn_type = if target_cid != "0" {
                let target_cid = get_peer_cid_from_cnac(&ctx.account_manager, ctx_user, target_cid).await?;
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

        if let Some(matches) = matches.subcommand_matches("list") {
            let limit = if let Some(val) = matches.value_of("limit") {
                Some(i32::from_str(val).map_err(|err| ConsoleError::Generic(err.to_string()))?)
            } else {
                None
            };

            let list_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::GetRegisteredPeers(HypernodeConnectionType::HyperLANPeerToHyperLANServer(ctx_user), None, limit));
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
            let _cnac = ctx.get_cnac_of_active_session().await.ok_or(ConsoleError::Default("Session CNAC non-existant"))?;
            let get_consented_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::GetMutuals(HypernodeConnectionType::HyperLANPeerToHyperLANServer(ctx_user), None));
            let ticket = server_remote.unbounded_send(get_consented_request)?;
            ctx.register_ticket(ticket, GET_REGISTERED_USERS_TIMEOUT, ctx_user, move |ctx, ticket, success| {
                match success {
                    PeerResponse::RegisteredCids(cids, online_status) => {
                        if let Some(ffi_io) = ffi_io.clone() {
                            let mut peer_mutuals = PeerMutuals::from((ticket, ctx_user));
                            if cids.is_empty() {
                                (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PeerMutuals(peer_mutuals)))));
                            } else {
                                let persistence_handler = ctx.account_manager.get_persistence_handler().clone();

                                let task = async move {
                                    match persistence_handler.get_hyperlan_peers_with_fcm_keys(ctx_user, &cids).await {
                                        Ok(hyperlan_peers) => {
                                            for (cid, is_online) in cids.into_iter().zip(online_status.into_iter()) {
                                                let entry = hyperlan_peers.iter().find(|peer| peer.0.cid == cid);
                                                if let Some((peer, keys)) = entry {
                                                    let username = peer.username.as_ref().map(|r|r.as_str()).unwrap_or("MISSING");
                                                    peer_mutuals.insert(cid, username, is_online, keys.is_some())
                                                } else {
                                                    log::error!("Unsynchronized peer entry! {}", cid);
                                                }
                                            }

                                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PeerMutuals(peer_mutuals)))))
                                        }

                                        Err(err) => {
                                            (ffi_io)(Ok(Some(KernelResponse::Error(ticket.0, err.into_string().into_bytes()))))
                                        }
                                    }
                                };

                                let _ = tokio::task::spawn(task);
                            }
                        } else {
                            if cids.len() != 0 {
                                let persistence_handler = ctx.account_manager.get_persistence_handler().clone();
                                let task = async move {
                                    match persistence_handler.get_hyperlan_peers(ctx_user,&cids).await {
                                        Ok(hyperlan_peers) => {
                                            log::info!("HyperLAN Peers: {:?}", &hyperlan_peers);
                                            let mut table = Table::new();
                                            table.set_titles(prettytable::row![Fgcb => "CID", "Username", "Online"]);

                                            for (cid, is_online) in cids.into_iter().zip(online_status) {
                                                let username = hyperlan_peers.iter().find(|peer| peer.cid == cid)
                                                    .map(|res| res.username.as_ref().map(|r| r.as_str())).flatten().unwrap_or("MISSING");
                                                table.add_row(prettytable::row![c => cid, username, is_online]);
                                            }

                                            colour::white!("\n\r");
                                            printf!(table.printstd());
                                        }

                                        Err(err) => {
                                            printf_ln!(colour::red!("Unable to obtain local peers: {:?}\n", err))
                                        }
                                    }
                                };

                                let _ = tokio::task::spawn(task);

                            } else {
                                printf_ln!(colour::yellow!("No other consensual users exist on the HyperLAN server\n"));
                            }
                        }
                    }

                    PeerResponse::Timeout => {
                        let resp = format!("Timeout on list ticket {}", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::Error(ticket.0, resp.into_bytes()))))
                        } else {
                            printf_ln!(colour::red!("{}\n", resp));
                        }
                    }

                    _ => {
                        let resp = format!("GetMutualPeers (ticket {}) has failed", ticket);
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::Error(ticket.0, resp.into_bytes()))))
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
            let read = ctx.sessions.read().await;
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
            let use_fcm = matches.is_present("fcm");
            let fcm = matches.is_present("fcm").then(|| FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let username = ctx.active_user.read().clone();
            let target_cid = u64::from_str(target).map_err(|_err| ConsoleError::Default("Registration: CID only"))?;

            let ref cnac = ctx.get_cnac_of_active_session().await.ok_or_else(|| ConsoleError::Generic(format!("ClientNetworkAccount not loaded. Check program logic")))?;

            if ctx.account_manager.get_persistence_handler().hyperlan_peer_exists(ctx_user, target_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))? {
                return Err(ConsoleError::Generic(format!("Peer {} is already consented to connect with {}", target_cid, username.as_str())));
            }

            if use_fcm {
                if cnac.fcm_hyperlan_peer_registration_pending(target_cid) {
                    return Err(ConsoleError::Generic(format!("Peer {} has already received an invitation", target_cid)))
                }
            }

            let post_register_request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(ctx_user, target_cid), username, None, None, fcm));
            let ticket = server_remote.unbounded_send(post_register_request)?;

            let timeout = if use_fcm { FCM_POST_REGISTER_TIMEOUT } else { POST_REGISTER_TIMEOUT };

            // if using FCM, we still need to register here to subscribe to error events. The FCM processor can call upon this after processing to remove the raw ticket from the queue
            ctx.register_ticket(ticket, timeout, target_cid, move |_ctx, ticket, response| {
                #[allow(unused_assignments)]
                let mut return_err = None;
                let res = match response {
                    PeerResponse::ServerReceivedRequest => {
                        printf_ln!(colour::white!("Hypernode received the request; awaiting for peer to accept registration ...\n"));
                        return CallbackStatus::TaskPending;
                    }

                    PeerResponse::Decline => {
                        return_err = Some(format!("Client {} did not accept your request", target_cid));
                        colour::red_ln!("Client {} did not accept your request\n", target_cid);
                        CallbackStatus::TaskComplete
                    }

                    PeerResponse::Accept(Some(username)) => {
                        // note: FCM will never reach here
                        printf_ln!(colour::white!("Peer {} ({}) has accepted your invitation! You may now connect to their node\n", &username, target_cid));

                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::PostRegisterResponse(PostRegisterResponse {
                                implicated_cid: ctx_user,
                                peer_cid: target_cid,
                                ticket: ticket.0,
                                accept: true,
                                username: username.into_bytes(),
                                fcm: use_fcm,
                            })))))
                        }

                        return CallbackStatus::TaskComplete;
                    }

                    PeerResponse::Err(err_opt) => {
                        printfs!({
                            colour::red_ln!("\rPeer {} was unable to handle your registration", target_cid);
                            if let Some(err) = err_opt.as_ref() {
                                colour::red_ln!("{}", &err);
                            }
                            println!();
                        });

                        return_err = err_opt;
                        CallbackStatus::TaskComplete
                    }

                    PeerResponse::Timeout => {
                        printf_ln!(colour::red!("Timeout on post-register ticket {}\n", ticket));
                        return_err = Some("Timeout on the post-register request".to_string());
                        CallbackStatus::TaskComplete
                    }

                    _ => {
                        printf_ln!(colour::red!("PostRegister (ticket {}) was unable to complete\n", ticket));
                        return_err = Some("Post-register request general error".to_string());
                        CallbackStatus::TaskComplete
                    }
                };

                // if we get here, request failed
                if let Some(ref ffi_io) = ffi_io {
                    let err_bytes = return_err.map(|res| res.into_bytes()).unwrap_or(Vec::from("Registration failed"));
                    let resp = if use_fcm { KernelResponse::FcmError(FcmTicket::new(ctx_user, target_cid, ticket.0), err_bytes) } else { KernelResponse::Error(ctx_user, err_bytes) };
                    (ffi_io)(Ok(Some(resp)))
                }

                res
            });

            return if use_fcm {
                Ok(Some(KernelResponse::ResponseFcmTicket(FcmTicket::new(ctx_user, target_cid, ticket.0))))
            } else {
                Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
            };


        }

        if let Some(matches) = matches.subcommand_matches("post-connect") {
            let target = matches.value_of("target_cid").unwrap();
            let security_level = parse_security_level(matches)?;
            let read = ctx.sessions.read().await;
            let sess = read.get(&ctx_user).ok_or(ConsoleError::Default("Session missing"))?;
            let acc_mgr = &ctx.account_manager;

            let target_cid = get_peer_cid_from_cnac(acc_mgr,ctx_user, target).await?;

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


        let accept_register_matches = matches.subcommand_matches("accept-register");
        let deny_register_matches = matches.subcommand_matches("deny-register");
        if accept_register_matches.is_some() || deny_register_matches.is_some() {
            let accept = accept_register_matches.is_some();
            let matches = accept_register_matches.unwrap_or_else(|| deny_register_matches.unwrap());
            let use_fcm = matches.is_present("fcm");

            let mail_id_target = matches.value_of("mail_id").unwrap();
            let is_numeric = mail_id_target.chars().all(|val| char::is_numeric(val));
            if !is_numeric {
                return Err(ConsoleError::Default("The Mail ID must contain a numeric-only sequence"));
            }

            let mail_id = usize::from_str(mail_id_target).map_err(|err| ConsoleError::Generic(err.to_string()))?;

            return if use_fcm {
                let cnac = ctx.get_cnac_of_active_session().await.ok_or(ConsoleError::Default("Active session CNAC absent"))?;
                let (fcm_post_register, ticket_id) = cnac.fcm_prepare_accept_register(mail_id as u64, accept).await.map_err(|err| ConsoleError::Generic(err.into_string()))?;
                let fcm_post_register = if accept { fcm_post_register } else { FcmPostRegister::Decline };
                let ticket = ticket_id.into();
                let username = accept.then(|| cnac.get_username());
                let response = PeerResponse::Accept(username.clone());
                let vconn = PeerConnectionType::HyperLANPeerToHyperLANPeer(cnac.get_cid(), mail_id as u64);
                // TODO: Get rid of redundant use of username
                let outbound_request = HdpServerRequest::PeerCommand(cnac.get_cid(), PeerSignal::PostRegister(vconn, username.unwrap_or("DECLINED".to_string()), Some(ticket), Some(response), fcm_post_register));
                server_remote.send_with_custom_ticket(ticket, outbound_request).map_err(|err| ConsoleError::Generic(err.into_string()))?;

                Ok(Some(KernelResponse::ResponseFcmTicket(FcmTicket::new(mail_id as u64, ctx_user, ticket.0))))
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
                    let ctx_username = if accept { ctx.account_manager.get_username_by_cid(implicated_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Implicated CID of request not found"))? } else { "DECLINED".to_string() };

                    let ticket = request.get_ticket_assert_register().unwrap();

                    if accept {
                        let peer_username = request.assert_register_get_username().unwrap();
                        log::info!("Registering peer username: {:?}", &peer_username);
                        // TODO: Pull this down to the networking layer to take the responsibility off the kernel (will need to relay peer_username ... )
                        ctx.account_manager.register_hyperlan_p2p_at_endpoints(implicated_cid, peer_cid, &peer_username).await.map_err(|err| ConsoleError::Generic(err.into_string()))?;
                    }

                    let response = if accept { PeerResponse::Accept(Some(ctx_username.clone())) } else { PeerResponse::Decline };
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
            };
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
            };
        }
        /*
                    .subcommand(SubCommand::with_name("update-fcm-keys").about("Updates the FCM keys for the active CID")
                .arg(Arg::with_name("fcm-token")
                    .long("fcm-token")
                    .help("If supplied, the following parameter must be the client FCM registration ID correlated to the CNAC")
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("fcm-api-key")
                    .long("fcm-api-key")
                    .help("If supplied, the following parameter must be the API key for the application")
                    .takes_value(true)
                    .required(true)))
         */
        if let Some(matches) = matches.subcommand_matches("update-fcm-keys") {
            let fcm_token = matches.value_of("fcm-token").unwrap();
            let fcm_api_key = matches.value_of("fcm-api-key").unwrap();
            let fcm_keys = FcmKeys::new(fcm_api_key, fcm_token);
            let request = HdpServerRequest::PeerCommand(ctx_user, PeerSignal::FcmTokenUpdate(fcm_keys));
            let ticket = server_remote.unbounded_send(request)?;

            ctx.register_ticket(ticket, FCM_FETCH_TIMEOUT, ctx_user, move |_,_, signal| {
                match signal {
                    PeerResponse::ServerReceivedRequest => {
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::ResponseTicket(ticket.0))))
                        } else {
                            printf!(colour::green!("\rServer successfully updated FCM keys for {}\n", ctx_user));
                        }
                    }

                    _ => {
                        if let Some(ref ffi_io) = ffi_io {
                            (ffi_io)(Ok(Some(KernelResponse::Error(ticket.0, Vec::from("Unable to update FCM keys")))))
                        } else {
                            printf!(colour::red!("\rUnable to update FCM keys for {}\n", ctx_user));
                        }
                    }
                }

                CallbackStatus::TaskComplete
            });

            return Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
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