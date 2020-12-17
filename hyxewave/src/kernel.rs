use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::pin::Pin;

use async_trait::async_trait;
use std::sync::atomic::AtomicBool;
use futures_util::future::Future;
use futures_util::stream::FuturesUnordered;
use futures_util::TryStreamExt;
use tokio::net::TcpListener;
use tokio::stream::StreamExt;
use tokio::time::Instant;

use hyxe_net::error::NetworkError;
use hyxe_net::hdp::hdp_packet_processor::includes::SocketAddr;
use hyxe_net::hdp::hdp_packet_processor::peer::group_broadcast::{GroupBroadcast, MemberState};
use hyxe_net::hdp::hdp_server::{HdpServerRemote, HdpServerResult, Ticket};
use hyxe_net::hdp::peer::channel::PeerChannelSendHalf;
use hyxe_net::hdp::peer::peer_layer::{PeerConnectionType, PeerResponse, PeerSignal};
use hyxe_net::hdp::peer::peer_layer::MailboxTransfer;
use hyxe_net::hdp::state_container::VirtualConnectionType;
use hyxe_net::kernel::kernel::NetKernel;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::{ClientNetworkAccount, MutualPeer};

use crate::app_config::AppConfig;
use crate::command_handlers::disconnect::DisconnectResponse;
use crate::console::console_context::ConsoleContext;
use crate::console::virtual_terminal::{INPUT_ROUTER, terminal_future};
use crate::console_error::ConsoleError;
use crate::constants::INVALID_UTF8;
use crate::ffi::{DomainResponse, FFIIO, KernelResponse};
use crate::mail::IncomingPeerRequest;
use crate::ticket_event::TicketQueueHandler;
use hyxe_net::functional::IfEqConditional;

#[allow(dead_code)]
pub struct CLIKernel {
    remote: Option<HdpServerRemote>,
    loopback_pipe_addr: Option<SocketAddr>,
    app_config: AppConfig,
    console_context: ConsoleContext,
    file_transfer_in_progress: AtomicBool,
}

impl CLIKernel {
    /// If a user starts off by connecting, initial_cid should be set. Otherwise, supply None
    pub async fn new(app_config: AppConfig, account_manager: AccountManager) -> Self {
        let loopback_pipe_addr = app_config.pipe.clone();
        let home_addr = app_config.home_dir.clone();
        let is_ffi = app_config.is_ffi;
        let file_transfer_in_progress = AtomicBool::new(false);
        Self { file_transfer_in_progress, remote: None, loopback_pipe_addr, console_context: ConsoleContext::new(is_ffi, app_config.local_bind_addr.clone().unwrap().ip().to_string(), home_addr, account_manager), app_config }
    }

    /// Returns true if the ticket was removed, false otherwise. If false, the ticket may have expired, or, it was never input
    /// Also runs the function
    pub fn on_ticket_received(&self, ticket: Ticket, response: PeerResponse) {
        self.console_context.on_ticket_received(ticket, response)
    }

    pub fn on_ticket_received_opt(&self, ticket: Option<Ticket>, response: PeerResponse) {
        if let Some(ticket) = ticket {
            self.console_context.on_ticket_received(ticket, response)
        }
    }

    pub fn load_new_kernel_session(&self, kernel_session: KernelSession) {
        self.console_context.load_kernel_session(kernel_session)
    }

    /// Returns the username, or, CID if not found
    fn get_username_display(&self, cid: u64) -> String {
        self.console_context.account_manager.get_username_by_cid(cid).unwrap_or_else(|| format!("{}", cid))
    }

    /// Returns the username, or, CID if not found
    fn get_peer_username_display(&self, implicated_cid: u64, peer_cid: u64) -> String {
        self.console_context.account_manager.visit_cnac(implicated_cid, |cnac| {
            cnac.get_hyperlan_peer(peer_cid).map(|res| res.username.unwrap_or(INVALID_UTF8.to_string()))
        }).unwrap_or_else(|| format!("{}", peer_cid))
    }

    /// Sometimes, this function is called after a disconnect_all. When that function is called,
    /// all the sessions are drained, and thus once disconnect status returns get sent to this kernel,
    /// the sessions won't be present. Thus, we must check the can_ran variable in the console context
    pub fn unload_kernel_session(&self, cid: u64) {
        if self.console_context.can_run() {
            self.console_context.on_session_dc(cid);
            let mut write = self.console_context.sessions.write();
            if let None = write.remove(&cid) {
                //colour::red_ln!("Attempted to remove session {}, but it did not exist in the sessions map", cid);
            }

            let (next_ctx_username, next_ctx) = if write.len() != 0 {
                let first = write.values().collect::<Vec<&KernelSession>>()[0];
                (first.username.clone(), first.cid)
            } else {
                self.console_context.in_personal.store(false, std::sync::atomic::Ordering::SeqCst);
                ("admin".to_string(), 0)
            };
            // replace the username
            std::mem::drop(write);
            *self.console_context.active_user.write() = next_ctx_username;
            self.console_context.active_session.store(next_ctx, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl NetKernel for CLIKernel {
    async fn on_start(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        log::info!("CLI/FFI Kernel executed!");

        let ffi_io = self.app_config.ffi_io.take();
        let daemon_mode = self.app_config.daemon_mode;

        let cli_future = terminal_ticket_and_loopback_future(self.console_context.ticket_queue.clone().unwrap(), self.loopback_pipe_addr.clone(), ffi_io, server_remote.clone(), self.console_context.clone(), daemon_mode);
        self.remote = Some(server_remote);
        // spawn on threadpool
        tokio::task::spawn(cli_future);

        Ok(())
    }

    #[allow(unused_variables)]
    async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        // print a line to ensure spaces between event print-outs, even if there's none (to prevent double printout on single line)
        if !self.file_transfer_in_progress.load(std::sync::atomic::Ordering::Relaxed) {
            colour::white_ln!("\r");
        }

        match message {
            HdpServerResult::PeerChannelCreated(ticket, channel) => {
                // send a [PeerResponse] of Ok to the ticket-tracker
                let cid = channel.get_implicated_cid();
                let peer_cid = channel.get_peer_cid();
                if let Err(err) = self.console_context.load_peer_channel_into_kernel(channel) {
                    printf_ln!(colour::red!("Unable to load channel into kernel: {}", err.into_string()));
                    return Ok(());
                }

                printf!(colour::green!("\rPeer channel {} created! (Peer: {})\n", ticket, peer_cid));
                self.on_ticket_received(ticket, PeerResponse::Accept(None))
            }

            HdpServerResult::FileTransferStatus(implicated_cid, key, _ticket, status) => {
                if status.is_tick_type() {
                    colour::yellow!("{}", status);
                    // ensure that the prompt doesn't print
                    return Ok(());
                } else {
                    colour::yellow_ln!("File transfer {} [{} -> {}] status: {}", key.object_id, implicated_cid, key.target_cid, status);
                    if status.is_finished_type() {
                        // non-tick, finished => signal for end of file transfer
                        self.file_transfer_in_progress.store(false, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        // non-tick, non-finished type => we should signal for file transfer
                        self.file_transfer_in_progress.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            HdpServerResult::GroupEvent(implicated_cid, ticket, signal) => {
                log::info!("Received group signal {:?}", &signal);
                match &signal {
                    GroupBroadcast::Disconnected(key) => {
                        self.console_context.remove_message_group_by_key(*key)
                    }

                    GroupBroadcast::EndResponse(key, _) => {
                        self.console_context.remove_message_group_by_key(*key)
                    }

                    GroupBroadcast::LeaveRoomResponse(key, success, response) => {
                        self.console_context.remove_message_group_by_key(*key)
                    }

                    GroupBroadcast::Invitation(key) => {
                        let mid = self.console_context.unread_mail.write().on_group_request_received(implicated_cid, ticket, *key);
                        let cmd = format!("group accept-invite {}", mid);
                        printfs!({
                            colour::green!("\nGroup invitation received for {:?}\nType ", key);
                            colour::yellow!("{} [shift-tab] ", &cmd);
                            colour::green!("to accept the group invitation\n");
                        });

                        INPUT_ROUTER.register_tab_action(cmd);
                    }

                    GroupBroadcast::Message(username, key, message) => {
                        printfs!({
                            colour::yellow!("\n[{}@{}:{}]: ", username, key.cid, key.mgid);
                            colour::white!("{}\n", message);
                        });
                    }

                    GroupBroadcast::MemberStateChanged(key, state) => {
                        match state {
                            MemberState::EnteredGroup(peers) => {
                                printf_ln!(colour::green!("{:?} entered the room\n", peers.iter().map(|cid| self.get_peer_username_display(implicated_cid, *cid)).collect::<Vec<String>>()));
                            }

                            MemberState::LeftGroup(peers) => {
                                printf_ln!(colour::yellow!("{:?} left the room\n", peers.iter().map(|cid| self.get_peer_username_display(implicated_cid, *cid)).collect::<Vec<String>>()));
                            }
                        }
                    }

                    _ => {}
                }

                self.on_ticket_received(ticket, PeerResponse::Group(signal))
            }

            // FFI Handled below
            HdpServerResult::InternalServerError(ticket, err) => {
                printf_ln!(colour::red!("\nInternal Server Error: {}\n", err));
                self.on_ticket_received_opt(ticket, PeerResponse::Err(Some(err.clone())));
                //return Err(NetworkError::Generic(err))

                if self.console_context.is_ffi {
                    self.console_context.proxy_to_ffi(KernelResponse::Error(ticket.unwrap_or(Ticket(0)).0, err.clone()))
                }

                // if the error relates to the HdpServer crashing, close the kernel immediately
                if self.remote.as_ref().unwrap().is_closed() {
                    return Err(NetworkError::Generic(err));
                }
            }

            // FFI handler is built-in to the ticket callback
            HdpServerResult::RegisterOkay(ticket, _cnac, message) => {
                self.on_ticket_received(ticket, PeerResponse::Ok(Some(String::from_utf8(message).unwrap_or(String::from("Invalid UTF-8 message")))));
            }

            // FFI Handler built-in to the ticket callback
            HdpServerResult::RegisterFailure(ticket, err) => {
                if !self.console_context.is_ffi {
                    printfs!({
                        colour::white!("\nRegistration for ticket {}", ticket);
                        colour::red!(" FAILED!\n\n");
                        colour::white_ln!("Server Message: {}\n\n", err);
                    });
                }

                self.on_ticket_received(ticket, PeerResponse::Err(Some(err)));
            }

            HdpServerResult::DeRegistration(vconn, ticket, is_personal, status) => {
                if !is_personal {
                    printf_ln!(colour::yellow!("Deregistration of {:?} was {}\n", self.get_username_display(vconn.get_implicated_cid()), status.if_eq(true, "successful").if_false("not successful")));
                } else {
                    let resp = status.if_eq(true, PeerResponse::Ok(None)).if_false(PeerResponse::Err(None));
                    self.on_ticket_received_opt(ticket, resp);
                }
                self.unload_kernel_session(vconn.get_implicated_cid());
            }

            // FFI handler built-in to the ticket callback
            HdpServerResult::ConnectSuccess(ticket, cid, ip_addr, is_personal, virtual_cxn_type, message) => {
                self.on_ticket_received(ticket, PeerResponse::Ok(Some(message)));
                let cnac = self.console_context.account_manager.get_client_by_cid(cid).unwrap();
                let username = cnac.get_username();
                if !is_personal {
                    printf!(colour::green!("Connection to hypernode {} ({}) forged\n", cid, &username));
                }

                match virtual_cxn_type {
                    VirtualConnectionType::HyperLANPeerToHyperLANServer(cid) => {
                        self.load_new_kernel_session(KernelSession::new(cnac, cid, ip_addr, username, is_personal, virtual_cxn_type));
                    }

                    _ => {}
                }
            }

            // FFI Handles this in the callback
            HdpServerResult::ConnectFail(ticket, cid, reason) => {
                self.on_ticket_received(ticket, PeerResponse::Err(Some(reason)));
            }

            HdpServerResult::OutboundRequestRejected(ticket, reason_opt) => {
                printfs!({
                    colour::white!("\nOutbound request for ticket {}", ticket);
                    colour::red!(" REJECTED!\n\n");
                });

                let resp = reason_opt.map(|reason|
                    PeerResponse::Err(Some(String::from_utf8(reason).unwrap_or(String::from(INVALID_UTF8)))))
                    .unwrap_or(PeerResponse::Err(None));


                self.on_ticket_received(ticket, resp);
            }

            // FFI Handled below
            HdpServerResult::MessageDelivery(ticket, cid, data) => {
                // NOTE: This data should only be delivered if sent if there is n=1 hop. Otherwise,
                // channels are used
                let message = String::from_utf8(data.into_buffer()).unwrap_or(String::from(INVALID_UTF8));
                if self.console_context.is_ffi {
                    self.console_context.proxy_to_ffi(KernelResponse::NodeMessage(ticket.0, cid, 0, 0, message));
                } else {
                    colour::white!("Server message[{}]: ", cid);
                    colour::yellow!("{}\n", message);
                }
            }

            // TODO: FFI should be handled within ticket callback
            HdpServerResult::Disconnect(ticket, cid, _success, _cxn_type, dc_message) => {
                printf_ln!(colour::yellow!("Session for {} disconnected", self.get_username_display(cid)));
                self.on_ticket_received(ticket, PeerResponse::Ok(Some(dc_message)));
                // A disconnect implies a connection occurred. As such, it is necessary the below not return an error, implying it is necessary that
                // a session loaded, UNLESS there is a bug still in the server-level that sends a DISCONNECT instead of a CONNECT_FAIL
                self.unload_kernel_session(cid);
                if self.console_context.is_ffi {
                    self.console_context.proxy_to_ffi(KernelResponse::DomainSpecificResponse(DomainResponse::Disconnect(DisconnectResponse::HyperLANPeerToHyperLANServer(ticket.0, cid))));
                } else {
                    printf_ln!(colour::yellow!("{} sessions left\n", self.console_context.sessions.read().len()));
                }
            }

            HdpServerResult::PeerEvent(signal, ticket) => {
                match signal {
                    PeerSignal::GetRegisteredPeers(conn, resp_opt) => {
                        self.on_ticket_received(ticket, resp_opt.unwrap_or(PeerResponse::empty_registered()));
                    }

                    PeerSignal::GetMutuals(conn, resp_opt) => {
                        self.on_ticket_received(ticket, resp_opt.unwrap_or(PeerResponse::empty_registered()));
                    }

                    PeerSignal::SignalReceived(ticket) => {
                        self.on_ticket_received(ticket, PeerResponse::ServerReceivedRequest)
                    }

                    PeerSignal::PostRegister(conn, username, ticket, response) => {
                        process_post_register_signal(self, conn, username, ticket, response, true)
                    }

                    PeerSignal::PostConnect(conn, ticket, response) => {
                        process_post_connect_signal(self, conn, ticket, response, true)
                    }

                    PeerSignal::SignalError(ticket, err) => {
                        self.on_ticket_received(ticket, PeerResponse::Err(Some(err)))
                    }

                    PeerSignal::Deregister(conn) => {
                        if let Some(peer) = self.console_context.account_manager.visit_cnac(conn.get_original_target_cid(), |cnac| cnac.remove_hyperlan_peer(conn.get_original_implicated_cid())) {
                            printf_ln!(colour::yellow!("Peer {} ({}) deregistered from {}", peer.username.unwrap_or_default(), peer.cid, conn.get_original_target_cid()));
                        } else {
                            printf_ln!(colour::red!("Unable to deregister peer {} from {}", conn.get_original_implicated_cid(), conn.get_original_target_cid()));
                        }

                        match self.console_context.remove_peer_connection_from_kernel(conn.get_original_target_cid(), conn.get_original_implicated_cid()) {
                            Ok(peer_sess) => {
                                printf_ln!(colour::yellow!("Removed peer session {} from {}", peer_sess.peer_info.username.unwrap_or_default(), conn.get_original_target_cid()));
                            }

                            Err(err) => {
                                printf_ln!(colour::red!("Unable to remove peer sess {} from {} ({})", conn.get_original_implicated_cid(), conn.get_original_target_cid(), err.into_string()));
                            }
                        }

                        self.on_ticket_received(ticket, PeerResponse::ServerReceivedRequest);
                    }

                    PeerSignal::Disconnect(peer_conn, resp) => {
                        // on the flight back, resp will always be none if our DC request is being confirmed by the server
                        // However, resp will always be Some if we are getting notified that the other peer disconnected from us
                        if let Some(resp) = resp {
                            match resp {
                                PeerResponse::Disconnected(dc_msg) => {
                                    printf_ln!(colour::yellow!("Peer disconnected: {}\n", &dc_msg));
                                    // finally, remove the connection
                                    let peer_conn = peer_conn.reverse();
                                    match peer_conn {
                                        PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                                            // disconnect
                                            if let Err(err) = self.console_context.remove_peer_connection_from_kernel(implicated_cid, target_cid) {
                                                printf_ln!(colour::red!("Unable to remove peer connection {} <-> {}. Reason: {}\n", target_cid, implicated_cid, err.into_string()));
                                            }
                                        }

                                        PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                                            unimplemented!("HyperWAN functionality not yet implemented")
                                        }
                                    }
                                }

                                _ => {}
                            }
                        } else {
                            // in this case, we are awaiting a response from the server
                            self.on_ticket_received(ticket, PeerResponse::Ok(None))
                        }
                    }

                    _ => {
                        self.on_ticket_received(ticket, PeerResponse::None);
                    }
                }
            }

            HdpServerResult::MailboxDelivery(implicated_cid, ticket_opt, delivery) => {
                match delivery {
                    MailboxTransfer::Signals(signals) => {
                        printfs!({
                            colour::green!("\n\rMailbox delivery for {}. Total items: {}. ", implicated_cid, signals.len());
                            colour::white!("Execute ");
                            colour::yellow!("peer mail print ");
                            colour::white!("to view the mail\n");
                        });

                        for signal in signals {
                            match signal {
                                PeerSignal::PostConnect(conn, ticket, response) => {
                                    process_post_connect_signal(self, conn, ticket, response, false)
                                }

                                PeerSignal::PostRegister(peer_conn, peer_username, ticket, response) => {
                                    process_post_register_signal(self, peer_conn, peer_username, ticket, response, false)
                                }

                                _ => {
                                    log::warn!("Unsupported mailbox signal received");
                                }
                            }
                        }
                    }
                }
            }
        }

        if !self.app_config.daemon_mode {
            INPUT_ROUTER.print_prompt(false, &self.console_context);
        }

        Ok(())
    }

    fn can_run(&self) -> bool {
        true
    }

    async fn on_stop(&self) -> Result<(), NetworkError> {
        self.console_context.signal_off();
        Ok(())
    }
}

fn process_post_connect_signal(this: &CLIKernel, conn: PeerConnectionType, ticket: Option<Ticket>, response: Option<PeerResponse>, do_print: bool) {
    // if we get a response, it means that this node's connection attempt with conn succeeded
    // else we don't get a response, it means that this node RECEIVED an INVITATION to connect
    if let Some(response) = response {
        // we don't add the connection here; we do when we receive the channel
        this.on_ticket_received_opt(ticket, response);
    } else {
        if let Some(ticket) = ticket {
            let peer_cid = conn.get_original_implicated_cid();
            let this_cid = conn.get_original_target_cid();
            let username = this.console_context.account_manager.visit_cnac(this_cid, |cnac| -> Option<String> {
                cnac.get_hyperlan_peer(peer_cid)?.username.clone()
            });
            let username = username.unwrap_or(String::from("INVALID"));
            // now, store the mail that way the next call to peer accept-request can work
            let mail_id = this.console_context.unread_mail.write().on_peer_request_received(IncomingPeerRequest::Connection(ticket, conn, Instant::now()));
            let cmd = format!("peer accept-connect {}", mail_id);
            if do_print {
                printfs!({
                    colour::green!("You have received an invitation to mutually connect with {} ({}). Execute ", peer_cid, username);
                    colour::yellow!("{} [shift + tab] ", &cmd);
                    colour::green!("to consent to the connection\n");
                });
            }

            INPUT_ROUTER.register_tab_action(cmd);
        } else {
            log::error!("Received an empty ticket from {:?}\n", conn);
        }
    }
}

fn process_post_register_signal(this: &CLIKernel, conn: PeerConnectionType, username: String, ticket: Option<Ticket>, response: Option<PeerResponse>, do_print: bool) {
    // if we get a response, it means that this node's connection attempt with conn succeeded
    // else we don't get a response, it means that this node RECEIVED an INVITATION to register
    if let Some(response) = response {
        this.on_ticket_received_opt(ticket, response)
    } else {
        // by the internal logic, `ticket` should always be Some!
        if let Some(ticket) = ticket {
            let peer_cid = conn.get_original_implicated_cid();
            // now, store the mail that way the next call to peer accept-request can work
            let mail_id = this.console_context.unread_mail.write().on_peer_request_received(IncomingPeerRequest::Register(ticket, username.clone(), conn, Instant::now()));
            let cmd = format!("peer accept-register {}", mail_id);
            if do_print {
                printfs!({
                    colour::green!("You have received an invitation to mutually register with {} ({}). Execute ", &username, peer_cid);
                    colour::yellow!("{} [shift + tab] ", &cmd);
                    colour::green!("to consent to the connection\n");
                });
            }

            INPUT_ROUTER.register_tab_action(cmd);
        } else {
            log::error!("Received an empty ticket from {:?}", conn);
        }
    }
}

pub struct KernelSession {
    pub cnac: ClientNetworkAccount,
    pub cid: u64,
    pub username: String,
    pub ip_addr: SocketAddr,
    pub is_personal: bool,
    pub tickets: HashSet<Ticket>,
    pub init_time: Instant,
    pub virtual_cxn_type: VirtualConnectionType,
    pub concurrent_peers: HashMap<u64, PeerSession>,
}

#[allow(dead_code)]
pub struct PeerSession {
    pub(crate) cxn_type: PeerConnectionType,
    pub(crate) peer_info: MutualPeer,
    pub(crate) peer_channel_tx: PeerChannelSendHalf,
    pub(crate) init_time: Instant,
}

impl KernelSession {
    pub fn new(cnac: ClientNetworkAccount, cid: u64, ip_addr: SocketAddr, username: String, is_personal: bool, virtual_cxn_type: VirtualConnectionType) -> Self {
        let concurrent_peers = HashMap::new();
        Self { cnac, virtual_cxn_type, username, cid, ip_addr, is_personal, tickets: HashSet::new(), init_time: Instant::now(), concurrent_peers }
    }

    pub fn elapsed_time_seconds(&self) -> u64 {
        self.init_time.elapsed().as_secs()
    }

    pub fn elapsed_time_minutes(&self) -> f32 {
        (self.elapsed_time_seconds() as f64 / 60f64) as f32
    }
}

async fn loopback_future(tcp_addr: Option<SocketAddr>) -> Result<(), ConsoleError> {
    if let Some(tcp_addr) = tcp_addr {
        printf_ln!(colour::yellow!("Creating loopback address on {}:{}", tcp_addr.ip(), tcp_addr.port()));
        let mut listener = TcpListener::bind(tcp_addr).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
        while let Some(inbound) = listener.incoming().next().await {
            match inbound {
                Ok(_stream) => {
                    // TODO: When data comes inbound, figure out a way to universally parse it. Then, send it as a command, get the ticket, and correlate the ticket
                    // to the socket address that this stream is connected to. You will need to use channels to accomplish this
                }

                Err(err) => {
                    log::error!("{}", err.to_string())
                }
            }
        }
    }

    Ok(())
}

#[allow(unused_results)]
async fn terminal_ticket_and_loopback_future(ticket_queue_handler: TicketQueueHandler, loopback_pipe_addr: Option<SocketAddr>, ffi_io: Option<FFIIO>, server_remote: HdpServerRemote, ctx: ConsoleContext, daemon_mode: bool) {
    let unordered = FuturesUnordered::<Pin<Box<dyn Future<Output=Result<(), ConsoleError>> + Send>>>::new();
    if let Some(ffi_io) = ffi_io {
        (ffi_io)(Ok(Some(KernelResponse::Message(String::from("Asynchronous kernel running. FFI Static is about to be set")))));
        let ctx = ctx.clone();
        let server_remote = server_remote.clone();
        let handle = tokio::runtime::Handle::current();
        // set this, that way the ffi can run a command later
        let _ = crate::ffi::ffi_entry::FFI_STATIC.lock().replace((ctx, server_remote, ffi_io, handle));
        //unordered.push(Box::pin(super::ffi::command_handler::ffi_future(server_remote, ctx, ffi_io.receiver, ffi_io.to_ffi_frontier)))
    } else {
        if !daemon_mode {
            unordered.push(Box::pin(terminal_future(server_remote, ctx)));
        }
    }

    let loopback_future = loopback_future(loopback_pipe_addr);
    let ticket_handler_future = ticket_handler_future(ticket_queue_handler);

    unordered.push(Box::pin(loopback_future));
    unordered.push(Box::pin(ticket_handler_future));

    let _ = unordered.try_collect::<Vec<()>>().await;

    log::warn!("Kernel ending ...");
    std::process::exit(0);
}

async fn ticket_handler_future(mut ticket_queue_handler: TicketQueueHandler) -> Result<(), ConsoleError> {
    while let Some(_) = ticket_queue_handler.next().await {
        black_box(())
    }

    Err(ConsoleError::Default("Ticket handler died"))
}