use std::sync::Arc;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering, AtomicBool};
use std::collections::HashMap;
use crate::ticket_event::{CallbackStatus, TicketQueueHandler};
use crate::kernel::{KernelSession, PeerSession};
use hyxe_net::hdp::hdp_server::{Ticket, HdpServerRemote, HdpServerRequest};
use std::path::PathBuf;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_net::hdp::state_container::VirtualConnectionType;
use crate::constants::DISCONNECT_TIMEOUT;
use std::time::Duration;
use hyxe_net::hdp::peer::peer_layer::PeerResponse;
use crate::mail::ConsoleSessionMail;
use crate::console_error::ConsoleError;
use hyxe_net::hdp::peer::channel::{PeerChannel, PeerChannelRecvHalf};
use futures_util::StreamExt;
use hyxe_net::hdp::hdp_packet_processor::includes::SecurityLevel;
use tokio::time::Instant;
use hyxe_net::hdp::peer::message_group::MessageGroupKey;
use std::sync::atomic::AtomicUsize;
use crate::ffi::KernelResponse;
use crate::command_handlers::group::MessageGroupContainer;
use crate::console::virtual_terminal::INPUT_ROUTER;
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_user::misc::CNACMetadata;

#[derive(Clone)]
pub struct ConsoleContext {
    /// The currently toggled user
    pub active_session: Arc<AtomicU64>,
    // These store long-running tickets
    pub sessions: Arc<tokio::sync::RwLock<HashMap<u64, KernelSession>>>,
    // These store short-term tickets
    pub ticket_queue: Option<TicketQueueHandler>,
    pub active_dir: Arc<RwLock<PathBuf>>,
    pub in_personal: Arc<AtomicBool>,
    pub account_manager: AccountManager,
    pub can_run: Arc<AtomicBool>,
    pub active_user: Arc<RwLock<String>>,
    pub bind_addr: Arc<String>,
    pub unread_mail: Arc<RwLock<ConsoleSessionMail>>,
    pub active_target_cid: Arc<AtomicU64>,
    pub message_groups: Arc<RwLock<HashMap<usize, MessageGroupContainer>>>,
    pub message_group_incrementer: Arc<AtomicUsize>,
    pub is_ffi: Arc<bool>
}

impl ConsoleContext {
    pub fn new(is_ffi: bool, bind_addr: String, home_path: Option<String>, account_manager: AccountManager) -> Self {
        let active_dir = Arc::new(RwLock::new(home_path.map(|path| PathBuf::from(path)).unwrap_or_else(|| dirs::home_dir().unwrap())));
        let in_stderr = Arc::new(AtomicBool::new(false));
        let can_run = Arc::new(AtomicBool::new(true));
        let nid = account_manager.get_local_nid();
        let active_user = Arc::new(RwLock::new(format!("{}", nid)));
        let unread_mail = Arc::new(RwLock::new(ConsoleSessionMail::new()));
        let bind_addr = Arc::new(bind_addr);
        let active_target_cid = Arc::new(AtomicU64::new(0));
        let message_groups = Arc::new(RwLock::new(HashMap::new()));
        let message_group_incrementer = Arc::new(AtomicUsize::new(0));
        let mut this = Self { is_ffi: Arc::new(is_ffi), message_group_incrementer, message_groups, active_target_cid, unread_mail, bind_addr, active_user, can_run, account_manager, in_personal: in_stderr, active_dir, active_session: Arc::new(AtomicU64::new(nid)), sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())), ticket_queue: None };
        let ticket_queue = TicketQueueHandler::new(this.clone());
        this.ticket_queue = Some(ticket_queue);
        this
    }

    pub fn proxy_to_ffi(&self, resp: KernelResponse) {
        let lock = super::super::ffi::ffi_entry::FFI_STATIC.lock();
        if let Some((_,_,ffi_io,_)) = lock.as_ref() {
            (ffi_io)(Ok(Some(resp)))
        }
    }

    pub async fn get_cnac_of_active_session(&self) -> Option<ClientNetworkAccount> {
        let cid = self.get_active_cid();
        if cid != 0 {
            // Previously, we use to read the cnac from the `sessions` field in self. However, this is not good since states can change when the backend is the database. Thus
            // we must instead read from the account manager to ensure we have an up to date version
            self.account_manager.get_client_by_cid(cid).await.ok().flatten()
            //Some(self.sessions.read().await.get(&cid)?.cnac.clone())
        } else {
            None
        }
    }

    pub async fn load_kernel_session(&self, kernel_session: KernelSession, channel_rx: PeerChannelRecvHalf) {
        self.set_active_cid(kernel_session.cid);
        Self::startup_channel_listener(channel_rx, kernel_session.username.clone(), self.clone());
        let mut write = self.sessions.write().await;
        write.insert(kernel_session.cid, kernel_session);
    }

    pub fn register_ticket(&self, ticket: Ticket, lifetime: Duration, implicated_cid: u64, fx: impl Fn(&ConsoleContext, Ticket, PeerResponse) -> CallbackStatus + Send + 'static) {
        let queue = self.ticket_queue.as_ref().unwrap();
        queue.register_ticket(ticket, lifetime, implicated_cid, fx)
    }

    pub fn on_ticket_received(&self, ticket: Ticket, response: PeerResponse) {
        self.ticket_queue.as_ref().unwrap().on_ticket_received(ticket, response)
    }

    /// Does not actually create a new message group with the server; it only register an entry locally
    /// Should be called after the server sends an AcceptMembership signal.
    ///
    /// Returns the local group ID
    pub fn add_message_group_local(&self, key: MessageGroupKey, implicated_cid: u64) -> usize {
        let id = self.message_group_incrementer.fetch_add(1, Ordering::SeqCst);
        let mut write = self.message_groups.write();
        write.insert(id, MessageGroupContainer::new(key, implicated_cid));
        id
    }

    /// When a session closes, some cleanup operations are necessary. For example, any groups listed in the
    /// hashmap associated with the `implicated_cid` should be removed
    pub fn on_session_dc(&self, implicated_cid: u64) {
        let mut write = self.message_groups.write();
        write.retain(|_gid, container| container.implicated_cid != implicated_cid)
    }

    pub fn remove_message_group_by_key(&self, key: MessageGroupKey) {
        let mut write = self.message_groups.write();
        let mut idx = None;
        for (entry_idx, entry) in write.iter() {
            if entry.key == key {
                idx = Some(*entry_idx);
                break
            }
        }

        if let Some(idx) = idx {
            colour::white_ln!("Successfully removed message group locally");
            assert!(write.remove(&idx).is_some());
        } else {
            colour::red_ln!("Unable to find message group locally");
        }
    }

    #[allow(unused_results)]
    pub async fn load_peer_channel_into_kernel(&self, peer_channel: PeerChannel) -> Result<(), ConsoleError> {
        let ctx = self.clone();
        let cxn_type = peer_channel.get_peer_conn_type().ok_or(ConsoleError::Default("Invalid cxn type"))?;
        let cid = cxn_type.get_original_implicated_cid();
        let peer_cid = cxn_type.get_original_target_cid();
        let peer_username = self.account_manager.get_persistence_handler().get_hyperlan_peer_by_cid(cid, peer_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))?;

        let peer_username = peer_username.map(|r| r.username).flatten().unwrap_or(String::from("INVALID"));

        let (peer_channel_tx, peer_channel_rx) = peer_channel.split();
        // loads a recv task to allow reception of data

        Self::startup_channel_listener(peer_channel_rx, peer_username, ctx);

        let peer_info = self.account_manager.get_persistence_handler().get_hyperlan_peer_by_cid(cid, peer_cid).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Mutual peer not found"))?;

        let mut write = self.sessions.write().await;
        if let Some(sess) = write.get_mut(&cid) {
            let init_time = Instant::now();
            let peer_sess = PeerSession {cxn_type, peer_info, peer_channel_tx, init_time};
            let _ = sess.concurrent_peers.insert(peer_cid, peer_sess);
            Ok(())
        } else {
            Err(ConsoleError::Generic(format!("Session {} does not exist locally", cid)))
        }
    }

    // TODO: For ffi, route events
    fn startup_channel_listener(mut peer_channel_rx: PeerChannelRecvHalf, peer_username: String, ctx: ConsoleContext) {
        tokio::task::spawn(async move {
            // this task will automatically be dropped once the underlying virtual-conn in the state container gets dropped
            // it receives an empty vec upon drop
            while let Some(message) = peer_channel_rx.next().await {
                printf_ln!(colour::yellow!("[{}]: {}\n", peer_username.as_str(), std::str::from_utf8(message.as_ref()).unwrap_or("INVALID UTF-8 MESSAGE")));
                INPUT_ROUTER.print_prompt(false, &ctx)
            }

            printf_ln!(colour::yellow!("Channel {} has disconnected\n", peer_username))
        });
    }

    pub async fn send_message_to_peer_channel(&self, cid: u64, peer_cid: u64, security_level: SecurityLevel, message: SecBuffer) -> Result<Ticket, ConsoleError> {
        let mut write = self.sessions.write().await;
        if let Some(sess) = write.get_mut(&cid) {
            if let Some(peer_sess) = sess.concurrent_peers.get_mut(&peer_cid) {
                let ticket = peer_sess.peer_channel_tx.channel_id();
                peer_sess.peer_channel_tx.set_security_level(security_level);
                peer_sess.peer_channel_tx.send_unbounded(message)
                    .map_err(|err| ConsoleError::Generic(err.to_string()))
                    .map(|_| ticket)
            } else {
                Err(ConsoleError::Generic(format!("Peer {} is not in an active channel with {}", peer_cid, cid)))
            }
        } else {
            Err(ConsoleError::Generic(format!("Session {} does not exist locally", cid)))
        }
    }

    pub async fn remove_peer_connection_from_kernel(&self, cid: u64, peer_cid: u64) -> Result<PeerSession, ConsoleError> {
        let mut write = self.sessions.write().await;
        if let Some(sess) = write.get_mut(&cid) {
            sess.concurrent_peers.remove(&peer_cid).ok_or_else(|| ConsoleError::Generic(format!("Peer {} is not connected to {}", peer_cid, cid)))
        } else {
            Err(ConsoleError::Generic(format!("Session {} does not exist locally", cid)))
        }
    }

    pub async fn list_all_sessions(&self, mut fx: impl FnMut(&KernelSession)) {
        let read = self.sessions.read().await;
        for val in read.values() {
            fx(val)
        }
    }

    pub async fn list_all_registered_users(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, ConsoleError> {
        self.account_manager.get_persistence_handler().get_clients_metadata(limit).await.map_err(|err| ConsoleError::Generic(err.into_string()))
    }

    /// Determines if a user is connected
    pub async fn user_is_connected(&self, cid: Option<u64>, username: Option<&str>) -> bool {
        let write = self.sessions.read().await;
        if let Some(cid) = cid {
            return write.values().any(|v| v.cid == cid);
        }

        if let Some(username) = username {
            return write.values().any(|v| v.username == username)
        }

        false
    }

    #[allow(unused_results)]
    pub async fn disconnect_session(&self, cid: u64, cxn_type: VirtualConnectionType, server_remote: &HdpServerRemote) -> Result<Ticket, ConsoleError> {
        let read = self.sessions.read().await;
        if let Some(sess) = read.get(&cid) {
            let username = sess.cnac.get_username();
            match cxn_type {
                VirtualConnectionType::HyperLANPeerToHyperLANServer(target_cid) => {
                    debug_assert_eq!(cid, target_cid);
                    self.send_disconnect_request(cid, Some(username), cxn_type, server_remote)
                }
                VirtualConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, peer_cid) => {
                    debug_assert_ne!(cid, peer_cid);
                    self.send_disconnect_request(cid, Some(username),cxn_type, server_remote)
                }
                VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, _target_cid) => {
                    unimplemented!()
                }
                VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, _icid) => {
                    unimplemented!()
                }
            }
        } else {
            Err(ConsoleError::Generic(format!("CID {} is not a concurrent session", cid)))
        }
    }

    #[allow(unused_results, unused_must_use)]
    pub async fn disconnect_all(&self, server_remote: &HdpServerRemote, shutdown_sequence: bool) {
        let mut write = self.sessions.write().await;
        for (cid, session) in write.drain() {
            //let username = session.cnac.get_username_blocking();
            self.send_disconnect_request(cid, None, session.virtual_cxn_type, server_remote);
        }

        if shutdown_sequence {
            self.signal_off();
        }
    }

    /// `username` should be some if resetting the print prompt is expected (should be Some when disconnecting from hypernodes over peers)
    fn send_disconnect_request(&self, cid: u64, username: Option<String>, virt_cxn_type: VirtualConnectionType, server_remote: &HdpServerRemote) -> Result<Ticket, ConsoleError> {
        let ticket = server_remote.unbounded_send(HdpServerRequest::DisconnectFromHypernode(cid, virt_cxn_type))?;
        let queue = self.ticket_queue.as_ref().unwrap();
        queue.register_ticket(ticket, DISCONNECT_TIMEOUT, cid, move |ctx,_, response| {
            match response {
                PeerResponse::Ok(_) => {
                    //printf_ln!(colour::green!("Disconnect success for {}", virt_cxn_type));
                    if let Some(ref username) = username {
                        let read = ctx.active_user.read();
                        if read.as_str() == username {
                            ctx.in_personal.store(false, Ordering::SeqCst);
                            //INPUT_ROUTER.print_prompt(false, ctx);
                        }
                    }
                }

                _ => {
                    printf_ln!(colour::red!("Disconnect fail for {}\n", virt_cxn_type));
                }
            }

            CallbackStatus::TaskComplete
        });

        Ok(ticket)
    }

    pub fn can_run(&self) -> bool {
        self.can_run.load(Ordering::Relaxed)
    }

    pub fn signal_off(&self) {
        self.can_run.store(false, Ordering::SeqCst);
    }

    pub fn get_active_cid(&self) -> u64 {
        self.active_session.load(Ordering::SeqCst)
    }

    pub fn set_active_cid(&self, next_active_cid: u64) {
        self.active_session.store(next_active_cid, Ordering::SeqCst);
    }

    pub fn get_active_target_cid(&self) -> u64 {
        self.active_target_cid.load(Ordering::SeqCst)
    }

    pub fn set_active_target_cid(&self, next_target_cid: u64) {
        self.active_target_cid.store(next_target_cid, Ordering::SeqCst)
    }
}