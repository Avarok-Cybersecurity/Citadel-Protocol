//! In order for the over-the-wire registration process to work (voids warranty, but allows great flexibility in the network), encryption is necessary.
//! The encryption is automatically handled by the [ConnectionHandle]'s TLS streams. This encryption, however, uses cryptographic standard set by the
//! NIST which use very large eliptical curves with particular deformations... this graph is a domain very well studied by the cryptographers in the
//! NIST, and as such, more than likely contains a backdoor at the mathematical level. Modern TLS encryption is backdoored at a level lower than software
//! and hardware: the mathematical level... as such, the warranty is voided when using over-the-wire registration. TODO: Long-term, find a new solution
use std::net::IpAddr;
use futures::sync::mpsc::{UnboundedSender, Sender};
use tokio_threadpool::Sender as ThreadPoolSender;

use crate::connection::stream_wrappers::old::OutboundItem;
use crate::packet::misc::ConnectError;
use crate::packet::inbound::stage_driver::StageDriverHandle;
use crate::connection::connection::ConnectionHandle;
use crate::connection::temporary_bridge::TemporaryBridge;
use hyxe_netdata::packet::StageDriverPacket;
use crate::connection::network_map::NetworkMap;
use hyxe_user::account_manager::AccountManager;
use chashmap::CHashMap;
use std::time::Instant;
use crate::packet::definitions::registration::{STAGE0_SERVER, STAGE1_SERVER, REGISTRATION_FAILURE};
use crate::packet::definitions::{PREFER_IPV6, PINNED_IP_MODE};
use hyxe_user::network_account::NetworkAccount;
use std::io::BufRead;
use hyxe_user::misc::check_credential_formatting;
use std::pin::Pin;
use hyxe_user::client_account::ClientNetworkAccount;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use crate::connection::registration::registration_process::RegistrationProcess;

/// The registration process is as follows:
pub struct RegistrationHandler<'cxn, 'bridge: 'cxn, 'server: 'bridge> {
    /// When a registration signal is sent from a particular IP, we must ensure that this source is not spamming requests. By enforcing 1-ip at a time,
    /// we can help reduce the pressure from registration attacks
    current_processes: CHashMap<IpAddr, Pin<Box<RegistrationProcess>>>,
    /// Used for injecting expectancies into the [StageDriver]
    stage_driver_handle: StageDriverHandle<'cxn, 'bridge, 'server>,
    thread_pool: ThreadPoolSender,
    /// Needed to produce CNACs
    local_nac: NetworkAccount
}

impl RegistrationHandler {
    /// Creates a new [RegistrationHandler]
    pub fn new(threadpool_sender: ThreadPoolSender, stage_driver_handle: StageDriverHandle, local_nac: NetworkAccount) -> Self {
        Self { current_processes: CHashMap::new(), stage_driver_handle, thread_pool: threadpool_sender, local_nac }
    }

    /// Processes a registration signal. The [ServerBridgeHandler] should by the only caller of this. It is expected that the ip provided is NOT an active
    /// connection. This subroutine will place the tubing within a new temporary [BridgeHandler] which will be discarded invariantly to a successful or
    /// unsuccessful registration.
    ///
    /// I enforce `&mut self` to ensure exclusive access, even though the underlying hashmap allows concurrent modifications
    pub fn process_stage0_server_registration_signal(&self, peer_addr: IpAddr, stream_outbound_tx: UnboundedSender<OutboundItem>, stream_signal_tx: Sender<u8>) -> Result<(), ConnectError> {
        // What is guaranteed at this point: The peer_addr does not exist as a concurrent connection. Now, we have to check to ensure this addr is not concurrently executing
        // a registration request
        if !self.current_processes.contains_key(&peer_addr) {
            // No registration is concurrently executing, and as such, we can proceed
            // We add the bridge for now to allow for later communication
            let temp_bridge = TemporaryBridge::new(stream_outbound_tx, stream_signal_tx);

            let prev = self.current_processes.insert(peer_addr, RegistrationProcess::new(temp_bridge, false, None));
            debug_assert!(prev.is_none());
            // At this point, the higher-level [ServerBridgeHandler] must handle packets forwarded internally via the [StageDriver], and then send the packets
            // to Self for further processing. We have the ability to communicate with the stream, which is necessary for the process. There is no need for
            // expectancies, because the [StageDriver] will specifically look for the registration packet header
            Ok(())
        } else {
            Err(ConnectError::ConcurrentRegistrationExecuting)
        }
    }
    
    /// Whereas the first stage simply injects the tubing into a compactified bridge (i.e., a [TemporaryBridge]), we still have not yet
    /// received the first packet. This stage processes the very first packet, and happen typically instantly after stage 0 finished executing
    /// 
    /// The first packet has been received, and the server has sent a notification with a nonce to the client
    /// that the request has been accepted; however, the server is now busy generating the f(0) drill, and as
    /// such, must await. The client is expected to create an expectancy for the transmission of the f(0) object
    pub fn process_stage1_server_registration_signal(&self, packet: StageDriverPacket, account_manager: &AccountManager, network_map: &NetworkMap) -> Result<(), ConnectError> {
        // If PINNED_IP_MODE is enabled, check to see that the IP address doesn't already belong to a registered user
        let ip = packet.get_sender().ip();

        match self.current_processes.get_mut(&ip) {
            Some(mut process) => {
                match account_manager.get_client_by_addr(&ip, PREFER_IPV6) {
                    Some(cnac) => {
                        if PINNED_IP_MODE {
                            let msg = format!("[RegistrationHandler] [E] Server uses PIM, and pre-existing user is already registered under {}", ip);
                            return Err(ConnectError::Generic(msg))
                        }
                        // While multiple logins per session is not allowed, multiple registrations under the same IP address IS allowed
                    },

                    None => {}
                }
                
                self.stage1_server_generate_cnac(process.as_mut(), &packet, account_manager)
            },

            None => {
                Err(ConnectError::Generic("[RegistrationHandler] [E] Process does not exist".to_string()))
            }
        }
    }

    /// Asynchronously performs stage 1 for the server
    #[allow(unused_results)]
    fn stage1_server_generate_cnac(&self, process: Pin<&mut RegistrationProcess>, packet: &StageDriverPacket, account_manager: &AccountManager) -> Result<(), ConnectError> {
        if process.semaphore.load(SeqCst) {
            // Possible packet spamming
            return Err(ConnectError::ConcurrentRegistrationExecuting)
        } else {
            // Lock the process in case of a packet spammer
            process.semaphore.store(true, SeqCst);
        }
        
        let parts = packet.get_payload().to_str().unwrap_or("").split(",").collect::<Vec<&str>>();

        if parts.len() != 4 {
            return Err(ConnectError::Generic("[RegistrationHandler] [E] Improperly formatted payload (bad parts length)".to_string()))
        }

        let (is_hyperwan_server, username, password, full_name) = (parts[0], parts[1], parts[2], parts[3]);

        if is_hyperwan_server != "0" && is_hyperwan_server != "1" {
            return Err(ConnectError::Generic("[RegistrationHandler] [E] Improperly formatted payload (is_hyperlan_server)".to_string()))
        }

        match check_credential_formatting(username, password, full_name) {
            Err(err) => return Err(ConnectError::Generic(err.to_string())),
            _ => {}
        }

        let nac = NetworkAccount::new_from_recent_connection(packet.get_sender().ip());
        let proc_ptr = &mut *process as *mut RegistrationProcess;
        
        self.thread_pool.spawn(move || unsafe {
            let proc_mut = &mut *proc_ptr;
            match self.local_nac.create_client_account(Some(nac), is_hyperwan_server == "1", username, password, full_name).await {
                Ok(cnac) => {
                    debug_assert!(proc_mut.generated_cnac.is_none());
                    proc_mut.generated_cnac.replace(cnac);
                    proc_mut.last_finished_state = STAGE1_SERVER;
                    
                    proc_mut.bridge.send()
                },

                Err(err) => {
                    eprintln!("[RegistrationHandler] [E] Unable to create CNAC. Reason: {}", err.to_string());
                    proc_mut.last_finished_state = REGISTRATION_FAILURE;
                }
            }
            
            // We are done with the mutable pointer; allow future uses by turning it off
            proc_mut.semaphore.store(false, SeqCst);
            Ok(())
        }).map_err(|err| ConnectError::Generic(err.to_string()))
    }

    /// Sends data outbound to a specific ip address, if the ip address exists
    pub fn send<T: AsRef<[u8]>>(&mut self, peer_addr: &IpAddr, msg: &T) -> Result<(), ConnectError> {
        match self.current_processes.get_mut(peer_addr) {
            Some(temp_bridge) => {
                temp_bridge.bridge.send(msg)
            },
            
            None => Err(ConnectError::None)
        }
    }
    
    /// Sends a shutdown signal to a particular stream, but does not send any signal outbound to the connecting node
    /// (only a local shutdown)
    pub fn shutdown_stream<T: AsRef<[u8]>>(&mut self, peer_addr: &IpAddr, msg: Option<&T>) -> Result<(), ConnectError> {
        match self.current_processes.get_mut(peer_addr) {
            Some(mut temp_bridge) => {
                if let Some(msg) = msg {
                    let _ = temp_bridge.bridge.send(msg);
                }

                temp_bridge.bridge.shutdown()
            },
            
            None => {
                Err(ConnectError::None)
            }
        }
    }
} 