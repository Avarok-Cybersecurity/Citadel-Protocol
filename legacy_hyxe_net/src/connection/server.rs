use std::time::Instant;
use hyxe_user::network_account::NetworkAccount;
use hyxe_user::account_loader::{load_node_nac, load_cnac_files};
use std::collections::HashMap;
use crate::connection::session::Session;
use crate::packet::inbound::stage_driver::{StageDriver, StageDriverPacket};
use tokio_threadpool::{ThreadPool, Sender};
use crate::file_loader::load_local_network_map;
use crate::connection::stream_wrappers::old::RawInboundItem;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender, Receiver};
use futures::Stream;
use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::drill::{Drill, DrillStandard};
use std::mem::MaybeUninit;
use std::pin::Pin;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_fs::io::FsError;
use hyxe_user::hypernode_account::HyperNodeAccountInformation;
use time::now_utc;
use crate::connection::network_map::NetworkMap;
use std::option::NoneError;
use std::ptr::null;
use hyxe_netdata::packet::StageDriverPacket;
use async_std::future::Future;
use crate::connection::session_manager::SessionManager;
use hyxe_user::account_manager::AccountManager;
use crate::packet::misc::ConnectError;
use crate::connection::server_bridge_handler::ServerBridgeHandler;
use parking_lot::RwLock;

lazy_static! {
    pub static ref SERVER_UP: RwLock<bool> = RwLock::new(false);
}

/// Manages multiple streams of data, including multiple protocol types, for all possible local connections, for all possible locally-stored network accounts.
///
/// This is the highest-level core networking type available within hyxewave. Whereas before, I differentiated between client and server nodes,
/// I now hold the two within a single type to help establish the concept that any node can be a "central server" simultaneous to being a client.
pub struct Server<'cxn, 'driver: 'cxn, 'server: 'driver> where Self: 'server {
    /// The `stage_driver` is what drives packets to completion and listens for unique packet eid_oid's. At each poll(), packets are filtered
    stage_driver: Pin<Box<StageDriver<'cxn, 'driver, 'server>>>,
    /// The `server_bridge_handler` must be pinned to the heap
    server_bridge_handler: Pin<Box<ServerBridgeHandler<'cxn, 'driver, 'server>>>,
    account_manager: AccountManager,
    /// This is the NAC associated with this node
    local_network_account: NetworkAccount,
    /// The global threadpool for async computation
    thread_pool: Sender,
    /// For debugging and uptime
    init_time: Instant
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> Server<'cxn, 'driver, 'server> where Self: 'server {
    /// Creates a new server instance. This will panic if it cannot create a local network account. This will panic if it cannot create a
    /// network map either. This will return an error if it cannot load any client network accounts
    pub async fn new(thread_pool: Sender) -> Result<Server<'cxn, 'driver, 'server>, FsError<String>> {
        if *SERVER_UP.read() {
            return Err(FsError::Generic("Server already running".to_string()))
        }

        match AccountManager::new().await {
            Ok(account_manager) => {
                let local_network_account = account_manager.get_local_nac();

                let stage_driver_to_session_tubes = unbounded(); // We use channels instead of Arc-RwLocks to prevent contention
                let (stream_to_stage_driver_tx, stream_to_stage_driver_rx) = unbounded();
                let stage_driver = StageDriver::new(local_network_account.get_id(), stream_to_stage_driver_rx,stage_driver_to_session_tubes.0, &account_manager);
                let stage_driver_handle = stage_driver.create_atomic_handle();
                let server_bridge_handler = ServerBridgeHandler::new(thread_pool.clone(), stage_driver_handle, stream_to_stage_driver_tx.clone(), stage_driver_to_session_tubes.1, account_manager.get_local_nac(), network_map.clone(), account_manager.clone());

                let mut this = Self { stage_driver, server_bridge_handler, account_manager, local_network_account, thread_pool, init_time: Instant::now() };

                Ok(this)
            },

            Err(err) => {
                Err(err)
            }
        }
    }

    /// Runs the server by selecting both the [StageDriver] and the [ServerBridgeHandler] together. The remote controls the
    /// [ServerBridgeHandler]; since we select() these futures together, once, the [ServerBridgeHandler] exits, so does the
    /// [StageDriver]. As for restarting the system, the [StageDriver] does not need to be restart as its input streams
    /// are dependent upon the lower-level components of the [ServerBridgeHandler]; the input stream's channel stays constant,
    /// but only its networking streams are reset.
    /// `remote`: This is the channel which receives byte-sized signals for starting, stopping, and restarting the server
    pub async fn execute(mut self: Pin<&'server mut Self>, remote: Receiver<u8>) -> Result<(), ConnectError> {
        let write = SERVER_UP.write();
        if *write {
            return Err(ConnectError::Generic("Server is already running about this node!".to_string()))
        } else {
            *write = true;
        }

        let stage_driver = self.stage_driver.execute();
        let server_bridge_handler = self.server_bridge_handler.start_server(remote);

        stage_driver.select(server_bridge_handler)
            .map_err(|err| err.0)
            .map(|_| ())
            .and_then(|_| Ok(()))
    }

    /// This allows for the creation of new connection from the higher-level [Launcher]
    pub fn get_server_bridge_handle_ptr(mut self: Pin<&'server mut Self>) -> *const ServerBridgeHandler {
        &*self.server_bridge_handler as *const ServerBridgeHandler
    }

    /// Returns this node's NID
    pub fn get_local_nid(&self) -> u64 {
        self.local_network_account.get_id()
    }

    /// Used for network synchronization
    pub fn get_server_time(&self) -> i32 {
        now_utc().to_timespec().nsec
    }
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> Drop for Server<'cxn, 'driver, 'server> {
    fn drop(&mut self) {
        *SERVER_UP.write() = false;
    }
}