/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;
use std::time::Instant;

use crossbeam_queue::SegQueue;
use futures::sync::mpsc::UnboundedSender;
use futures::task::Task;
use futures_mpmc::array::{Receiver, Sender};
use hashbrown::HashMap;
use lazy_static::LazyStatic;
use mut_static::MutStatic;
use parking_lot::{Mutex, RwLock};

use hyxe_util::HyxeError;
use tokio_kcp::KcpSessionManager;

use crate::HyxeObject;
use crate::hyxewave::network::ConnectionHandler::ConnectionHandler;
use crate::hyxewave::network::ExpectanceHandler::Expectancy;
use crate::hyxewave::network::GUIConnector::GUIConnector;
use crate::hyxewave::network::NetworkMapping::*;
use crate::hyxewave::network::Packet::{};
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::services::ServerDCHandler;
use crate::hyxewave::network::session::SessionHandler::StateManager;
use crate::hyxewave::network::SocketHandler::PacketType;

#[macro_use] lazy_static! {

    //We get this value at runtime=0
    pub static ref RUNTIME_INIT: Instant = Instant::now();

    pub static ref CAN_RUN: Mutex<bool> = Mutex::new(true);
    pub static ref FIRST_RUN: Mutex<bool> = Mutex::new(true);

    //Moved from ExpectancyQueue
    pub static ref EXP_GLOBAL_TASKS: Arc<Mutex<HashMap<u8, Task>>> = Arc::new(Mutex::new(HashMap::new()));
    pub static ref EXP_QUEUES: Arc<Mutex<HashMap<u64, Arc<Mutex<Expectancy>>>>> = Arc::new(Mutex::new(HashMap::new()));

    //Moved from NetworkAccount
    pub static ref DHT_NACS: HyxeObject<HashMap<u64, HyxeObject<NetworkAccount>>> = Object::new(HashMap::new());

    //Moved from BackgroundService
    pub static ref ENTROPY_BANK_IS_UPDATING: MutStatic<bool> = MutStatic::new();

    //Moved from SessionHandler
    pub static ref GLOBAL_SESSIONS: HyxeObject<StateManager> = HyxeObject::new(StateManager::new());

    //Moved from ServerDCHandler
    pub static ref NEEDS_RESTART: Mutex<bool> = Mutex::new(false);

    //Moved from SocketHandler
    pub static ref SOCKET_WRITERS: RwLock<HashMap<String, Mutex<HashMap<u16, Arc<Mutex<SegQueue<String>>>>>>> = RwLock::new(HashMap::new());
    pub static ref SOCKET_TASKS_INPUT: Mutex<HashMap<String, Arc<Mutex<Task>>>> = Mutex::new(HashMap::new());
    pub static ref KCP_SESSION_MANAGER: Arc<Mutex<Option<KcpSessionManager>>> = Arc::new(Mutex::new(None));

    //Moved from GUIConnector
    pub static ref GUI_CONNECTOR: MutStatic<GUIConnector> = MutStatic::new();
    pub static ref GUI_CONN_UDP_TASK: Mutex<Vec<Task>> = Mutex::new(Vec::new());

    //Moved from PacketQueue
    pub static ref PACKET_QUEUES: Mutex<HashMap<usize, Mutex<HashMap<PacketType, Arc<Mutex<SegQueue<Packet>>>>>>> = Mutex::new(HashMap::new());
    /**
        Tasks: A hashmap for storing the async capacity to notify and initiate a poll()
    */
    pub static ref PACKET_QUEUE_TASKS: Mutex<HashMap<usize, Arc<Mutex<Task>>>> = Mutex::new(HashMap::new());

    pub static ref MAIN_CONNECTION_REQUEST_PIPE: Mutex<Option<UnboundedSender<(bool, String)>>> = Mutex::new(None);

    /// MPSC For communicating with the async cores
    pub static ref CORE_COMMUNICATOR_TX: Mutex<Option<Sender<String>>> = Mutex::new(None);
    pub static ref CORE_COMMUNICATOR_RX: Mutex<Option<Receiver<String>>> = Mutex::new(None);


    /// for communicating between this client and external services
    pub static ref CLIENT_CONNECTOR_TX: Mutex<Option<Sender<String>>> = Mutex::new(None);

    pub static ref CONNECTION_HANDLER: Mutex<Option<Arc<Mutex<ConnectionHandler>>>> = Mutex::new(None);

    pub static ref NETWORK_MAP_CLIENT: CowCell<ClientNetworkMap> = CowCell::new(ClientNetworkMap::new());
    pub static ref NETWORK_MAP_SERVER: CowCell<ServerNetworkMap> = CowCell::new(ServerNetworkMap::new());
}

pub fn system_engaged() -> bool {
    *CAN_RUN.lock()
}

pub fn reset_system() -> Result<bool, HyxeError> {
    //*tokio_kcp::CLIENT_NEEDS_RESTART.lock() = false;

    *CAN_RUN.lock() = true;

    EXP_GLOBAL_TASKS.lock().clear();
    EXP_QUEUES.lock().clear();

    //DHT_NACS.lock().clear();

    if ENTROPY_BANK_IS_UPDATING.is_set().unwrap() {
        *ENTROPY_BANK_IS_UPDATING.write().unwrap() = false;
    }

    GLOBAL_SESSIONS.write().reset();

    *NEEDS_RESTART.lock() = false;

    SOCKET_WRITERS.lock().clear();
    SOCKET_TASKS_INPUT.lock().clear();
    *KCP_SESSION_MANAGER.lock() = None;
    // GUI_CONNECTOR is self-replaced in the constructor
    GUI_CONN_UDP_TASK.lock().clear();
    PACKET_QUEUES.lock().clear();
    PACKET_QUEUE_TASKS.lock().clear();

    Ok(*CAN_RUN.lock() && !*NEEDS_RESTART.lock())
}

pub fn get_runtime_ns() -> u128 {
    RUNTIME_INIT.elapsed().as_nanos()
}

pub fn signal_system_restart() {
    *NEEDS_RESTART.lock() = true;
    *CAN_RUN.lock() = false;
}

pub fn get_connection_handler() -> Option<Arc<Mutex<ConnectionHandler>>> {
    Some(Arc::clone(&CONNECTION_HANDLER.lock().clone().unwrap().clone()))
}