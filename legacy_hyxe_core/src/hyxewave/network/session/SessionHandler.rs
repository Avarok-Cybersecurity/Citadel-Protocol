/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::Borrow;
use std::any::Any;
use std::borrow::Cow;
//use futures::future::shared::{new, SharedItem, SharedError, Shared};
use std::cell::RefCell;
use std::sync::Arc;

use crossbeam::{bounded, Receiver, Sender};
use futures::future::Executor;
use futures::future::FutureResult;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use hashbrown::HashMap;
use parking_lot::Mutex;
use rand::random;
use serde_derive::{Deserialize, Serialize};
use tokio::prelude::{Future, future};
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::HyxeObject;
use crate::hyxewave::api::AsyncHandler::AsyncHandler;
use crate::hyxewave::api::Communicator::Communicator;
use crate::hyxewave::misc::{Constants, Globals};
use crate::hyxewave::misc::Constants::{MAX_DRILL_TRIGGERS, SERVICES::{*, CONNECTION_WORKER, SAAQ_WORKER_CLIENT, SAAQ_WORKER_SERVER, SERVER_CONNECTION_WORKER}};
use crate::hyxewave::network::GUIConnector::get_client_alerter;
use crate::hyxewave::network::HyperNode;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::services::ConnectionWorker::{check_connection_worker_async, check_connection_worker_async_server};
use crate::hyxewave::network::session::services::SAAQ::saaq_client;

pub struct SessionChecker {
    action: Arc<Mutex<Box<FnMut(Remote, HyxeObject<Session>) -> FutureResult<bool, tokio::timer::Error> + Send>>>,
    pub session_to_observe: HyxeObject<Session>,
}

impl SessionChecker {
    pub fn create<F: 'static>(session_to_observe: HyxeObject<Session>, fx: Box<F>) -> Self where F: FnMut(Remote, HyxeObject<Session>) -> FutureResult<bool, tokio::timer::Error> + Send {
        Self { action: Arc::new(Mutex::new(fx)), session_to_observe }
    }

    pub fn execute(&mut self, remote: Remote) -> FutureResult<bool, tokio::timer::Error> {
        (*self.action.lock()).call_mut((remote, Arc::clone(&self.session_to_observe)))
    }
}

//let (mut sender_exp, mut receiver_exp) = futures::sync::mpsc::unbounded::<Packet>();
pub struct AsyncService {
    pub service_name: usize,
    pub is_running: bool,
    pub can_run: bool,
    pub bounded_sender: Sender<String>,
    pub bounded_receiver: Receiver<String>,
    pub unbounded_sender: Option<UnboundedSender<String>>,
    //The sender and receivers for each service provide a way for other parts of the program to communicate with itself using 0/1's (bounded)
}

impl AsyncService {
    pub fn default(service_name: usize) -> Self {
        let (bounded_sender, bounded_receiver) = bounded(1); //bounded by this line of code

        Self { service_name, is_running: false, can_run: true, bounded_sender, bounded_receiver, unbounded_sender: None }
    }

    pub fn set_running(&mut self, can_run: bool) {
        self.can_run = can_run;
    }

    pub fn is_running(&self) -> bool {
        self.is_running && self.can_run
    }

    pub fn can_run(&self) -> bool { self.can_run }

    pub fn setup_unbounded_tx_rx_channel(&mut self) -> UnboundedReceiver<String> {
        let (tx, rx) = unbounded::<String>();
        self.unbounded_sender = Some(tx);
        rx
    }
}

///This object will be periodically refreshed that way the server and all clients in the HyperLAN, as well as any HyperWAN servers connections, are accounted for
#[derive(Serialize, Deserialize)]
pub struct IPTable {
    ///input: IP. Output: CID
    pub mapping: HashMap<String, u64>
}

pub struct Session {
    pub peer_ip: String,
    pub nac: HyxeObject<NetworkAccount>,
    pub source: ClientSourceType,
    pub session_state: SessionState,
    pub sid: u128,
    //session id
    pub remote: Remote,
    pub services: HashMap<usize, AsyncService>,
    pub communicator: Option<Arc<Communicator>>,

    /// This is to let the SAAQ client know when to update the drill version
    drill_triggers: usize,
}


impl Session {
    /// If there was a missed packet somewhere in the ConnectionWorker service, check_connection_fail_count increments.
    /// If the incremented value reaches 3, the connection is marked as dead, and no packets can go through. However,
    /// if it is nonzero and less than 3, the connection is possibly dead. The possibly dead state is useful for the
    /// ServerDCHandler in the case that an emergency signal is sent. This function must return true in order for the
    /// reconnection process to ensue
    pub fn session_is_possibly_dead(&self) -> bool {
        self.nac.lock().get_central_bridge().lock().check_connection_fail_count > 0
    }

    /// This should ALWAYS be executed before drilling-shut any data that is to be sent outbound via the Communicator
    pub fn trigger(&mut self) {
        self.drill_triggers += 1;
        println!("[Session] Most Recent Drill Triggered [{}]", self.drill_triggers);
        if self.drill_at_maximum_heat() {
            println!("[Session] Most Recent Drill At MAX HEAT! Engaging SAAQ subsystem");
            self.services.get(&Constants::SERVICES::SAAQ_WORKER_CLIENT).unwrap().unbounded_sender.unwrap().unbounded_send("TRIGGER".to_string());
        }
    }

    /// This is to be called once a new drill version is active
    pub fn reset_trigger(&mut self) {
        self.drill_triggers = 0;
    }

    /// You can metaphorically only use a drill for so long! Once it's been triggered long enough, we must be ready for the SAAQ client's check system to update the drill
    pub fn drill_at_maximum_heat(&mut self) -> bool {
        self.drill_triggers >= MAX_DRILL_TRIGGERS
    }

    pub fn run_saaq_client(&mut self, arc_mutex: HyxeObject<Session>) {
        let mut nac = Arc::clone(&self.nac);
        let remote = self.remote.clone();
        let service = AsyncService::default(SAAQ_WORKER_CLIENT);
        let mut checker = SessionChecker::create(Arc::clone(&arc_mutex), Box::new(move |remote: Remote, session: HyxeObject<Session>| {
            let mut result: Option<FutureResult<bool, tokio::timer::Error>> = None;
            //let session = Arc::clone(&arc_mutex);
            let mut session = session.lock();
            match session.get_service(SAAQ_WORKER_CLIENT).unwrap().can_run {
                true => result = {
                    println!("[SessionHandler::Session::SAAQ] Checking; service enabled!");
                    Some(future::ok(true))
                },
                _ => result = {
                    eprintln!("[SessionHandler::Session::SAAQ] Not checking; service disabled! Shutting down async checker");
                    Some(future::err(tokio::timer::Error::shutdown()))
                }
            }
            result.unwrap()
        }));

        let future = saaq_client(checker, remote.clone(), Arc::clone(&arc_mutex), nac);
        self.services.insert(SAAQ_WORKER_CLIENT, service);
        self.remote.execute(future);
    }

    ///Possibly needed; kept here just incase!
    pub fn run_saaq_server(&mut self) {}
    //0
    pub fn run_client_connection_worker_async(&mut self, arc_mutex: HyxeObject<Session>) {
        let nac = Arc::clone(&self.nac);
        let bridge = self.nac.lock().get_central_bridge();
        let remote = self.remote.clone();
        let username = self.nac.lock().get_username().clone();
        let password = self.nac.lock().password_unencrypted.clone();
        let sid = self.sid.clone();
        let service = AsyncService::default(CONNECTION_WORKER);
        let client_alerter_opt = get_client_alerter();

        if client_alerter_opt.is_none() {
            eprintln!("[SessionHandler] Unable to get GUI Handler! Severe error");
            return;
        }
        let client_alerter = client_alerter_opt.unwrap();

        let mut checker = SessionChecker::create(Arc::clone(&arc_mutex), Box::new(move |remote: Remote, session: HyxeObject<Session>| {
            let mut result: Option<FutureResult<bool, tokio::timer::Error>> = None;
            //let session = Arc::clone(&arc_mutex);
            let mut session = session.lock();
            match session.get_service(CONNECTION_WORKER).unwrap().can_run {
                true => result = {
                    println!("[SessionHandler::Session::CxnWorker] Checking; service enabled!");
                    Some(future::ok(true))
                },
                _ => result = {
                    eprintln!("[SessionHandler::Session::CxnWorker] Not checking; service disabled! Shutting down async checker");
                    Some(future::err(tokio::timer::Error::shutdown()))
                }
            }
            result.unwrap()
        }));
        let future = check_connection_worker_async(sid, checker, client_alerter, nac, bridge, remote, username, password);
        self.services.insert(CONNECTION_WORKER, service);
        self.remote.execute(future).unwrap();
    }


    //1
    pub fn run_server_connection_worker_async(&mut self, arc_mutex: HyxeObject<Session>) {
        if !self.services.contains_key(&SERVER_CONNECTION_WORKER) { //only 1 per session/cxn!
            let server_cxn_svc = AsyncService::default(SERVER_CONNECTION_WORKER);
            let mut checker = SessionChecker::create(Arc::clone(&arc_mutex), Box::new(move |remote: Remote, session: HyxeObject<Session>| {
                let mut result: Option<FutureResult<bool, tokio::timer::Error>> = None;
                //let session = Arc::clone(&arc_mutex);
                let mut session = session.lock();
                let sid = session.sid;
                let amt_left = Globals::GLOBAL_SESSIONS.lock().sessions.len();
                match session.get_service(SERVER_CONNECTION_WORKER).unwrap().can_run {
                    true => result = {
                        //println!("[SessionHandler::Session] ~Checking; service for {} enabled!", sid);
                        Some(future::ok(true))
                    },
                    _ => result = {
                        eprintln!("[SessionHandler::Session] Not checking; service for {} disabled! ({} global sessions left)", sid, amt_left);
                        Some(future::err(tokio::timer::Error::shutdown()))
                    }
                }
                result.unwrap()
            }));

            self.services.insert(SERVER_CONNECTION_WORKER, server_cxn_svc);
            let future = check_connection_worker_async_server(checker, self.services.get(&SERVER_CONNECTION_WORKER).unwrap().bounded_receiver.clone(), self.nac.read().get_central_bridge(), Arc::clone(&arc_mutex), self.remote.clone());
            self.remote.execute(future).unwrap();
        }
    }

    pub fn get_service(&mut self, service_name: usize) -> Option<&mut AsyncService> {
        self.services.get_mut(&service_name)
    }

    pub fn get_nac(&self) -> HyxeObject<NetworkAccount> {
        self.nac.clone()
    }

    pub fn kill_session(&mut self, peer_ip: &String) -> bool {
        self.kill_all_inner_services();
        Globals::GLOBAL_SESSIONS.lock().remove_session(&self.sid, peer_ip)
    }

    pub fn kill_all_inner_services(&mut self) -> bool {
        let num_to_kill = self.services.len();
        let mut num_killed = 0;
        for (id, mut service) in self.services.iter_mut() {
            service.set_running(false);
            num_killed += 1;
        }
        num_to_kill == num_killed
    }

    pub fn kill_inner_service(&mut self, service_name: usize) -> bool {
        let svc = self.services.get_mut(&service_name);
        if svc.is_none() {
            return false;
        }
        svc.unwrap().set_running(false);
        true
    }

    pub fn get_peer_ip(&self) -> &String {
        &self.peer_ip
    }

    pub fn get_communicator(&self) -> Arc<Communicator> {
        self.communicator.unwrap().clone()
    }
}

pub struct StateManager {
    sessions: HashMap<u128, HyxeObject<Session>>,
    remote: Option<Remote>,
    ip_table: IPTable,
}

impl StateManager {
    pub fn new() -> Self {
        Self { sessions: HashMap::new(), remote: None, ip_table: IPTable { mapping: HashMap::new() } }
    }


    ///As a packet makes hops between the network, is must be able to determine the IP address of a client/server by the IP, as ALL packets have a CID encoded
    pub fn get_cid_by_ip(&self, peer_addr: &String) -> Option<&u64> {
        self.ip_table.mapping.get(peer_addr)
    }

    pub fn get_ip_by_cid(&self, cid: &u64) -> Option<String> {
        for (peer_addr, cid) in self.ip_table.mapping {
            if *cid == cid {
                return Some(peer_addr);
            }
        }

        None
    }

    pub fn cid_exists_locally(&self, cid: u64) -> bool {
        for (sid, sess) in &self.sessions {
            if sess.lock().get_nac().lock().cid == cid {
                return true;
            }
        }

        false
    }

    ///Whenever the server sends a new wave of packets correspnding to the IPTable serialized object, call the function below
    pub fn update_ip_table(&mut self, new_ip_table: IPTable) {
        self.ip_table = new_ip_table;
    }

    pub fn get_session(&mut self, sid: &u128) -> Option<HyxeObject<Session>> {
        if let Some(session) = self.sessions.get_mut(sid) {
            return Some(Arc::clone(session));
        }
        None
    }

    pub fn reset(&mut self) {
        self.sessions.clear();
        self.remote = None;
    }

    pub fn create_session(&mut self, session_state: SessionState, source: ClientSourceType, nac: HyxeObject<NetworkAccount>, remote: Remote, peer_ip: String) -> Option<HyxeObject<Session>> {
        if let Some(sid) = nac.read().get_hyper_random::<u128>(random::<u128>() as u128) {
            let session = Session { peer_ip, nac, source, session_state, sid, remote, services: HashMap::new(), communicator: None, drill_triggers: 0 };
            let mut session = HyxeObject::new(session);
            self.sessions.insert(sid, session.clone());
            let communicator = Communicator::new(&sid).unwrap();
            ///Setup the communicator
            session.write().communicator = Some(Arc::new(communicator));
            self.ip_table.mapping.insert(peer_ip.clone(), nac.read().cid);
            return Some(session.clone());
        }
        None
    }

    pub fn remove_session(&mut self, sid: &u128, peer_ip: &String) -> bool {
        if let Some(session) = self.sessions.remove(sid) {
            return true;
        }
        false
    }

    pub fn get_session_ids(&self) -> Vec<u128> {
        let mut ret = vec!();
        for (cid, session) in self.sessions.iter() {
            ret.push(*cid);
        }
        ret
    }

    pub fn get_sessions(&self) -> Vec<HyxeObject<Session>> {
        let mut ret = vec!();
        for (cid, session) in self.sessions.iter() {
            ret.push(session.clone());
        }
        ret
    }

    ///Since there can only be one connection per NAC, and for each NAC, there is only one central bridge,
    ///We can match the CID's of NAC's to determine if a session exists
    pub fn get_session_by_nac(&self, nac_ext: &HyxeObject<NetworkAccount>) -> Option<HyxeObject<Session>> {
        println!("[SessionHandler] Getting Session By NAC {}", nac_ext.read().cid);
        let ext_cid = nac_ext.read().cid;
        for (cid, session) in self.sessions.iter() {
            let mut is_equal = false;
            if session.read().get_nac().read().compare_to_nac(&ext_cid) {
                is_equal = true;
            }

            if is_equal {
                println!("[SessionHandler] Found NAC");
                return Some(session.clone());
            }
        }
        None
    }

    pub fn set_remote(&mut self, remote: Remote) {
        self.remote = Some(remote);
    }

    pub fn get_remote(&self) -> Option<Remote> {
        self.remote.clone()
    }
}

//Is the user using the GUI, RCON, or WEB/httpx program?
#[derive(Debug, PartialEq)]
pub enum ClientSourceType {
    GUI,
    RCON,
    WEB,
    SERVER_CXN,
}

pub enum SessionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
}

/**
    User nac successfully logs-in via GUI, webfront, console, etc. Now, HyxeWave::Sys() must
    allow the connection to persist internally and handle requests to and from the ClientSourceType.
    This is where we start a live session... on login success!
*/


pub mod StateTransfer {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use tokio_core::reactor::Remote;

    use crate::HyxeObject;

    use super::*;

    //Today, work on making the connection-checker system work to allow stable communications ontop of the kcp layer
    pub fn on_login_success_client(source: ClientSourceType, nac: HyxeObject<NetworkAccount>, remote: Remote, peer_ip: String) -> Option<HyxeObject<Session>> {
        println!("[SessionHandler] on_login_success");
        if let Some(session) = Globals::GLOBAL_SESSIONS.write().create_session(SessionState::CONNECTED, source, nac, remote, peer_ip) {
            println!("[SessionHandler] Starting core services for session {}", &session.read().sid);

            /// I am temporarily disabling the SAAQ client to ensure the other changes in the system don't negatively affect the overall system
            session.lock().run_client_connection_worker_async(session.clone());
            //session.lock().run_saaq_client(Arc::clone(&arc_mutex));

            return Some(session);
        }
        None
    }

    //When a server received a connect packet, it is either the first connect packet, or a keep-alive connect packet.
    //The two are informatically identical, thus it's up to this function to create a session for the server to handle
    //the sockets between itself and the client.
    pub fn on_connect_packet_received_server(nac: HyxeObject<NetworkAccount>, remote: Remote, peer_ip: String) -> Option<HyxeObject<Session>> {
        let nac_id = nac.read().cid;
        let session_opt = Globals::GLOBAL_SESSIONS.read().get_session_by_nac(&nac);
        if session_opt.is_some() {
            let session = session_opt.unwrap();
            println!("[SessionHandler] Session already exists ({}). Treating as KEEP_ALIVE packet, thus notifying internal bridge-handler", session.lock().sid);
            match session.read().get_service(SERVER_CONNECTION_WORKER).unwrap().bounded_sender.try_send("1".to_string()) {
                Ok(res) => println!("[SessionHandler] Success notifying the bridge-handler"),
                Err(err) => println!("[SessionHandler] No need for this KEEP_ALIVE (redundancy); Packet already exists within internal sender!")
            }
            return Some(session);
        } else {
            println!("[SessionHandler] Session does not exist; creating session for NAC {}", &nac_id);
            let session_opt = Globals::GLOBAL_SESSIONS.write().create_session(SessionState::CONNECTED, ClientSourceType::SERVER_CXN, nac.clone(), remote, peer_ip);
            if session_opt.is_none() {
                eprintln!("[SessionHandler] Unable to instantiate session with NAC {}", &nac_id);
                //TODO: Send error packet
                return None;
            }
            let mut session = session_opt.unwrap();
            println!("[SessionHandler] Session {} created!", session.read().sid);
            let session_ext = session.clone();
            session.write().run_server_connection_worker_async(session_ext);
            return Some(session);
        }
        None
    }

    pub fn on_disconnect(sid: &u128, peer_ip: &String) -> bool {
        Globals::GLOBAL_SESSIONS.write().remove_session(sid, peer_ip)
    }

    pub fn on_reconnect(sid: &u128) -> bool {
        //TODO::
        true
    }
}

pub fn get_session_by_nac(nac: HyxeObject<NetworkAccount>) -> Option<HyxeObject<Session>> {
    if let Some(sess) = Globals::GLOBAL_SESSIONS.read().get_session_by_nac(&nac) {
        return Some(sess);
    }
    None
}

/**
    These functions are for global use
*/
pub fn get_session(sid: &u128) -> Option<HyxeObject<Session>> {
    Globals::GLOBAL_SESSIONS.read().get_session(sid)
}

/// This function is useful for checking to see if a given CID even has a valid connection

pub fn get_session_by_cid(cid: &u64) -> Option<HyxeObject<Session>> {
    if let Some(nac) = crate::hyxewave::network::session::NetworkAccount::get_nac(cid) {
        if let Some(sess) = Globals::GLOBAL_SESSIONS.read().get_session_by_nac(&nac) {
            return Some(sess);
        }
    }

    None
}

pub fn get_sessions() -> Vec<HyxeObject<Session>> {
    Globals::GLOBAL_SESSIONS.read().get_sessions()
}

pub fn get_session_ids() -> Vec<u128> {
    Globals::GLOBAL_SESSIONS.read.get_session_ids()
}

