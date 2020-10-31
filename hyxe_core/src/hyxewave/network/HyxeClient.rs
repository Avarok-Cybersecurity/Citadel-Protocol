/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::sync::Arc;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use futures::future::{Executor, Future};
use futures::stream::Stream;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_mpmc::array::array;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::Scope;
use tokio_core::reactor::{Core, Remote};

use hyxe_util::HyxeError;

use crate::HyxeObject;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Constants::MAINFRAME_SERVER_IP;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::printf_err;
use crate::hyxewave::network::BackgroundService::background_service;
use crate::hyxewave::network::BridgeHandler::BridgeHandler;
use crate::hyxewave::network::BridgeHandler::send_packet_async;
use crate::hyxewave::network::ConnectionHandler;
use crate::hyxewave::network::GUIConnector::GUIConnector;
use crate::hyxewave::network::HyperNode;
use crate::hyxewave::network::HyxeServer::HyxeServer;
use crate::hyxewave::network::Packet::{InboundPacket, ProcessedInboundPacket};
use crate::hyxewave::network::PacketSeriesListener::PacketSeriesListener;
use crate::hyxewave::network::session::NetworkAccount::*;
use crate::hyxewave::network::session::services::ConnectionWorker::{check_connection_worker_async, check_connection_worker_async_server};
use crate::hyxewave::network::session::services::ServerDCHandler::dc_handler;
use crate::hyxewave::network::StageFlowHandler::StageHousing;
use crate::hyxewave::network::WaveformListener;

pub struct HyxeClient {
    dispatchers: HyxeObject<HashMap<String, Arc<BridgeHandler>>>,
    //client_ip -> send-functions
    can_run: bool,
    self_reference: Option<Arc<Mutex<HyxeClient>>>,
    connection_handler: Option<Arc<Mutex<ConnectionHandler::ConnectionHandler>>>,
    nid: u64,
}

impl HyxeClient {
    /// This function is necessary to (non-blockingly to the other event loops) initiate interaction between the client system and the GUI/WEB/ETC subsystem
    /// TODO: Abstract-away GUI/WEB/ETC connector (get the GUI connector working-well first, then make trait that all "connectors" can use
    pub fn setup_vital_user_services(&self) {
        let self_reference = self.replicate();
        rayon::spawn(|| {
            let mut central_bridge = BridgeHandler::new(Constants::MAINFRAME_SERVER_IP.to_string(), Constants::PORT_START, Constants::PORT_END, Constants::AUX_PORTS.to_vec(), false);
            let cb_arx_mutex = Arc::new(Mutex::new(central_bridge));

            let mut vital_svc_core = Core::new().unwrap();
            let remote = vital_svc_core.remote();
            GUIConnector::new(cb_arx_mutex.clone(), remote.clone());

            /// In order for the GUI connector to run, we will need to run() the core that is attributed with the remote sent within the GUI connector
            /// Thus, I will create a "background" service, and have that be the primary event loop

            //let background_svc_future = background_service(remote.clone(), cb_arx_mutex.clone()).from_err::<()>().join(dc_handler(remote.clone()));


            let background_svc_future = background_service(remote.clone(), cb_arx_mutex.clone()).join(dc_handler(self_reference, remote.clone()));
            ///launch the core!
            vital_svc_core.run(background_svc_future).unwrap();
        });
    }
}

impl HyperNode for HyxeClient {
    fn new(nid: u64, port_start: u16, port_end: u16, aux_ports: Vec<u16>) -> HyxeObject<HyxeClient> {
        ///TODO: Handle multiple servers
        tokio_kcp::GLOBAL_IP_ADDR.write().unwrap().push(MAINFRAME_SERVER_IP);

        HyxeObject::new(HyxeClient {
            dispatchers: HyxeObject::new(HashMap::new()),
            can_run: true,
            self_reference: None,
            connection_handler: None,
            nid,
        })
    }

    fn get_instance_type(&mut self) -> i32 {
        Constants::CLIENT_INST
    }

    fn get_bridge(&mut self, destination_ip: &String) -> Option<Arc<BridgeHandler>> {
        let ret = self.dispatchers.get_object();
        let ret = ret.get(destination_ip);
        if ret.is_none() {
            return None;
        }

        Some(Arc::clone(ret.unwrap()))
    }

    fn can_run(&self) -> &bool {
        &self.can_run
    }

    fn close_connection_to(&mut self, peer_addr: String) -> Result<(), HyxeError> {
        self.connection_handler.clone().unwrap().lock().stop_connection(peer_addr)
    }

    fn get_connection_handler(&mut self) -> Option<Arc<Mutex<ConnectionHandler::ConnectionHandler>>> {
        self.connection_handler.clone()
    }

    fn get_nid(&self) -> &u64 {
        &self.nid
    }
}

pub fn initialize_node(port_start: u16, port_end: u16, aux_ports: Vec<u16>) -> Result<bool, HyxeError> {
    crate::hyxewave::network::session::NetworkAccount::load_all_nacs(true);

    rayon::scope(move |scope| {
        let hyxe_client = HyxeClient::new(port_start, port_end, aux_ports.clone());
        let (stage0_to_stage_1_tx, stage1_rx) = unbounded::<InboundPacket>(); //forwards stage 0 to stage 1

        let (stage1_tx_wave, stage2_rx_wave) = unbounded::<ProcessedInboundPacket>();
        let (stage1_tx_linear, stage2_rx_linear) = unbounded::<ProcessedInboundPacket>();


        let (stage2_tx_exp, stage2_rx_exp) = unbounded::<ProcessedInboundPacket>();


        let (stage4_tx, stage4_rx) = unbounded::<ProcessedInboundPacket>();

        let (stage5_tx_wave, stage5_rx_wave) = unbounded::<(u64, HashMap<u16, HashMap<u16, HashMap<u64, HashMap<u16, ProcessedInboundPacket>>>>)>();
        let (stage5_tx_linear, stage5_rx_linear) = unbounded::<(u64, HashMap<u16, ProcessedInboundPacket>)>();

        /// The connection handler lets packets forward to another consumer @ stage 1. We only need to give the cxn handler senders.
        let mut connection_handler = ConnectionHandler::ConnectionHandler::new(port_start, port_end, aux_ports.clone(), stage0_tx_wave, stage0_tx_linear);


        /// Create a core communicator, allowing for the cores to be terminated upon command
        let (core_communicator_tx, core_communicator_rx) = array::<String>(10);

        ///Set the Global for easy access runtime-wide
        *Globals::CORE_COMMUNICATOR_TX.lock() = Some(core_communicator_tx.clone());
        let core_com2 = core_communicator_rx.clone();

        /// This closure is for the stage housing
        scope.spawn(move |sc2| {
            println!("[HyxeClient] Starting stage handler...");
            let mut stage_core = Core::new().unwrap();
            let stage_remote = stage_core.remote();

            ///Stage 4 setup
            let packet_series_listener = PacketSeriesListener::new(stage_remote.clone(), stage4_tx.clone(), stage4_rx, stage5_tx_wave.clone(), stage5_tx_linear.clone());

            let mut stage_housing = StageHousing::new(stage1_tx_wave, stage1_tx_linear, stage2_tx_exp, stage4_tx, stage5_tx_wave, stage5_tx_linear, false);
            /// inside this, another core is ran


            let core_communicator_rx = core_com2;

            stage_core.run(stage_housing.start_stage_handler(stage1_rx_wave, stage1_rx_linear, stage2_rx_exp, stage_remote, core_communicator_rx));
            printf_err("[HyxeClient] Stopping stage handler...");
        });

        /// Since this is a client, we want to enable interaction between this system and an external service (like a GUI/WEB/ETC)
        hyxe_client.lock().setup_vital_user_services();

        /// Send a "CONNECT" signal to the core_communicator, that way the connection handler receives it an enacts appropriately
        core_communicator_tx.clone().try_send(format!("CONNECT{}", Constants::MAINFRAME_SERVER_IP)).unwrap();

        /// Now, wrap the ConnectionHandler in an Arc<Mutex<>> to have it distributed. Set it inside the HyperNode object
        let cxn_handler_arc_mutex = Arc::new(Mutex::new(connection_handler));
        hyxe_client.lock().connection_handler = Some(cxn_handler_arc_mutex.clone());

        ///Set the global cxn_handler for easy-access for the bridge-handler above in the case of needing to reconnect
        *Globals::CONNECTION_HANDLER.lock() = Some(cxn_handler_arc_mutex.clone());

        /// Now, run the ConnectionHandler, blocking this thread
        ConnectionHandler::core_blocker(cxn_handler_arc_mutex.clone(), core_communicator_rx);
        println!("[HyxeClient] Exiting System");
    });

    Ok(true)
}
