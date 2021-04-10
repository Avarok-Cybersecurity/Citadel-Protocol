/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use futures::future::Future;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_mpmc::array::{array, Receiver, Sender};
use hashbrown::HashMap;
use mut_static::MutStatic;
use parking_lot::Mutex;
use rayon::*;
use serde_derive::{Deserialize, Serialize};
use tokio::prelude::stream::Stream;
use tokio_core::reactor::{Core, Remote};

use hyxe_util::HyxeError;

use crate::HyxeObject;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Constants::MAINFRAME_SERVER_IP;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::printf_err;
use crate::hyxewave::network::BridgeHandler::BridgeHandler;
use crate::hyxewave::network::ConnectionHandler;
use crate::hyxewave::network::ExpectanceHandler::*;
use crate::hyxewave::network::HyperNode;
use crate::hyxewave::network::Packet::{InboundPacket, ProcessedInboundPacket};
use crate::hyxewave::network::PacketSeriesListener::PacketSeriesListener;
use crate::hyxewave::network::session::services::ServerDCHandler::dc_handler;
use crate::hyxewave::network::StageFlowHandler::StageHousing;
use crate::hyxewave::network::WaveformListener;

pub struct HyxeServer {
    active_bridges: HyxeObject<HashMap<String, Arc<BridgeHandler>>>,
    //client_ip -> send-functions
    can_run: bool,
    connection_handler: Option<Arc<Mutex<ConnectionHandler::ConnectionHandler>>>,
    nid: u64,
}

impl HyperNode for HyxeServer {
    fn new(nid: u64, port_start: u16, port_end: u16, aux_ports: Vec<u16>) -> HyxeObject<HyxeServer> {
        tokio_kcp::GLOBAL_IP_ADDR.write().unwrap().push(MAINFRAME_SERVER_IP);

        HyxeObject::new(HyxeServer {
            active_bridges: HyxeObject::new(HashMap::new()),
            can_run: true,
            connection_handler: None,
            nid,
        })
    }

    fn get_instance_type(&mut self) -> i32 {
        Constants::SERVER_INST
    }

    fn get_bridge(&mut self, destination_ip: &String) -> Option<Arc<BridgeHandler>> {
        Some(Arc::clone(self.active_bridges.get_object().get(destination_ip).unwrap_or(return None; )))
    }

    fn can_run(&self) -> &bool {
        &self.can_run
    }

    fn close_connection_to(&mut self, peer_addr: String) -> Result<(), HyxeError> {
        self.connection_handler.clone().unwrap().clone().lock().stop_connection(peer_addr)
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
        let hyxe_server = HyxeServer::new(port_start, port_end, aux_ports.clone());
        let (stage0_tx_wave, stage1_rx_wave) = unbounded::<InboundPacket>(); //forwards stage 0 to stage 1
        let (stage0_tx_linear, stage1_rx_linear) = unbounded::<InboundPacket>(); //forwards stage 0 to stage 1

        let (stage1_tx_wave, stage2_rx_wave) = unbounded::<ProcessedInboundPacket>();
        let (stage1_tx_linear, stage2_rx_linear) = unbounded::<ProcessedInboundPacket>();


        /// stage0_tx_wave - - - > [stage1_rx_wave  => stage1_tx_wave] - - - > stage2_rx_wave   = >
        ///                                                                                          \
        ///                                                                                             > > > stage2_tx_exp - - -> stage2_rx_exp  [...]
        ///                                                                                          /
        /// stage0_tx_linear - - > [stage1_rx_linear => stage1_tx_linear] - - > stage2_rx_linear = >


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

        ///Setup a reference for the dc_handler
        let self_reference = hyxe_server.lock().self_reference.clone().unwrap().clone();

        /// This closure is for the stage housing
        scope.spawn(move |sc2| {
            println!("[HyxeServer] Starting stage handler...");
            /// inside this, another core is ran

            let mut stage_core = Core::new().unwrap();
            let stage_remote = stage_core.remote();

            ///Stage 4 setup
            let packet_series_listener = PacketSeriesListener::new(stage_remote.clone(), stage4_tx.clone(), stage4_rx, stage5_tx_wave.clone(), stage5_tx_linear.clone());

            let mut stage_housing = StageHousing::new(stage1_tx_wave, stage1_tx_linear, stage2_tx_exp, stage4_tx, stage5_tx_wave, stage5_tx_linear, true);

            let core_communicator_rx = core_com2;
            let background_svc_future = dc_handler(self_reference, stage_remote.clone());
            ///Run the stage core, and join w/the dc handler to make reconnection hereon seemless!
            stage_core.run(stage_housing.start_stage_handler(stage1_rx_wave, stage1_rx_linear, stage2_rx_exp, stage_remote, core_communicator_rx).join(background_svc_future));
            printf_err("[HyxeServer] Stopping stage handler...");
        });


        /// Send a "listen" signal to the core_communicator, that way the connection handler receives it an enacts appropriately
        core_communicator_tx.clone().try_send("LISTEN".to_string());
        let cxn_handler_arc_mutex = Arc::new(Mutex::new(connection_handler));
        hyxe_server.lock().connection_handler = Some(cxn_handler_arc_mutex.clone());


        ///Set the global cxn_handler for easy-access for the bridge-handler above in the case of needing to reconnect
        *Globals::CONNECTION_HANDLER.lock() = Some(cxn_handler_arc_mutex.clone());


        /// Now, run the ConnectionHandler, blocking this thread
        ConnectionHandler::core_blocker(cxn_handler_arc_mutex.clone(), core_communicator_rx);
        println!("[HyxeServer] Exiting System");
    });

    Ok(true)
}