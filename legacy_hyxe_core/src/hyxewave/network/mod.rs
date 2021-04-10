/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::Mutex;
use tokio::prelude::Stream;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::HyxeObject;
pub use crate::hyxewave::misc::Constants::*;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;

pub mod session;

pub mod HyxeServer;
pub mod HyxeClient;
pub mod WaveformListener;
pub mod SocketHandler;

pub mod BridgeHandler;

pub mod DecryptionHandler;
pub mod ExpectanceHandler;
pub mod PacketWrapper;

pub mod PacketGenerator;
pub mod PacketProcessor;
pub mod PacketSubProcessor;

pub mod BackgroundService;
pub mod GUIConnector;

pub mod NetworkMapping;

pub mod ConnectionHandler;
pub mod StageFlowHandler;

pub mod PacketSeriesListener;

pub mod PacketHopRouter;

pub trait HyperNode {
    fn new(nid: u64, port_start: u16, port_end: u16, aux_ports: Vec<u16>) -> HyxeObject<Self>;
    fn get_instance_type(&self) -> i32;
    fn get_bridge(&mut self, destination_ip: &String) -> Option<Arc<BridgeHandler::BridgeHandler>>;
    fn can_run(&self) -> &bool;
    fn close_connection_to(&mut self, peer_addr: String) -> Result<(), HyxeError>;
    fn get_connection_handler(&mut self) -> Option<Arc<Mutex<ConnectionHandler::ConnectionHandler>>>;
    fn get_nid(&self) -> &u64;
}

pub trait ExternalService {
    fn on_data_received(&mut self) -> Result<(), HyxeError>;

    fn send_data_to(&mut self) -> Result<(&String, Vec<u8>), HyxeError>;

    fn on_startup(&mut self) -> Result<(), HyxeError>;
}


