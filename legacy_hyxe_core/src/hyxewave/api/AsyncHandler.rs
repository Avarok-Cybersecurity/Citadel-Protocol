/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use futures::future::{Executor, Future};
use parking_lot::Mutex;
use tokio_core::reactor::{Core, Remote};

use hyxe_util::HyxeError;

use crate::hyxewave::api::Communicator::Response;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Utility::generate_rand_u64;
use crate::hyxewave::network::BridgeHandler::*;
use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::PacketGenerator::*;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::SessionHandler::*;
use crate::hyxewave::network::SocketHandler::PacketType;

pub struct AsyncHandler {
    sid: u128,
    nac: HyxeObject<NetworkAccount>,
    remote: Remote,
    session: HyxeObject<Session>,
    core: Core,
}

///Important destinctions: `messages` are meant for linear connections to the coms port of the central server. It is then the job of hte central server to directly respond or
/// forward the message to a peer on the HyperLAN or forward it to another server.
/// `data` is meant for sending wave-based data (multiport transmission) which takes advantage of the full technology of HyperEncryption/SAAQ
impl AsyncHandler {
    pub fn new(session_id: &u128) -> Option<Arc<Self>> {
        let session = get_session(session_id);
        if let Some(session) = session {
            let nac = session.lock().get_nac();
            let mut core = Core::new().unwrap();

            return Some(Arc::new(Self {
                sid: *session_id,
                nac,
                remote: core.remote(),
                session,
                core,
            }));
        }
        None
    }

    pub fn send_coms_message_async<F: 'static>(&self, message: Vec<u8>, dest_ip: String, on_message_received: Option<F>) where
        F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send {
        let session = self.session.clone();
        let remote = self.remote.clone();
        let aux_port_for_coms = self.nac.lock().get_aux_ports()[0];
        let expect_response = on_message_received.is_some();
        let expectancy_value_eid = generate_rand_u64();
        let nac = Arc::clone(&self.nac);
        let central_node_ip = nac.lock().get_central_node_ip().clone();
        let central_bridge = nac.lock().get_central_bridge();
        let (username, password) = nac.lock().get_credentials();
        let timeout = self.calculate_timeout_for_message(message.len());

        let drill_version = nac.lock().get_latest_drill_version();
        if drill_version.is_none() {
            eprintln!("[API: AsyncHandler] send_coms_message_async failed: drill_version empty");
            return;
        }

        let drill_version = drill_version.unwrap();

        let mut eid: Option<u64> = None;
        if expect_response {
            eid = Some(generate_rand_u64());
        }

        //bridge: remote: Remote, mut packet: ProcessedInboundPacket, expect_response: bool, expectancy_value: Option<u64>, on_packet_received: Option<F>
        //send_packet_async(remote,)

        if let Some(packet) = generate_coms_packet(message, Some(session), nac, &central_node_ip, &dest_ip, aux_port_for_coms, &username, &password, drill_version, eid, Constants::Flags::MESSAGE) {
            println!("[API: AsyncHandler] send_coms_message_async: Sent packet to {} then to {}", central_node_ip, dest_ip);
            //remote: Remote, mut packet: ProcessedInboundPacket, expect_response: bool, timeout: usize, expectancy_value: Option<u64>, on_packet_received: Option<F>
            remote.execute(send_packet_async(remote.clone(), packet, expect_response, timeout, eid, on_message_received)
                .and_then(|p| { Ok(()) }).map_err(|err| { eprintln!("[ASYNC_HANDLER] ERR! {:#?}", err) })).unwrap();
            return;
        }

        eprintln!("[API: AsyncHandler] send_coms_message_async failed: packet is None");
    }

    ///This is one option. The API developer gets the end-point instead of the CID. The server verifies the dest_ip with a CID.
    /// if there exists a CID, that means the NAC thereon the server is loaded. As such, it is then possible to forward
    /// the data below to the next hop
    pub fn send_data_async<F: 'static>(&self, message: Vec<u8>, dest_ip: String, on_message_received: Option<F>) where
        F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send {}

    ///TODO: actually implement the capacity for this to change in relation to not only packet size, but also self.connection_rate! (must implement this!)
    pub fn calculate_timeout_for_message(&self, message_len: usize) -> usize {
        Constants::TIMEOUT
    }

    pub fn get_nac(&self) -> HyxeObject<NetworkAccount> {
        Arc::clone(&self.nac)
    }

    pub fn get_session_id(&self) -> &u128 {
        &self.sid
    }
}