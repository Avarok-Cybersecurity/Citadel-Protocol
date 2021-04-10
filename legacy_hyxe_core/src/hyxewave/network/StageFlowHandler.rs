/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use futures::future::Executor;
use futures::stream::Stream;
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_mpmc::array::{array, Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::Scope;
use tokio::prelude::Future;
use tokio_core::reactor::{Core, Handle, Remote};

use hyxe_util::HyxeError;

use crate::HyxeObject;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::network::Packet::{InboundPacket, ProcessedInboundPacket};
use crate::hyxewave::network::PacketProcessor;
use crate::hyxewave::network::WaveformListener::WaveformListener;

use super::HyperNode;

/// The purpose of this file and structs herein are to ensure that packets correctly flow throughout the interior architecture of this program
pub struct StageHousing {
    /// This will set the foundation for a future, F, that starts up and kills connections.
    /// The input of the receiver is (K, V) where K: bool, and if K == true, then it makes a connection
    /// to V (typeof String). Else if K == false, then it disconnects from V. EDIT: MOVED TO GLOBAL PREVENT DEADLOCK OVER WFL
    //pub main_connection_request_acceptor: UnboundedReceiver<(bool, String)>,

    /// Stage 1. Header/Data extraction stage (will guarantee that packets have a header and payload with information)
    /// Stage 2. Security/Decryption stage (will guarantee that packets have valid headers, and will also decrypt data otherwise drop packet)
    /// Stage 3. Packet Routing Detection (figure out the "where")
    /// Stage 4. Packet Action Detection and Execution (Give movement to the direction determined in stage 3)

    pub is_server: bool
}

impl StageHousing {
    pub fn new(is_server: bool) -> Self {
        Self { is_server }
    }

    /// The stage handler must get the futures associated with all the stages and run them with a select()
    /// This future receives data from stage0/SocketHandler, which pushes an unfiltered InboundPacket.
    /// The remotes will be used in subroutines for computationally-expensive futures that would otherwise
    /// block the thread
    pub fn start_stage_handler<'a, hNode>(&'a mut self, hyperNode: HyxeObject<hNode>,
                                          stage1_rx: UnboundedReceiver<InboundPacket>, remote_stage1: &'a Remote, stage1_to_stage2_tx: &'a UnboundedSender<ProcessedInboundPacket>,
                                          stage2_rx: UnboundedReceiver<ProcessedInboundPacket>, remote_stage2: &'a Remote, stage2_to_stage3_tx: &'a UnboundedSender<ProcessedInboundPacket>,
                                          stage3_rx: UnboundedReceiver<ProcessedInboundPacket>, remote_stage3: &'a Remote,
                                          core_communicator_rx: Receiver<String>) -> impl Future<Item=(), Error=HyxeError> + 'a {
        stage1_future(stage1_rx, remote_stage1, stage1_to_stage2_tx)
            .select(stage2_future(stage2_rx, remote_stage2, stage2_to_stage3_tx))
            .map_err(|err| { () })
            .map(|obj| { () })
            .from_err::<HyxeError>()
            .select(core_communicator_rx.from_err::<HyxeError>().for_each(move |signal| {
                match signal.as_str() {
                    "STOP" => { HyxeError::throw("[StageFlowHandler] STOPPING STAGE FLOW HANDLER") }
                    _ => { Ok(()) }
                }
            }).map_err(|mut err| err.printf())).map_err(|(mut err, obj)| err.printf()).map(|obj| ())
    }

    pub fn signal_shutdown(&mut self) -> Result<bool, HyxeError> {
        /// TODO: shutdown system here for safe-shutdown. Simply just send SHUTDOWN signals through the senders.
        /// Make sure the receivers enact appropriately
        ///
        Ok(true)
    }
}

/// Stage 1 receives unprocessed InboundPackets' sent from the SocketHandlers. The goal of this stage is to determine the values of an unprocessed InboundPacket's header.
/// If the header is of invalid length, then the packet gets dropped. Otherwise, forward to stage2
pub fn stage1_future<'a>(stage1_rx: UnboundedReceiver<InboundPacket>, remote_stage1: &'a Remote, stage1_to_stage2_tx: &'a UnboundedSender<ProcessedInboundPacket>) -> impl Future<Item=(), Error=()> + 'a {
    stage1_rx.for_each(move |mut packet| {
        //println!("[StageFlowHandler::1] Packet header parsing...");

        if let Some(mut packet) = PacketProcessor::stage1_process_inbound_packet(packet) {
            println!("[StageFlowHandler::1 OKAY] Forwards packet with pid {} and oid {} to stage 2", packet.pid, packet.oid_eid);
            stage1_to_stage2_tx.unbounded_send(packet);
        } else {
            eprintln!("[StageFlowHandler::1 DROP] PacketProcessor Failed");
        }

        Ok(())
    }).map_err(|err| ()).map(|obj| ())
}

/// Validation and Decryption stage. Here, we want to make sure the packets being sent have a cid which belong to a session which is logged-in (unless a CONNECT type of packet, then PUSH to stage_2_connect).
/// Then, decrypt the data at this node and push to stage 3.
pub fn stage2_future<'a>(stage2_rx: UnboundedReceiver<ProcessedInboundPacket>, remote_stage2: &'a Remote, stage2_to_stage3_tx: &'a UnboundedSender<ProcessedInboundPacket>) -> impl Future<Item=(), Error=()> + 'a {
    stage2_rx.for_each(move |mut packet| {
        PacketProcessor::stage2_validate_and_decrypt_packet(&mut packet, &remote_stage2).and_then(move |res| {
            stage2_to_stage3_tx.unbounded_send(packet)
        })
    }).map_err(|err| ()).map(|obj| ())
}

/// Packet Direction Determination Stage. All packets received here (except those packets sent to stage2_substages) must be evaluated to determine "where" packets must go next.
/// Cases:
/// If there is no EID stored locally for the object, then we push the packet to its next destination outside of this node.
///
/// If there EXISTS an EID stored locally for the object, then we execute the expectancy for the given `oid_eid` within the ProcessedInboundPacket.
/// NOTE: All multipacket objects MUST send an OBJECT_HEADER packet, otherwise the inbound packets will be dropped
pub fn stage3_future<'a>(stage3_rx: UnboundedReceiver<ProcessedInboundPacket>, remote_stage3: &'a Remote, stage3_to_stage4_tx: &'a UnboundedSender<&'a mut ProcessedInboundPacket>) -> impl Future<Item=(), Error=()> + 'a {
    stage3_rx.for_each(move |mut packet| {})
}


/// Stage 2 receives packets from stage 1 that have a parsed header. However, we don't know if the data in the header is valid. Stage 2 sorts out what to do with the packet of information
/// given the `oid_eid` which is the object identification/expectancy identification. (Case A): If there is an expectancy in the local hashmap that matches the packet's oid_eid,
/// that implies that the packet contains data relevant to the closure specified in the hashmap and we must thus forward it thereto. (Case B): However, it is also
/// possible that there is no matching `oid_eid` in the local hashmap, which means this node has no specific listener for the packet. Case B usually means to bounce a response back
/// (e.g., registering, connecting, disconnecting, getting a hashmap, etc)
pub fn stage4_future(receiver_stage2: UnboundedReceiver<ProcessedInboundPacket>, remote_stage2: Remote) -> impl Future<Item=(), Error=()> {
    receiver_stage2.for_each(move |mut packet| {
        let oid_eid = packet.oid_eid;

        println!("[StageFlowHandler::2] [SECURITY_VULNERABILITY] Looking up Expectancy {}", oid_eid);
        if Globals::EXP_QUEUES.lock().contains_key(&oid_eid) {
            //If the eid is not recurrent, remove() the expectancy so it isn't executed again. Else, simply get_mut() so it remains in the queue
            ///WARNING: THIS MAY RESULT IN A DEADLOCK IF CALLED CONCURRENTLY
            let is_recurrent = Globals::EXP_QUEUES.lock().get(&oid_eid).unwrap().lock().is_recurrent.clone();

            if !is_recurrent {
                let mut data = Globals::EXP_QUEUES.lock();
                let data0 = data.remove(&oid_eid);
                //response-packet received
                let exp = data0.unwrap();

                println!("[StageFlowHandler::2] Found expectancy for {}, pushing packet to step 3aa (execute closure/expectancy)", oid_eid);
                exp.lock().execute(Some(packet), remote_exp.clone());
            } else {
                let mut data = Globals::EXP_QUEUES.lock();
                let data = data.get_mut(&oid_eid);
                //response-packet received
                let exp = data.unwrap();

                println!("[StageFlowHandler::2] Found [recurrent] expectancy for {}, pushing packet to step 3ab (execute [recurrent] closure/expectancy)", oid_eid);
                exp.lock().execute(Some(packet), remote_exp.clone());
            }
        } else {
            //response requested (requires username and password)
            println!("[StageFlowHandler::2] Expectancy not found, pushing packet to step 3b (NO EXP AVAILABLE LOCALLY, NEEDS RESPONSE)");
            PacketProcessor::stage_3b(packet, remote_exp.clone());
        }
        Ok(())
    }).map_err(|_| {})
}
