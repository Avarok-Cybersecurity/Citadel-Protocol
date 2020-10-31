/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::BorrowMut;
use std::sync::Arc;

use futures::future::{Executor, Future};
use futures::stream::Stream;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use hashbrown::HashMap;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::hyxewave::misc::Globals;
use crate::hyxewave::network::Packet::ProcessedInboundPacket;

///Stage 4
pub struct PacketSeriesListener {
    /// EID => PID ~> ProcessedInboundPacket
    pub linear_arrays: HashMap<u64, HashMap<u16, ProcessedInboundPacket>>,

    ///oid: u64, z_time: u16, v_time: u16, wid: u64, pid: u16 ~> ProcessedInboundPacket
    pub wave_arrays: HashMap<u64, HashMap<u16, HashMap<u16, HashMap<u64, HashMap<u16, ProcessedInboundPacket>>>>>,

    /// For communicating with this async process
    pub stage4_tx: UnboundedSender<ProcessedInboundPacket>,

    ///For inbound waves!
    pub expected_oids: HashMap<u64, usize>,
    pub expected_oids_count: HashMap<u64, usize>,

    ///For inbound linear packets!
    pub expected_eids: HashMap<u64, usize>,
    pub expected_eids_count: HashMap<u64, usize>,

    pub stage5_tx_wave: UnboundedSender<(u64, HashMap<u16, HashMap<u16, HashMap<u64, HashMap<u16, ProcessedInboundPacket>>>>)>,
    pub stage5_tx_linear: UnboundedSender<(u64, HashMap<u16, ProcessedInboundPacket>)>,
}

impl PacketSeriesListener {
    /// This return the object as well as a STAGE 5 receiver. This program sends READY linear/wave series to stage 5, thus signalling the processing of the data-as-a-whole
    /// `UnboundedReceiver`<(u64, bool)> => (eid OR oid ready, is_oid)
    pub fn new(remote: Remote, stage_4_tx: UnboundedSender<ProcessedInboundPacket>, stage4_rx: UnboundedReceiver<ProcessedInboundPacket>, stage5_tx_wave: UnboundedSender<(u64, HashMap<u16, HashMap<u16, HashMap<u64, HashMap<u16, ProcessedInboundPacket>>>>)>,
               stage5_tx_linear: UnboundedSender<(u64, HashMap<u16, ProcessedInboundPacket>)>) -> Arc<Self> {
        let linear_arrays = HashMap::new();
        let wave_arrays = HashMap::new();


        let mut object = Self { linear_arrays, wave_arrays, stage4_tx, expected_oids: HashMap::new(), expected_oids_count: HashMap::new(), expected_eids: HashMap::new(), expected_eids_count: HashMap::new(), stage5_tx_wave, stage5_tx_linear };

        let mut object = Arc::new(object);

        let stage4 = stage4_rx.from_err::<HyxeError>().for_each(move |packet| {
            if !*Globals::CAN_RUN.lock() {
                HyxeError::throw("[PacketSeriesListener] System marked to shutdown! Exiting");
            }

            let mut obj = Arc::clone(&object);
            let (pid, wid, v_time, z_time, oid, impartial) = packet.get_coords().unwrap().get();

            match packet.is_wave() {
                true => {

                    //We must ensure all possible hashmaps are stored and exist within... we don't want to insert the packet inside a blank space of memory!
                    //TODO:: OPTIMIZE this process!
                    if !obj.wave_arrays.contains_key(&oid) {
                        obj.wave_arrays.insert(oid, HashMap::new());
                    }

                    if !obj.wave_arrays.get(&oid).unwrap().contains_key(&z_time) {
                        obj.wave_arrays.get(&oid).unwrap().insert(z_time, HashMap::new());
                    }

                    if !obj.wave_arrays.get(&oid).unwrap().get(&z_time).unwrap().contains_key(&v_time) {
                        obj.wave_arrays.get(&oid).unwrap().get(&z_time).unwrap().insert(v_time, HashMap::new());
                    }

                    if !obj.wave_arrays.get(&oid).unwrap().get(&z_time).unwrap().get(&v_time).unwrap().contains_key(&wid) {
                        obj.wave_arrays.get(&oid).unwrap().get(&z_time).unwrap().get(&v_time).unwrap().insert(wid, HashMap::new());
                    }

                    obj.wave_arrays.get(&oid).unwrap().get(&z_time).unwrap().get(&v_time).unwrap().get(&wid).unwrap().insert(pid, packet);
                    obj.increment_wave_packet_count(&oid);

                    ///Now, check for completion!
                    obj.check_for_completions();
                }
                false => {
                    let eid = packet.get_eid().unwrap();

                    if !obj.linear_arrays.contains_key(&eid) {
                        obj.linear_arrays.insert(eid, HashMap::new());
                    }
                    obj.linear_arrays.get(&eid).unwrap().insert(pid, packet);
                    obj.increment_linear_packet_count(&eid);
                }
            };
        }).map_err(|mut err| err.printf());

        remote.clone().execute(stage4).unwrap();

        obj
    }

    ///Each OID has a total number of possible packets! RUN THIS WHEN A HEADER PACKET IS RECEIVED
    pub fn add_expected_wave_oid(&mut self, oid: u64, num_packets: usize) {
        self.expected_oids.insert(oid, num_packets);
    }

    ///Each EID has a total number of possible packets! RUN THIS WHEN A HEADER PACKET IS RECEIVED
    pub fn add_expected_linear_eid(&mut self, eid: u64, num_packets: usize) {
        self.expected_eids.insert(eid, num_packets);
    }

    /// For the wave-arrays, each OID has a total number of packets for all z_time, v_time, and pid arrays!
    pub fn check_for_completions(&mut self) {
        for (oid, count_needed) in self.expected_oids {
            if self.expected_oids_count.get(&oid) == count_needed {
                self.expected_oids.remove(&oid);
                self.expected_oids_count.remove(&oid);
                println!("[PacketSeriesListener] OID series {} fulfilled!", &oid);
                let map = self.wave_arrays.remove(&oid).unwrap();
                self.stage5_tx_wave.unbounded_send((oid, map));
            }
        }

        for (eid, count_needed) in self.expected_eids {
            if self.expected_eids_count.get(&eid) == count_needed {
                self.expected_eids.remove(&eid);
                self.expected_eids_count.remove(&eid);
                println!("[PacketSeriesListener] OID series {} fulfilled!", &eid);
                let map = self.linear_arrays.remove(&eid).unwrap();
                self.stage5_tx_linear.unbounded_send((eid, map));
            }
        }
    }

    pub fn increment_wave_packet_count(&mut self, oid: &oid) {
        *self.expected_oids_count.get_mut(oid).unwrap() += 1;
    }

    pub fn increment_linear_packet_count(&mut self, eid: &eid) {
        *self.expected_eids_count.get_mut(eid).unwrap() += 1;
    }
}



