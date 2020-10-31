/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use arrayfire::count;
use hashbrown::HashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use hyxe_util::HyxeError;

use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Utility::{is_even, scramble_array, scramble_generic_array};
use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::session::SessionHandler::Session;

///The purpose of this file is to take an input of data and map it to a layout of packets such that:
///The packets are virtually in a coordinate-space in alignment with a sine wave
///These are aligned columns of packets
///
/// The end result of the mapping: it tells a PacketSeriesSender which port to send information through, and which port is should arrive in.
/// `v_time` is the order the entire column in relation to the higher array of columns
/// whereas `wid` is the wave-identification number (unto itself DOES NOT imply `v_time`)
pub struct PacketSeriesLayout {
    ///(send_port, recv_port, data)
    /// For ports vals: values are in deltas.
    /// This object is now iterative
    /// The f64's are the WID's
    mapping: Vec<(f64, Vec<(u8, u8, Vec<u8>)>)>,
    pub oid_eid: u64,
}

impl PacketSeriesLayout {
    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn len_of_column(&self, column_idx: usize) -> usize {
        self.mapping.get(column_idx).unwrap().len()
    }
}

impl Iterator for PacketSeriesLayout {
    type Item = (f64, Vec<(u8, u8, Vec<u8>)>);

    ///WARNING! This drains the mapping! Once this is iterated through, it cannot be re-visited
    fn next(&mut self) -> Option<Self::Item> {
        self.mapping.pop()
    }
}

/// This function takes into account the KCP header, Hyxe header, inputted payload len (which is stretched by security level), and base64 encoding which happens in the lower-level RIGHT BEFORE being sent-outwards
pub fn get_expected_packet_size(payload_unencrypted_len: usize, security_level: &u64) -> usize {}

///Input: `data_unencrypted`
/// Output: scrambled packets of encrypted data
/// We don't need to encrypt the data here because it is automatically done in PacketWrapper.rs. HOWEVER, we want a synchronized
/// `drill_version` thatway debugging is easier. In the future, we will pass the responsibility of creating the drill_version to
/// PacketWrapper.rs thatway each individual packet has the chance to have a different version of encryption, as desired
pub fn create_linear_mapping(data_unencrypted: Vec<u8>, oid_eid: u64, session: HyxeObject<Session>, security_level: &u64) -> Result<PacketSeriesLayout, HyxeError> {
    //Step 1: split information in frames
    let unencrypted_len = data_unencrypted.len();
    let chunk_size = Constants::MIN_PACKET_PAYLOAD_SIZE;
    if unencrypted_len <= Constants::MIN_PACKET_PAYLOAD_SIZE {
        return HyxeError::throw("[WaveformGenerator] Skipping layout creation; small-data detected, no scrambling applied");
    }

    ///TODO: Recalculate given that data isn't going to be encrypted until the lower level @ PacketWrapper
    let fl_num_packets = (unencrypted_len / chunk_size) as f64;
    let packets_needed = math::round::ceil(fl_num_packets, 0);
    println!("[WaveformGenerator] [LINEAR] Received an (encrypted!) input of {} bytes; will create {} packets", encrypted_len, packets_needed);

    let port_range = session.lock().nac.lock().get_port_range();
    /// We can only have, at-most, port_range packets per inner-hashmap
    /// However, there is no limit to the number of rows(usize) that
    /// can exist
    let mut mapping = Vec::new();

    let drill_version = session.lock().nac.lock().get_latest_drill_version().unwrap() as usize;

    let columns_needed = math::round::ceil(packets_needed / valid_ports.len(), 0);
    let (port_sources, port_dests) = session.lock().nac.lock().get_port_combos(drill_version);

    println!("[WaveformGenerator] [dV: {}] To fit {} packets, we will need {} columns", drill_version, num_packets, columns_needed);


    let mut packets_made = packets_needed as usize;
    let mut column_count = 0;
    let mut port_iter_idx = 0;

    // The `column_cur` counter doubly serves as the iterative_idx for finding the WID!
    for column_cur in 0..columns_needed {
        let mut column_map = Vec::<(u8, u8, Vec<u8>)>::new();

        for row_cur in 0..packets_per_column {
            if packets_made == packets_needed {
                //Scramble the ordering, so when the packets are dispatched, reconstruction cannot occur via serial concatenation
                scramble_generic_array(&mut mapping);
                return Ok(ScrambledLinearPacketLayout { mapping, oid_eid, drill_version });
            }

            let start_idx = packets_made * chunk_size;
            let end_idx = start_idx + chunk_size;
            let chunk = data_encrypted[start_idx..end_idx].to_vec();
            let tuple = (port_sources[port_iter_idx], port_dests[port_iter_idx], chunk);
            column_map.push(tuple);

            packets_made += 1;
        }

        port_iter_idx += 1;
        if port_iter_idx == port_range {
            port_iter_idx = 0;
        }

        let tuple = (session.lock().nac.lock().get_drill(drill_version).unwrap().get_object().calculate_wid(column_cur), column_map);
        mapping.push(tuple);
    }

    HyxeError::throw("[WaveformGenerator] [LINEAR] Unable to generate layout!")
}