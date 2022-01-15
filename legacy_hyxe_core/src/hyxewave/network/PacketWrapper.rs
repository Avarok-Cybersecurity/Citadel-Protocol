/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::str::FromStr;
use std::sync::Arc;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use chrono::prelude::*;
use num::ToPrimitive;
use parking_lot::Mutex;

use async_mem::hyxeobject::HyxeObject;
use hyxe_util::HyxeError;
use hyxewave_net::prelude::{LayoutVerified, ProcessedInboundPacket, ProcessedInboundPacketHeader};

use crate::{HyxeObject, SecurityLevel};
use crate::hyxewave::encrypt::Drill::Drill;
use crate::hyxewave::misc::Constants;
use crate::prelude::{ByteSliceMut, NetworkAccount, OutboundPacket, RwLock, Session};

use super::PacketHopRouter::*;
use super::PacketHopRouter::{PacketHopDestination, PacketHopState};

pub static HYXE_HEADER_SIZE: usize = 77; //indexes should end at data[76]

/// This function crafts a correct header which is necessary for every packet. This function also encrypts unencrypted_data, then prepends the header to the encrypted_data.
/// `nac` must contain the data for `cid_initial`
/// This will be sent to the central server, where the `dest_nid` will be validated and later forwarded.
/// `oid_eid` is preserved as the packet hops about the network
/// `route_dest_nid` is the final location the packet reaches before that node rebounds a response (if `expects_response` is 1, that is).
/// While this function performs the encryption, it does NOT decide the `drill_version`. The reason why is because this function doesn't know the correct ordering of the PID and WID if the drill_versions are unsynced
/// This function should always be used when creating a new packet (e.g., initial or rebound), but this should NOT be used for forwarding packets! use prepare_existing_packet_for_forwarding, as it reduces the number of new allocs
pub fn wrap_new_packet<Input: AsRef<[u8]>>(session: Option<HyxeObject<Session>>, nac: HyxeObject<NetworkAccount>, unencrypted_bytes: Input, security_level: &SecurityLevel, drill_version: u32, expects_response: u8, src_port: u16, dest_port: u16, route_dest_nid: u64, dest_type: PacketHopDestination, command_flag: u8, oid_eid: u64, wid: f64, pid: f64, amplitudal_sum: &u16, network_map_version: u32) -> Option<OutboundPacket<Input>> {
    let mut packet = BytesMut::with_capacity(HYXE_HEADER_SIZE + (unencrypted_bytes.len() * security_level.get_encrypt_byte_multiplier()));
    let nac = nac.read();
    let selected_drill = nac.get_drill(drill_version as usize);
    if selected_drill.is_none() {
        severe!("[PacketWrapper] The drill version {} does not exist", latest_drill);
        return None;
    }


    let timestamp = Utc::now().timestamp_millis();

    let current_packet_hop_state = PacketHopState::AT_PRIMARY_SENDER.value();
    // The next packet MUST go to the mainframe server, as this function is dedicated for "new" packets
    let next_packet_hop_state = PacketHopState::AT_MAINFRAME_SERVER.value();
    let endpoint_destination_type = dest_type.value();


    /// We write the cid twice since we are wrapping an INITIAL packet
    packet.put_u64_be(nac.cid);
    packet.put_u64_be(nac.cid);
    packet.put_u32_be(drill_version);
    packet.put_u8(security_level.get_byte_representation());
    packet.put_i64_be(timestamp);
    packet.put_u8(current_packet_hop_state);
    packet.put_u8(next_packet_hop_state);
    packet.put_u8(endpoint_destination_type);
    packet.put_u8(command_flag);
    packet.put_u8(expects_response);
    packet.put_u64_be(oid_eid);
    packet.put_u64_be(wid.to_bits());
    packet.put_u64_be(pid.to_bits());
    packet.put_u64_be(route_dest_nid);
    packet.put_u64_be(route_dest_cid);
    packet.put_u32_be(network_map_version);

    let drill = selected_drill.unwrap();
    nac.get_message_encryptor().encrypt_bytes(unencrypted_bytes, &mut packet, drill, security_level, amplitudal_sum, session).and_then(move |res| {
        // The below should be necessarily true
        debug_assert!(packet.len() == packet.capacity());

        Some(OutboundPacket {
            src_port,
            dest_ip: nac.get_central_node_ip().clone(),
            dest_port,
            data: packet,
        })
    })
}

/// This function should be used in the case where... let F represent this function, let C = client, let M = mainframe server, let J equal the route destination, let S equal current state, and let (S+1) equal the next state then:
/// use F generally when S != C or J, and (S+1) == A HyperLAN Client, A HyperWAN Server, or a HyperWAN client. In other words, use this in intermediate steps between the sending client and the final destination. If the packet's state, S, is at either
/// the client (S) or destination (J), then use wrap_new_packet. Most simply put, only servers forwardng packets call this function.
///
/// The nac used can be either a Mainframe HyperLAN Server to HyperLAN client (internal route), or a Mainframe Server to HyperWAN Server (external route)
///
/// Because of this configuration, the security level is determined by the default value in `next_nac_used_to_drill`, but because of packet modulation, we let the parent calling function determine this for the function F.
///
/// The security level in the server's nac (`next_nac_used_to_drill`) is a crucial consideration for the admin, because it determines the computational expense of decrypting and re-encrypting packets. The encryption level the InboundPacket contained
/// is not necessarily going to equal the server's level of encryption. By having different encryption levels and different encryption sets, the data appears to be continually morphing as it translates through the network.
///
/// It is NECESSARY that `bridge_session` exists, because data cannot move between a client and some (S+1) until a session is established (for security reasons. The server must make sure both nodes agree to the connection)
pub fn translate_existing_packet_for_forwarding<Input: AsRef<[u8]>, B: ByteSliceMut>(old_packet: &mut ProcessedInboundPacket<B>, bridge_session: HyxeObject<Session>, next_nac_used_to_drill: HyxeObject<NetworkAccount>, next_unencrypted_bytes: Input, next_security_level: &SecurityLevel,
                                                                                     local_send_port: u16, next_dest_port: u16, next_hop_ip: String,
                                                                                     next_amplitudal_sum: &u16, next_wid: f64, next_pid: f64, current_hop_state: PacketHopState, next_hop_state: PacketHopState, network_map_version: u32) -> Result<OutboundPacket<Input>, HyxeError> {
    /**
    We need to change the following values denoted with a *

            cid_original,
            *cid_needed_to_undrill,
            *drill_version_needed_to_undrill,
            *security_level_drilled,
            timestamp,
            *current_packet_hop_state,
            *next_hop_state,
            endpoint_destination_type,
            command_flag,
            expects_response,
            oid_eid,
            *wid,
            *pid,
            route_dest_nid,
            *network_map_version,
            *data
    */

    /// TODO: Figure out a way to craft two packets simultaneously
    let nac = next_nac_used_to_drill.read();
    let next_cid_needed_to_undrill = nac.cid;
    let next_drill_version_opt = nac.get_latest_drill_version();

    if next_drill_version_opt.is_none() {
        return HyxeError::create("[PacketWrapper ERR_NO_DRILL_VERSION_AVAILABLE]");
    }

    let next_drill_version = next_drill_version_opt.unwrap();

    let next_selected_drill_opt = nac.get_drill(next_drill_version as usize);

    if selected_drill_opt.is_none() {
        return HyxeError::create("[PacketWrapper ERR_NO_DRILL_AVAILABLE]");
    }

    let next_selected_drill = next_selected_drill_opt.unwrap();
    //encrypt_bytes<Input: AsRef<[u8]>>(&self, unencrypted_bytes: Input, dst: &mut BytesMut, drill: HyxeObject<Drill>, security_level: &SecurityLevel, amplitudal_sum: &u16, session: Option<HyxeObject<Session>>) -> HyxeResult<usize>
    //let mut next_encrypted_payload = nac.get_message_encryptor().encrypt_bytes(next_unencrypted_bytes, next_selected_drill, next_security_level, next_amplitudal_sum, Some(bridge_session));
    //local_send_port, next_dest_port, next_hop_ip => add these at end after header + encrypt added

    debug_assert!(next_unencrypted_bytes.len() % security_level.get_encrypt_byte_multiplier() == 0);

    let mut packet = BytesMut::with_capacity(HYXE_HEADER_SIZE + (next_unencrypted_bytes.len() / security_level.get_encrypt_byte_multiplier()));

    //packet: &mut BytesMut, next_cid_needed_to_undrill: u64, next_drill_version_needed_to_undrill: u32, next_security_level_drilled: u8, next_current_packet_hop_state: u8, next_hop_state: u8, next_wid: f64, next_pid: f64, network_map_version: u32

    old_packet.get_header().translate_next_forward_packet_header(&mut packet, next_cid_needed_to_undrill, next_drill_version, next_security_level.get_byte_representation(),
                                                                 current_hop_state.value(), next_hop_state.value(), next_wid, next_pid, network_map_version).and_then(move |packet| {
        nac.get_message_encryptor().encrypt_bytes(next_unencrypted_bytes, packet, next_selected_drill, next_security_level, next_amplitudal_sum, Some(bridge_session)).and_then(move |res| {
            debug_assert!(packet.len() == packet.capacity());
            Ok(OutboundPacket {
                src_port: local_send_port,
                dest_ip: next_hop_ip,
                dest_port: next_dest_port,
                data: packet,
            })
        })
    })
}

#[inline]
pub unsafe fn prepend_slice<T: Copy>(vec: &mut Vec<T>, slice: &[T]) {
    let len = vec.len();
    let amt = slice.len();
    vec.reserve(amt);

    ptr::copy(vec.as_ptr(),
              vec.as_mut_ptr().offset((amt) as isize),
              len);
    ptr::copy(slice.as_ptr(),
              vec.as_mut_ptr(),
              amt);
    vec.set_len(len + amt);
}
