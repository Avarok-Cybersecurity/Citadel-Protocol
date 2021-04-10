/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use parking_lot::Mutex;
use tokio::prelude::Future;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::{HyxeObject, SecurityLevel};
use crate::hyxewave::encrypt::WaveFormGenerator::PacketSeriesLayout;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::network::Packet::{OutboundPacket, Packet, ProcessedInboundPacket};
use crate::hyxewave::network::PacketHopRouter::PacketHopDestination;
use crate::hyxewave::network::PacketSeriesListener::PacketSeriesListener;
use crate::hyxewave::network::PacketWrapper;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::SessionHandler::Session;
use crate::hyxewave::network::SocketHandler::PacketType;

/// If a session is already established, then the packet is an equivalent to a KEEP_ALIVE. This packet requires security, otherwise it may be susceptible to MITM attacks via IP spoofing
pub fn generate_connect_packet(session: Option<HyxeObject<Session>>, nac: HyxeObject<NetworkAccount>, username: &String, password: &String, security_level: &SecurityLevel, drill_version: u32, oid_eid: u64) -> Option<OutboundPacket> {
    //first, validate password
    let nac = nac.read();
    if !nac.validate_password(password.as_ref()) {
        return None;
    }

    let drill_version_opt = nac.get_latest_drill_version();
    if drill_version_opt.is_none() {
        return None;
    }

    let drill_version = drill_version_opt.unwrap();

    let aux_port_0 = nac.get_aux_ports()[0];

    let mut payload = unsafe { password.into_bytes() };

    PacketWrapper::wrap_new_packet(session, nac, &payload, security_level, drill_version, 1, aux_port_0, aux_port_0, 0, PacketHopDestination::TO_MAINFRAME_SERVER, Constants::Flags::DO_CONNECT, oid_eid, 0 as f64, 0 as f64, &0)
}

/// This function should only be ran by MAINFRAME SERVERS returning a packet to a node in the HyperLAN. We will later create a function that applies to the connection between two MAINFRAME SERVERS
/// We leave `session` as possibly non-existent, because the connection request (or keep alives; they have the same calculi in this program) may have failed.
pub fn generate_connect_rebound_packet(session: Option<HyxeObject<Session>>, nac: HyxeObject<NetworkAccount>, ip_to: &String, login_success: bool, message: Option<String>, oid_eid: u64) -> Option<OutboundPacket> {
    let nac = nac.read();
    let drill_version_opt = nac.get_latest_drill_version();

    if drill_version_opt.is_none() {
        return None;
    }

    let cid = nac.cid;
    let central_node = nac.get_central_node_ip().clone();
    let security_level = nac.get_security_level();
    let drill_version = drill_version_opt.unwrap();


    let src_port = nac.get_aux_ports()[0];
    let command_flag = {
        if login_success {
            Constants::Flags::DO_CONNECT_SUCCESS
        } else {
            Constants::Flags::DO_CONNECT_FAILURE
        }
    };

    let mut data = Vec::new();
    if let Some(mut message) = message {
        let v = message.into_bytes();
        for byte in v.iter() {
            data.push(*byte);
        }
    }

    PacketWrapper::wrap_new_packet(session, nac, &data, &security_level, drill_version, 0, src_port, src_port, cid, PacketHopDestination::TO_PRIMARY_SENDER, command_flag, oid_eid, 0 as f64, 0 as f64, &0)
}

///We need the `packets_in_column` in order for the adjacent node to know how many packets to expect in this column
/// For each column that is sent out, this should be sent out beforehand!
/// The WID doubles as the EID for memory efficiency purposes, as well as the purpose that the will expect a verification from the server for consistency purposes
/// This is a pseudo-wave packet header, because it is just a singleton with 0-coords (except wid_eid)
pub fn generate_column_header_packet(session: HyxeObject<Session>, ip_to: &String, wid_eid: f64, packets_in_column: u16, drill_version: u32) -> Option<ProcessedInboundPacket> {
    let mut nac = session.read().get_nac().read();
    let central_node = nac.get_central_node_ip().clone();
    let packets_in_column_bytes = packets_in_column.to_be_bytes().to_vec();
    let src_ip = Constants::LOCALHOST.to_string();
    let src_port = nac.get_aux_ports()[0];

    //session: HyxeObject<Session>, mut payload: Vec<u8>, central_node: String, src_ip: String, src_port: u16, dest_ip: String, dest_port: u16, pid: u16, wid: f64, v_time: u16, z_time: u16, oid: u64, flag: u8, eid: Option<u64>, drill_version: u32, packet_type: PacketType
    PacketWrapper::wrap_wave_data(session, packets_in_column_bytes, central_node, src_ip, src_port, ip_to.clone(), src_port, 0, wid_eid, 0, 0, 0, Constants::Flags::PACKET_COLUMN_HEADER, None, drill_version, PacketType::WAVE)
}

/// This is sent out even if there is n=1 packet_column_headers also sent out.
/// `num_packet_columns` is translated into bytes, as this is the information most relevant for purpose of verification and expectation on the adjacent node
pub fn generate_object_header_packet(session: HyxeObject<Session>, ip_to: &String, oid_eid: u64, num_packet_columns: u64, drill_version: u32) -> Option<ProcessedInboundPacket> {
    let mut nac = session.read().get_nac().read();
    let central_node = nac.get_central_node_ip().clone();
    let packet_columns_bytes = num_packet_columns.to_be_bytes().to_vec();
    let src_ip = Constants::LOCALHOST.to_string();
    let src_port = nac.get_aux_ports()[0];

    PacketWrapper::wrap_linear_data(Some(session), nac, packets_in_column_bytes, central_node, src_ip, src_port, ip_to.clone(), src_port, Constants::Flags::OBJECT_HEADER, Some(oid_eid), drill_version)
}

pub fn generate_wave_packet(session: HyxeObject<Session>, src_port: u16, dest_port: u16, ip_to: &String, wid_eid: f64, oid: u64, payload: Vec<u8>, drill_version: u32) -> Option<ProcessedInboundPacket> {
    let mut nac = session.read().get_nac().read();
    let central_node = nac.get_central_node_ip().clone();
    let packet_columns_bytes = packet_columns.to_be_bytes().to_vec();
    let src_ip = Constants::LOCALHOST.to_string();

    PacketWrapper::wrap_wave_data(session, payload, central_node, src_ip, src_port, ip_to.clone(), dest_port, 0, wid_eid, 0, 0, oid, Constants::Flags::D5, None, drill_version, PacketType::WAVE)
}


///This returns a header packet (which should be sent out first), then a scrambled array of packets to be sent-out
/// We make this a future because potentially lots of data has to be inscribed, and we don't want to block the async core!
pub fn convert_packet_layout_to_packets(wave_layout: PacketSeriesLayout) -> impl Future<Item=((Packet, Vec<Packet>)), Error=HyxeError> {
    futures::lazy(move || {})
}