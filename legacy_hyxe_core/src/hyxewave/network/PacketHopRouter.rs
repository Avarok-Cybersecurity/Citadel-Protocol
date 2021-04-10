/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use hyxe_util::HyxeError;

use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::PacketHopRouter::RoutingError::*;

pub enum RoutingError<I> {
    INVALID_NEXT_HOP_STATE(HyxeError),
    INCOMPLETE_ROUTING(HyxeError),
    _PHANTOM(I),
}

impl<I> RoutingError<I> {
    pub fn unfold(&mut self) -> Result<I, HyxeError> {
        match self {
            INVALID_NEXT_HOP_STATE(e) => e.printf(),
            INCOMPLETE_ROUTING(e) => e.printf(),
            _ => HyxeError::throw("NO_ERROR?")
        }
    }

    pub fn silent_unfold(mut self) -> Result<I, HyxeError> {
        match self {
            INVALID_NEXT_HOP_STATE(e) => Err(e),
            INCOMPLETE_ROUTING(e) => Err(e),
            _ => Err(HyxeError("NO_ERROR?".to_string(), false))
        }
    }
}

/// When a client sends a packet, there are different paths (NOTE: <- implies flip in directionality):
/// A: From client to central_server (<-) then back to client (loopback)
/// B: From client to central_server to HyperLAN client (<-) to central_server back to client (loopback)
/// C: From client to central_server to HyperWAN_server (<-) to central_server back to client (loopback)
/// D: From client to central_server to HyperWAN_server to HyperWAN_client (<-) to HyperWAN_server to central_server back to client (loopback)
/// This function sets the packet's initial direction, that way every node downstream will know how to handle it
pub fn determine_initial_packet_direction(cid_initial: u64, packet_hop_state_current: PacketHopState, packet_hop_mainframe_server: PacketHopDestination, packet_hop_destination: PacketHopDestination) -> Result<PacketDirection, HyxeError> {
    //initial_cid: u64, current: PacketHopState, next_hop: PacketHopDestination, destination: PacketHopDestination
    Ok(PacketDirection::new(cid_initial, packet_hop_state_current, packet_hop_mainframe_server, packet_hop_destination))
}

/// Any packet that comes inbound should be processed here, even if it reaches the final node.
/// Returns true if it has reached the final node, false if not, error if invalid packet. This DOES NOT
/// execute for the initial outbound send of a packet from the initial client
pub fn transform_inbound_packet_directionality(mut packet: &mut Packet, localhost_is_server: bool) -> Result<(bool, PacketHopState), HyxeError> {
    //Possibilities: 1. Packet was received at central_server (necessarily sent by client)
    //If this is true, then we can either forward the packet to 1.1) a HyperLAN client, 1.2) a HyperWAN server, or 1.3) a rebound to the client

    //impl 1. We need to make sure that the next_hop inscribed within the packet equals this server, otherwise throw an error due to bad routing or MITM attack

    let new_hop_status_opt = None;
    let cid_

    if let Some(hop_status) = packet.get_hop_status() {
        if Globals::GLOBAL_SESSIONS.lock().cid_exists_locally()
    } else {
        return RoutingError::INCOMPLETE_ROUTING(HyxeError::new("[Routing Error] The hop status feature of the inbound packet was not found; dropping"));
    };

    //2. Packet was received at HyperLAN client. If this is the case, the we must return Ok(true, PacketHopState::AT_HYPERLAN_PEER) and let the calling function execute a rebound_packet (if an EID is present!)

    //3. Packet was received by HyperWAN server. If this is the case, because the name "HyperWAN" is relative to the primary client, the packet must either
    //3.1) bounce back to the central_server (connect or register request?), or, 3.2) forward to a HyperWAN client.

    //4. Packet was received by HyperWAN client. If this is the case, then we must return Ok(true, PacketHopState::AT_HYPERWAN_PEER) and let the calling function execute a rebound_packet
}

/// This function is like `determine_initial_packet_direction`, but going the other way. As the packet hops, it will use the
/// CID in the header (which is actively replaced as it hops around) to determine the direction, but will CONTINUE to PRESERVE the initial CID.
pub fn determine_rebound_packet_direction_from_hyperwan_client(cid_initial: u64) -> Result<PacketDirection, HyxeError> {
    Ok(PacketDirection::new(cid_initial, PacketHopState::AT_HYPERWAN_PEER, PacketHopDestination::TO_HYPERWAN_SERVER, PacketHopDestination::TO_PRIMARY_SENDER))
}


pub enum PacketHopState {
    AT_PRIMARY_SENDER,
    AT_MAINFRAME_SERVER,
    AT_HYPERLAN_PEER,
    AT_HYPERWAN_SERVER,
    AT_HYPERWAN_PEER,
}

impl PacketHopState {
    pub fn value(&self) -> u8 {
        match *self {
            PacketHopState::AT_PRIMARY_SENDER => 0,
            PacketHopState::AT_MAINFRAME_SERVER => 1,
            PacketHopState::AT_HYPERLAN_PEER => 2,
            PacketHopState::AT_HYPERWAN_SERVER => 3,
            PacketHopState::AT_HYPERWAN_PEER => 4
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(PacketHopState::AT_PRIMARY_SENDER),
            1 => Some(PacketHopState::AT_MAINFRAME_SERVER),
            2 => Some(PacketHopState::AT_HYPERLAN_PEER),
            3 => Some(PacketHopState::AT_HYPERWAN_SERVER),
            4 => Some(PacketHopState::AT_HYPERWAN_PEER),
            _ => None
        }
    }
}

pub enum PacketHopDestination {
    TO_PRIMARY_SENDER,
    TO_MAINFRAME_SERVER,
    TO_HYPERLAN_PEER,
    TO_HYPERWAN_SERVER,
    TO_HYPERWAN_PEER,
}

impl PacketHopDestination {
    pub fn value(&self) -> u8 {
        match *self {
            PacketHopDestination::TO_PRIMARY_SENDER => 0,
            PacketHopDestination::TO_MAINFRAME_SERVER => 1,
            PacketHopDestination::TO_HYPERLAN_PEER => 2,
            PacketHopDestination::TO_HYPERWAN_SERVER => 3,
            PacketHopDestination::TO_HYPERWAN_PEER => 4
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(PacketHopDestination::TO_PRIMARY_SENDER),
            1 => Some(PacketHopDestination::TO_MAINFRAME_SERVER),
            2 => Some(PacketHopDestination::TO_HYPERLAN_PEER),
            3 => Some(PacketHopDestination::TO_HYPERWAN_SERVER),
            4 => Some(PacketHopDestination::TO_HYPERWAN_PEER),
            _ => None
        }
    }
}

pub struct PacketDirection {
    ///This is IMPORTANT for determining the direction. As the packet makes hops, the CID of the most recent sender gets updated in the HEADER, but the original CID *MUST* be preserved herein.
    /// When a node receives a packet, then, it must necessarily update the header of the packet, but keep the initial cid preserved towards the END of the header. The servers will have an IP address of connected peers
    /// in the network that will translate the CID to an IP address

    pub initial_cid: u64,
    pub initial_mainframe_server: String,
    pub current: PacketHopState,

    /// Where the packet is going next will be given by:
    /// if packet is at client, then goto mainframe server
    /// if packet is at mainframe server, then [goto next hop
    /// if next hop is hyperlan client, then done
    /// if the next hop is a hyperwan server, then goto
    /// hyperwan client (done). THE DIRECTION OF THE PACKET
    /// IS ALWAYS RELATIVE TO THE INITIAL CLIENT. IF THE PACKET
    /// NEEDS A REBOUND (E.G., EID exists/response needed), THEN
    ///
    pub next_hop: PacketHopDestination,

    ///The destination is inscribed within the dest_ip in the packet header
    pub destination: PacketHopDestination,
}
