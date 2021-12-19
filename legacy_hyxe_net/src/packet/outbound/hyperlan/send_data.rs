//! Sending data is one of the most fundamental and volumnous actions executed in the HyperNetwork.

use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::prelude::Drill;
use crate::connection::network_map::NetworkMap;
use crate::packet::packet_layout::{PacketLayout0D, BaseHeaderConfig, determine_layout, PacketLayout1D, PacketLayout2D};
use hyxe_crypt::misc::CryptError;
use crate::routing::PacketRoute;
use hyxe_crypt::drill::SecurityLevel;
use crate::misc::get_time;
use crate::packet::flags::send_data::SEND_DATA;
use crate::packet::definitions::{OBJECT_HEADER, OBJECT_PAYLOAD};

/// This should NOT be used to forward a packet. This is only for creating a packet from a node that is meant to be dispatched outbound
/// `drill`: This must be the drill which is used for the next hop
/// `route`: As always, the packet route should be created relative to SELF.
pub fn craft_send_data<Drx: DrillType, T: AsRef<[u8]>>(payload: &T, oid_eid: u64, drill: &Drill<Drx>, route: PacketRoute, security_level: SecurityLevel, expects_response: bool, port_start: u16) -> Result<Vec<PacketLayout0D>, CryptError<String>> {
    let payload = payload.as_ref();

    let expects_response= expects_response as u8;

    let cid_needed_to_undrill = drill.get_cid();
    let drill_version_needed_to_undrill = drill.get_version();
    let timestamp = get_time();

    let header_wid = drill.get_wid(0);
    let header_pid = drill.get_pid(0);
    
    let base_header_config_header = BaseHeaderConfig {
        cid_original: route.cid_original,
        cid_needed_to_undrill,
        drill_version_needed_to_undrill,
        security_level_drilled: security_level.value(),
        timestamp,
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        command_flag: SEND_DATA,
        packet_type: OBJECT_HEADER,
        expects_response,
        oid_eid,
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: route.route_dest_cid,
        network_map_version: route.network_map_version
    };

    let base_header_config_payload = BaseHeaderConfig {
        cid_original: route.cid_original,
        cid_needed_to_undrill,
        drill_version_needed_to_undrill,
        security_level_drilled: security_level.value(),
        timestamp,
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        command_flag: SEND_DATA,
        packet_type: OBJECT_PAYLOAD,
        expects_response,
        oid_eid,
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: route.route_dest_cid,
        network_map_version: route.network_map_version
    };

    match determine_layout(payload.len(), drill, security_level) {
        0 => {
            // When we only need 1 packet to send the payload, we will just send the data bundled with the pro-header to save bandwidth (makes no sense to send + ~80 bytes of data)
            let mut ret = Vec::with_capacity(1);
            ret.push(PacketLayout0D::new(payload, drill, security_level, &base_header_config_header, header_wid, header_pid, port_start, port_start)?);
            Ok(ret)
        },

        1 => {
            let mut ret = Vec::new();
            // pro-header
            ret.push(PacketLayout0D::new([], drill, security_level, &base_header_config_header, header_wid, header_pid, port_start, port_start)?);
            // object payload
            ret.extend(PacketLayout1D::new(payload, drill, security_level, &base_header_config_payload, port_start)?);
            Ok(ret)
        },

        2 => {
            let mut ret = Vec::new();
            // pro-header
            ret.push(PacketLayout0D::new([], drill, security_level, &base_header_config_header, header_wid, header_pid, port_start, port_start)?);
            
            for layout1d in PacketLayout2D::new(payload, drill, security_level, &base_header_config_payload, port_start)?.data {
                (&mut ret).extend(layout1d);
            }
            
            Ok(ret)
        },

        _ => {
            unreachable!()
        }
    }
}