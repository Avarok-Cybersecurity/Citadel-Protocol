use crate::packet::inbound::expectancy::ExpectancyResponse;
use crate::connection::stream_wrappers::old::OutboundItem;
use crate::packet::flags::{*};
use crate::routing::PacketRoute;
use hyxe_netdata::packet::OutboundPacket;
use crate::packet::misc::ConnectError;
use crate::packet::outbound::hyperlan::send_data::craft_send_data;
use hyxe_crypt::prelude::{DrillType, SecurityLevel, CryptError};
use hyxe_crypt::drill::Drill;
use crate::packet::packet_layout::{PacketLayout0D, BaseHeaderConfig};
use crate::packet::outbound::hyperlan::login::craft_do_login;
use crate::connection::network_map::NetworkMap;
use hyxe_user::prelude::{NetworkAccount, ClientNetworkAccount, HyperNodeAccountInformation};
use crate::misc::get_time;
use crate::packet::definitions::SINGLETON_PACKET;

/// This function determines which packet to craft, returns the appropriate, and thereafter possibly returns a futures-awaitable [ExpectancyResponse]
/// Currently, the [BridgeHandler] and [ServerBridgeHandler] call this subroutine.
///
/// This is NOT to be called when attempting to forward a packet. This crafts new packets meant to be dispatched outbound from the routing::Self node.
pub fn craft_packet<Drx: DrillType, T: AsRef<[u8]>>(packet_command: u8, cid: u64, eid_oid: u64, port_start: u16, packet_route: PacketRoute, security_level: SecurityLevel, drill: &Drill<Drx>, payload_opt: Option<&T>, expects_response: bool) -> Result<Vec<PacketLayout0D>, CryptError<String>> {
    match packet_command {
        /*
            Implement: § Reserved Section 0 - 9
        **/
        send_data::SEND_DATA => {
            craft_send_data(payload_opt.unwrap(), eid_oid, drill, packet_route, security_level, expects_response, port_start)
        },

        send_data::UPLOAD_DATA => {
            unimplemented!()
        },

        send_data::UPLOAD_DATA_SUCCESS => {
            unimplemented!()
        },

        send_data::UPLOAD_DATA_FAILURE => {
            unimplemented!()
        },

        /*
            Implement: § Reserved Section 10-29
        **/

        connect::DO_LOGIN => {
            craft_do_login(eid_oid, drill,)
        },

        connect::DO_LOGIN_SUCCESS => {
            unimplemented!()
        },

        connect::DO_LOGIN_FAILURE => {
            unimplemented!()
        },

        connect::HYPERLAN_CLIENT_CONNECT => {
            unimplemented!()
        },

        connect::HYPERLAN_CLIENT_CONNECT_REQUEST => {
            unimplemented!()
        },

        connect::HYPERLAN_CLIENT_CONNECT_ACCEPT => {
            unimplemented!()
        },

        connect::HYPERLAN_CLIENT_CONNECT_REJECT => {
            unimplemented!()
        },

        connect::HYPERWAN_CLIENT_CONNECT => {
            unimplemented!()
        },

        connect::HYPERWAN_CLIENT_CONNECT_REQUEST => {
            unimplemented!()
        },

        connect::HYPERWAN_CLIENT_CONNECT_ACCEPT => {
            unimplemented!()
        },

        connect::HYPERWAN_CLIENT_CONNECT_REJECT => {
            unimplemented!()
        },

        /*
            Implement: § Reserved Section 30-39
        **/
        drill_update::DO_DRILL_UPDATE => {
            unimplemented!()
        },

        drill_update::GET_DRILL_STATS => {
            unimplemented!()
        },

        /*
            Implement: § Reserved Section 40-49
        **/

        scan::SCAN_HYPERLAN => {
            unimplemented!()
        },

        scan::SCAN_POTENTIAL_HYPERLAN => {
            unimplemented!()
        },

        scan::SCAN_HYPERWAN => {
            unimplemented!()
        },

        scan::SCAN_POTENTIAL_HYPERWAN => {
            unimplemented!()
        },

        scan::SCAN_SUCCESS => {
            unimplemented!()
        },

        scan::SCAN_FAILURE => {
            unimplemented!()
        },

        /*
            Implement: § Reserved Section 50-59
        **/
        registration::DO_HYPERLAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::DO_HYPERWAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::REQUEST_HYPERLAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::REQUEST_HYPERWAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::ACCEPT_HYPERLAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::ACCEPT_HYPERWAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::DENY_HYPERLAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        registration::DENY_HYPERWAN_CLIENT_REGISTER => {
            unimplemented!()
        },

        /*
            Implement: § Reserved Section 60-69
        **/
        network_map_update::REQUEST_FRESH_MAP => {
            unimplemented!()
        },

        network_map_update::REQUEST_FRESH_MAP => {
            unimplemented!()
        },

        network_map_update::MAP_UPDATE => {
            unimplemented!()
        },

        network_map_update::INTERSERVER_MAP_UPDATE => {
            unimplemented!()
        },

        _ => {
            unimplemented!()
        }
    }
}

/// For crafting signal types. A drill is necessary, because ALL packets must have a valid PID and WID. Since signals are singletons, the PID and WID index are zero
/// `cid`: This should be the destination CID
pub fn craft_signal<Drx: DrillType, T: AsRef<[u8]>>(oid_eid: u64, command_flag: u8, port_local: u16, port_remote: u16, network_map_version: u32, expects_response: bool, packet_route: &PacketRoute, security_level: SecurityLevel, drill: &Drill<Drx>, payload_opt: Option<&T>) -> Result<PacketLayout0D, CryptError<String>> {
    let (pid, wid) = (drill.get_pid(0), drill.get_wid(0));

    let base_header_config = BaseHeaderConfig {
        cid_original: packet_route.cid_original,
        nid_original: packet_route.nid_original,
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: security_level.value(),
        timestamp: get_time(),
        current_packet_hop_state: packet_route.directionality.current_packet_hop_state,
        next_hop_state: packet_route.directionality.next_hop_state,
        endpoint_destination_type: packet_route.directionality.endpoint_destination_type,
        hops_remaining: packet_route.hops_remaining,
        command_flag,
        packet_type: SINGLETON_PACKET,
        expects_response: expects_response as u8,
        oid_eid,
        route_dest_nid: packet_route.route_dest_nid,
        route_dest_cid: packet_route.route_dest_cid,
        network_map_version
    };

    PacketLayout0D::new(payload_opt.unwrap_or(b""), drill, security_level, &base_header_config, wid, pid, port_local, port_remote)
}

/// Oneshot signals are types that are meant to be sent to an immediately adjacent node. It may possibly rebound, but always to the original sender.
pub fn craft_oneshot_signal
    <Drx: DrillType, T: AsRef<[u8]>>
        (eid_oid: u64, command_flag: u8, port_local: u16, port_remote: u16, self_node_type: u8, adjacent_node_type: u8, local_is_server: bool, network_map_version: u32, local_nac: &NetworkAccount, implicated_client: &ClientNetworkAccount, security_level: SecurityLevel, drill: &Drill<Drx>, payload_opt: Option<&T>, expects_response: bool)
            -> Result<PacketLayout0D, CryptError<String>> {

    let packet_route = PacketRoute::prepare_oneshot(self_node_type, adjacent_node_type, local_nac.get_id(), local_is_server, network_map_version, implicated_client, expects_response);

    craft_signal(eid_oid, command_flag, port_local, port_remote, network_map_version, expects_response, &packet_route, security_level, drill, payload_opt)
}