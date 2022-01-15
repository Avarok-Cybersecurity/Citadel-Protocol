use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::prelude::Drill;
use crate::packet::packet_layout::{BaseHeaderConfig, PacketLayout0D};
use secstr::SecVec;
use hyxe_crypt::misc::CryptError;
use hyxe_crypt::drill::SecurityLevel;
use crate::misc::get_time;
use crate::routing;
use crate::packet::flags::connect::{DO_LOGIN, DO_LOGIN_SUCCESS, DO_LOGIN_FAILURE};
use crate::packet::definitions::{SINGLETON_PACKET, DEFAULT_AUXILIARY_PORTS};
use crate::connection::stream_wrappers::old::OutboundItem;
use crate::connection::network_map::{NetworkMap, NetworkSyncMap};


/// A login needs three important data chunks:
/// [1] A valid zero-index pid
/// [2] A valid zero-index wid
/// [3] A valid unencrypted(username), unencrypted(password) (encryption takes place herein)
/// All [1], [2], and [3] must use the LATEST drill version
///
/// `drill`: The LATEST Drill of the client logging in
/// `network_map`: This should be the network map synchronized with the central server which you expect to login to
///
/// Drill index: 0
pub fn craft_do_login<Drx: DrillType, T: AsRef<[u8]>>(oid_eid: u64, drill: &Drill<Drx>, network_map: &NetworkMap, username: &T, password_bytes: SecVec<u8>) -> Result<PacketLayout0D, CryptError<String>> {
    let payload: &[u8] = [username.as_ref(), b',', password_bytes.unsecure()].concat();
    let payload = drill.encrypt_to_vec(payload)?;
    let pid = drill.get_pid(0);
    let wid = drill.get_wid(0);

    let base_header_config = BaseHeaderConfig {
        cid_original: drill.get_cid(),
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: SecurityLevel::DIVINE.value(),
        timestamp: get_time(),
        current_packet_hop_state: routing::HYPERLAN_CLIENT, // Start at client (implied)
        next_hop_state: routing::HYPERLAN_SERVER, // Rebound from server
        endpoint_destination_type: routing::HYPERLAN_CLIENT, // return to self
        command_flag: DO_LOGIN,
        packet_type: SINGLETON_PACKET,
        expects_response: 1,
        oid_eid,
        route_dest_nid: network_map.get_owner_nid(),
        route_dest_cid: drill.get_cid(), // isn't actually needed
        network_map_version: 0
    };

    PacketLayout0D::new(payload.as_slice(), drill, SecurityLevel::DIVINE, &network_map.get_central_server_ip().to_string(), &base_header_config, wid, pid, DEFAULT_AUXILIARY_PORTS[0], DEFAULT_AUXILIARY_PORTS[0])
}

/// The DO_LOGIN_SUCCESS, unlike the DO_LOGIN, does not transmit a password. Instead, it uses a different drill index
/// for the WID and PIDs
/// `oid_eid`: This should be equal to the `oid_eid` received from the DO_LOGIN request
///
/// Drill index: 1
pub fn craft_do_login_success<Drx: DrillType, T: AsRef<[u8]>>(oid_eid: u64, drill: &Drill<Drx>, client_dest_nid: u64, network_map: &NetworkMap, welcome_message: Option<T>) -> Result<PacketLayout0D, CryptError<String>> {
    let pid = drill.get_pid(1);
    let wid = drill.get_wid(1);

    let base_header_config = BaseHeaderConfig {
        cid_original: drill.get_cid(),
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: SecurityLevel::DIVINE.value(),
        timestamp: get_time(),
        current_packet_hop_state: routing::HYPERLAN_SERVER, // Start at server
        next_hop_state: routing::HYPERLAN_CLIENT, // Arrive to client
        endpoint_destination_type: routing::HYPERLAN_CLIENT, // black hole
        command_flag: DO_LOGIN_SUCCESS,
        packet_type: SINGLETON_PACKET,
        expects_response: 1,
        oid_eid,
        route_dest_nid: network_map.get_owner_nid(),
        route_dest_cid: drill.get_cid(), // isn't actually needed
        network_map_version: 0
    };

    PacketLayout0D::new(welcome_message.unwrap_or(b""), drill, SecurityLevel::DIVINE, &base_header_config, wid, pid, DEFAULT_AUXILIARY_PORTS[0], DEFAULT_AUXILIARY_PORTS[0])
}

/// This is similar to the DO_LOGIN_SUCCESS, except the message failed. Furthermore, the WID and PID indexes are different
///
/// Drill index: 2
pub fn craft_do_login_failure<Drx: DrillType, T: AsRef<[u8]>>(oid_eid: u64, drill: &Drill<Drx>, client_dest_nid: u64, network_map: &NetworkMap, error_message: Option<T>) -> Result<PacketLayout0D, CryptError<String>> {
    let pid = drill.get_pid(2);
    let wid = drill.get_wid(2);

    let base_header_config = BaseHeaderConfig {
        cid_original: drill.get_cid(),
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: SecurityLevel::DIVINE.value(),
        timestamp: get_time(),
        current_packet_hop_state: routing::HYPERLAN_SERVER, // Start at server
        next_hop_state: routing::HYPERLAN_CLIENT, // Arrive to client
        endpoint_destination_type: routing::HYPERLAN_CLIENT, // black hole
        command_flag: DO_LOGIN_FAILURE,
        packet_type: SINGLETON_PACKET,
        expects_response: 1,
        oid_eid,
        route_dest_nid: network_map.get_owner_nid(),
        route_dest_cid: drill.get_cid(), // isn't actually needed
        network_map_version: 0
    };

    PacketLayout0D::new(error_message.unwrap_or(b""), drill, SecurityLevel::DIVINE, &base_header_config, wid, pid, DEFAULT_AUXILIARY_PORTS[0], DEFAULT_AUXILIARY_PORTS[0])
}