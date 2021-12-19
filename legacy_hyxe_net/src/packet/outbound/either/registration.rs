use crate::routing::PacketRoute;
use crate::packet::packet_layout::{PacketLayout0D, BaseHeaderConfig, create_packet_with_cfg, determine_layout, PacketLayout2D, generate_raw_layout_sequential};
use crate::packet::misc::ConnectError;
use crate::misc::get_time;
use crate::packet::flags::registration::{DO_HYPERLAN_CLIENT_REGISTER, DO_HYPERWAN_CLIENT_REGISTER, ACCEPT_HYPERLAN_CLIENT_REGISTER, ACCEPT_HYPERWAN_CLIENT_REGISTER, DENY_HYPERLAN_CLIENT_REGISTER, DENY_HYPERWAN_CLIENT_REGISTER};
use crate::packet::definitions::{SINGLETON_PACKET, REGISTRATION_PORT, OBJECT_HEADER, OBJECT_PAYLOAD};
use crate::packet::definitions::registration::{STAGE0_SERVER, STAGE1_CLIENT, STAGE2_CLIENT, STAGE3_SERVER, REGISTRATION_COMPLETE, STAGE3_CLIENT, STAGE1_SERVER};
use hyxe_user::client_account::{ClientNetworkAccountInner, ClientNetworkAccount};
use bytes::BufMut;
use hyxe_util::prelude::BytesMut;
use crate::packet::bit_handler::apply_nonce;
use hyxe_user::prelude::HyperNodeAccountInformation;
use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::drill::SecurityLevel;
use crate::packet::MAX_PAYLOAD_SIZE;
use hyxe_crypt::prelude::HyperEncryptor;
use hyxe_user::misc::check_credential_formatting;

/// Client -> HyperLAN/WAN Stage 0 Client. WARNING: This DOES NOT check the username, password, and full_name for validity
pub fn craft_stage0_client<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(route: &PacketRoute, username: &T, password: &R, full_name: &V, adjacent_is_hyperlan: bool, network_map_version: u32) -> Result<PacketLayout0D, ConnectError> {

    let adjacent_is_hyperlan_repr = {
        if adjacent_is_hyperlan {
            b"1"
        } else {
            b"0"
        }
    };

    let payload: &str = [adjacent_is_hyperlan_repr, username.as_ref(), password.as_ref(), full_name.as_ref()].join(",");

    let command_flag = {
        if adjacent_is_hyperlan {
            DO_HYPERLAN_CLIENT_REGISTER
        } else {
            DO_HYPERWAN_CLIENT_REGISTER
        }
    };

    let base_header_config = BaseHeaderConfig {
        cid_original: 0,
        nid_original: route.nid_original,
        cid_needed_to_undrill: 0, // no CID is setup yet
        drill_version_needed_to_undrill: 0, // this is also irrelevant
        security_level_drilled: 0, // irrelevant
        timestamp: get_time(),
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining, // this should be equal to either 1 or 2 hops
        command_flag,
        packet_type: SINGLETON_PACKET,
        expects_response: 1, // We expect a response
        oid_eid: STAGE1_SERVER as u64, // we point to the step expected to be executed upon arrival to the appropriate node
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: 0, // This should be equal to zero always
        network_map_version
    };

    Ok(PacketLayout0D { data: create_packet_with_cfg(payload, &base_header_config, 0.0, 0.0), port_mapping: (REGISTRATION_PORT, REGISTRATION_PORT) })
}

/// HyperLAN/WAN -> Client Stage1 Server. The server tells the client to either expect an object header or not
/// `nonce`: This must be `Some` if `accept` is true
pub fn craft_stage1_server(route: &PacketRoute, accept: bool, adjacent_is_hyperlan: bool, nonce: Option<u64>, network_map_version: u32) -> Result<PacketLayout0D, ConnectError> {
    debug_assert!((accept && nonce.is_some()) || (!accept && nonce.is_none()));

    let command_flag = {
        if accept {
            if adjacent_is_hyperlan {
                ACCEPT_HYPERLAN_CLIENT_REGISTER
            } else {
                ACCEPT_HYPERWAN_CLIENT_REGISTER
            }
        } else {
            if adjacent_is_hyperlan {
                DENY_HYPERLAN_CLIENT_REGISTER
            } else {
                DENY_HYPERWAN_CLIENT_REGISTER
            }
        }
    };

    let base_header_config = BaseHeaderConfig {
        cid_original: 0,
        nid_original: route.nid_original,
        cid_needed_to_undrill: 0, // irrelevant still
        drill_version_needed_to_undrill: 0, // " "
        security_level_drilled: 0, // " "
        timestamp: get_time(),
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining,
        command_flag,
        packet_type: SINGLETON_PACKET,
        expects_response: 1,
        oid_eid: STAGE1_CLIENT as u64, // point to the correct action
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: 0, // Should still be zero. No CID has been generated yet
        network_map_version
    };

    Ok(PacketLayout0D { data: create_packet_with_cfg(nonce.unwrap_or(0 as u64).to_be_bytes(), &base_header_config, 0.0, 0.0), port_mapping: (REGISTRATION_PORT, REGISTRATION_PORT) })
}

/// HyperLAN/WAN Server -> Client (Stage 2 server; send serialized CNAC object). It is expected that any other handles of `cnac` are not concurrently modifying the inner device
/// This applies the `nonce` to the serialized bytes of `cnac`
pub fn craft_stage2_server(cnac: &mut ClientNetworkAccount, route: &PacketRoute, adjacent_is_hyperlan: bool, nonce: u64, network_map_version: u32) -> Result<Vec<PacketLayout0D>, ConnectError> {
    let bytes_unnonced = cnac.generate_bytes_sync().map_err(|err| ConnectError::Generic(err.to_string()))?;

    let cid = cnac.get_id();
    let bytes_nonced = apply_nonce(&bytes_unnonced, nonce);

    let command_flag = {
        if adjacent_is_hyperlan {
            DO_HYPERLAN_CLIENT_REGISTER
        } else {
            DO_HYPERWAN_CLIENT_REGISTER
        }
    };

    let timestamp = get_time();

    let base_header_config = BaseHeaderConfig {
        cid_original: route.cid_original, // being the server, this is zero
        nid_original: route.nid_original,
        cid_needed_to_undrill: 0,
        drill_version_needed_to_undrill: 0,
        security_level_drilled: 0,
        timestamp,
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining,
        command_flag,
        packet_type: OBJECT_PAYLOAD,
        expects_response: 0,
        oid_eid: 0,
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: cid, // we can now add the CID to the header, since we have a valid cid generated
        network_map_version
    };

    let object_header_config = BaseHeaderConfig {
        cid_original: route.cid_original,
        nid_original: route.nid_original,
        cid_needed_to_undrill: 0,
        drill_version_needed_to_undrill: 0,
        security_level_drilled: 0,
        timestamp,
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining,
        command_flag,
        packet_type: OBJECT_HEADER,
        expects_response: 1, // Yes, we expect a response after the client has
        oid_eid: STAGE2_CLIENT as u64,
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: cid,
        network_map_version
    };

    let header = PacketLayout0D { data: create_packet_with_cfg([], &object_header_config, 0.0, 0.0), port_mapping: (REGISTRATION_PORT, REGISTRATION_PORT) };

    // This creates the object payload; however, we need to prepend the OBJECT_HEADER to ensure the receiving node is prepared to receive this
    let object_payload = generate_raw_layout_sequential(&bytes_nonced, &base_header_config, REGISTRATION_PORT, REGISTRATION_PORT);

    let mut output = Vec::with_capacity(object_payload.len() + 1);
    output.push(header);
    output.extend(object_payload);

    Ok(output)
}

/// Client -> HyperWAN/LAN Server
pub fn craft_stage2_client(cnac: &ClientNetworkAccount, route: &PacketRoute, adjacent_is_hyperlan: bool, network_map_version: u32) -> Result<PacketLayout0D, ConnectError> {
    let cid = cnac.get_id();
    let drill = cnac.read().toolset.get_most_recent_drill().unwrap();

    let zero_index_pid = drill.get_pid(0); // The adjacent endpoint will ensure their zero-index PID is also equal to this value
    let zero_index_wid = drill.get_wid(0);

    let command_flag = {
        if adjacent_is_hyperlan {
            DO_HYPERLAN_CLIENT_REGISTER
        } else {
            DO_HYPERWAN_CLIENT_REGISTER
        }
    };

    let base_header_config = BaseHeaderConfig {
        cid_original: route.cid_original,
        nid_original: route.nid_original,
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: 0, // irrelevent
        timestamp: get_time(),
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining,
        command_flag,
        packet_type: SINGLETON_PACKET,
        expects_response: 1,
        oid_eid: STAGE3_SERVER as u64,
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: route.route_dest_cid,
        network_map_version
    };

    Ok(PacketLayout0D { data: create_packet_with_cfg([], &base_header_config, zero_index_pid, zero_index_wid), port_mapping: (REGISTRATION_PORT, REGISTRATION_PORT) })
}

/// HyperLAN/WAN Server -> Client. This is the final signal sent, thus concluding the registration process. The payload welcome message is encrypted per usual
/// This will return an error if the payload expands beyond the max payload size
pub fn craft_stage3_server<T: AsRef<[u8]>>(cnac: &ClientNetworkAccount, route: &PacketRoute, adjacent_is_hyperlan: bool, security_level: SecurityLevel, welcome_message: Option<&T>, network_map_version: u32) -> Result<PacketLayout0D, ConnectError> {
    let welcome_message = welcome_message.unwrap_or(b"").as_ref();
    if security_level.get_expected_encrypted_len(welcome_message.len()) > MAX_PAYLOAD_SIZE {
        return Err(ConnectError::OutOfBoundsError);
    }

    let cid = cnac.get_id();
    let drill = cnac.read().toolset.get_most_recent_drill().unwrap();

    let command_flag = {
        if adjacent_is_hyperlan {
            ACCEPT_HYPERLAN_CLIENT_REGISTER
        } else {
            ACCEPT_HYPERWAN_CLIENT_REGISTER
        }
    };

    let base_header_config = BaseHeaderConfig {
        cid_original: route.cid_original,
        nid_original: route.nid_original,
        cid_needed_to_undrill: drill.get_cid(),
        drill_version_needed_to_undrill: drill.get_version(),
        security_level_drilled: security_level.value(),
        timestamp: get_time(),
        current_packet_hop_state: route.directionality.current_packet_hop_state,
        next_hop_state: route.directionality.next_hop_state,
        endpoint_destination_type: route.directionality.endpoint_destination_type,
        hops_remaining: route.hops_remaining,
        command_flag,
        packet_type: SINGLETON_PACKET,
        expects_response: 0, // This is the last packet that will get sent; there is no more need for expecting a response
        oid_eid: STAGE3_CLIENT as u64, // signal the last step
        route_dest_nid: route.route_dest_nid,
        route_dest_cid: route.route_dest_cid,
        network_map_version
    };

    let encrypted_payload = drill.encrypt_to_vec(welcome_message, 0, security_level).map_err(|err| ConnectError::Generic(err.to_string()))?;

    Ok(PacketLayout0D { data: encrypted_payload, port_mapping: (REGISTRATION_PORT, REGISTRATION_PORT) })
}