use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::prelude::Drill;
use hyxe_crypt::drill_update::DrillUpdateObject;
use crate::packet::packet_layout::{PacketLayout0D, determine_layout, BaseHeaderConfig, PacketLayout1D, PacketLayout2D};
use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::misc::CryptError;
use crate::connection::network_map::{NetworkMap, NetworkSyncMap, ClientViewport};
use std::ops::Try;
use crate::misc::get_time;
use crate::routing;
use crate::packet::definitions::{OBJECT_PAYLOAD, OBJECT_HEADER};
use hyxe_user::prelude::HyperNodeAccountInformation;
use crate::packet::flags::drill_update::DO_DRILL_UPDATE;

/// The default security level for transmitting drill update objects. Mathematically, transporting unencrypted
/// drill update objects is not necessary. However, if we do a wrapping byte shift, then it makes obtaining the
/// key-pairs that much more harder. By using low-security, we don't increase the data size and only cause a
/// byte shift
pub const DRILL_UPDATE_SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;

/// Creates a drill-update waveform. There are a few requirements for this type that make it unique.
/// As usual, the pid and wid must be of a unique index.
///
/// By default, the central server initiates the process of creating the hyper-random numbers. This is to
/// reduce loads caused by the streams of data.
///
/// Before this function is initiated, it is expected that the server's toolset has already generated f(1) = f(0)*U(0..n)
/// `drill_update_object`: The U(0..n) values
///
/// The function returns a [DRILL_UPDATE_OBJECT_HEADER] in the zeroth index, followed by the waveform in the following indexes
pub fn craft_do_drill_update<Drx: DrillType>(previous_drill: &Drill<Drx>, drill_update_object: &DrillUpdateObject, client_viewport: &ClientViewport, port_start: u16) -> Result<Vec<PacketLayout0D>, CryptError<String>> {
    let payload = &drill_update_object.data;
    //let addr_to = client_viewport.client_nac.get_addr(true).into_result().map_err(|_| CryptError::DrillUpdateError("None".to_string()))?;

    let drill_cid = previous_drill.get_cid();
    let drill_version = previous_drill.get_version();

    let time = get_time();

    let route_dest_nid = client_viewport.nid_parent;
    let route_dest_cid = client_viewport.cid_owner;
    let network_map_version = client_viewport.version;

    let base_header_config_header = BaseHeaderConfig {
        cid_original: drill_cid,
        cid_needed_to_undrill: drill_cid,
        drill_version_needed_to_undrill: drill_version,
        security_level_drilled: DRILL_UPDATE_SECURITY_LEVEL.value(),
        timestamp: time,
        current_packet_hop_state: routing::HYPERLAN_SERVER,
        next_hop_state: routing::HYPERWAN_CLIENT,
        endpoint_destination_type: routing::HYPERLAN_CLIENT,
        command_flag: DO_DRILL_UPDATE,
        packet_type: OBJECT_HEADER,
        expects_response: 0, // There is no need for a response. The "response" will be the client sending any packet with the new drill version
        oid_eid: 0, // There is no need for this either
        route_dest_nid,
        route_dest_cid,
        network_map_version
    };

    let base_header_config_payload = BaseHeaderConfig {
        cid_original: drill_cid,
        cid_needed_to_undrill: drill_cid,
        drill_version_needed_to_undrill: previous_drill.get_version(),
        security_level_drilled: DRILL_UPDATE_SECURITY_LEVEL.value(),
        timestamp: time,
        current_packet_hop_state: routing::HYPERLAN_SERVER, // This starts at the local server
        next_hop_state: routing::HYPERLAN_CLIENT, // It gets sent to a HyperLAN client
        endpoint_destination_type: routing::HYPERLAN_CLIENT, // Black hole (implied by next_hop_state == endpoint_destination_type)
        command_flag: DO_DRILL_UPDATE,
        packet_type: OBJECT_PAYLOAD,
        expects_response: 0,
        oid_eid: 0,
        route_dest_nid,
        route_dest_cid,
        network_map_version
    };

    match determine_layout(payload.len(), previous_drill, DRILL_UPDATE_SECURITY_LEVEL) {
        0 => {
            let mut ret = Vec::with_capacity(2);
            ret.push(PacketLayout0D::new([], previous_drill, DRILL_UPDATE_SECURITY_LEVEL, &base_header_config_header, previous_drill.get_wid(0), previous_drill.get_pid(0), port_start, port_start)?);
            ret.push(PacketLayout0D::new(payload, previous_drill, DRILL_UPDATE_SECURITY_LEVEL,&base_header_config_payload, previous_drill.get_wid(0), previous_drill.get_pid(0),port_start, port_start)?);
            Ok(ret)
        },

        1 => {
            let mut ret = Vec::new();
            ret.push(PacketLayout0D::new([], previous_drill, DRILL_UPDATE_SECURITY_LEVEL,&base_header_config_header, previous_drill.get_wid(0), previous_drill.get_pid(0),port_start, port_start)?);
            ret.extend(PacketLayout1D::new(payload, previous_drill, DRILL_UPDATE_SECURITY_LEVEL,&base_header_config_payload, port_start)?);
            Ok(ret)
        },

        2 => {
            let mut ret = Vec::new();
            ret.push(PacketLayout0D::new([], previous_drill, DRILL_UPDATE_SECURITY_LEVEL,&base_header_config_header, previous_drill.get_wid(0), previous_drill.get_pid(0),port_start, port_start)?);
            for layout1d in PacketLayout2D::new(payload, previous_drill, DRILL_UPDATE_SECURITY_LEVEL,&base_header_config_payload, port_start)?.data {
                (&mut ret).extend(layout1d);
            }

            Ok(ret)
        },

        _ => {
            unreachable!()
        }
    }
}