use crate::packet::misc::ConnectError;
use crate::routing::{HYPERWAN_CLIENT, HYPERWAN_SERVER, HYPERLAN_SERVER, HYPERLAN_CLIENT};
use hyxe_netdata::packet::StageDriverPacket;
use crate::connection::network_map::NetworkMap;
use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::misc::CryptError;
use hyxe_crypt::prelude::Drill;
use hyxe_crypt::drill::SecurityLevel;
use std::ops::Try;
use zerocopy::AsBytes;

/// This takes a recent external inbound packet and generates its next packet route. If there
/// are no further steps, and the destination is reached, then this will return `true` and no
/// further changes will be altered unto the header
///
/// This will return an Error if the packet has an improperly formatted header
///
/// This does NOT perform a complete packet translation. Any information regarding the drill
/// must be manually updated. This subroutine only updates the routing details to prepare it for
/// the next outbound dispatch
///
/// `packet`: This packet should NOT have any routing details updated prior to this function call
pub fn translate_packet_route_details(mut packet: &mut StageDriverPacket, local_network_map: &NetworkMap) -> Result<bool, ConnectError> {
    let header = packet.get_mut_header();

    let previous_point_type = header.current_packet_hop_state; // this changes each hop
    let this_point_type = header.next_hop_state; // this also changes between each hop. We need to verify that this is valid, however. TODO: Verification
    let endpoint_type = header.endpoint_destination_type; // this is constant throughout translation

    let hops_left = header.hops_remaining; // The real value is now 1 less than this. First, ensure the value is greater than or equal to 1
    // Max hops in the network is 3-inclusive, the min is 1
    if hops_left > 0 && hops_left < 4 {
        let hops_left_now = hops_left - 1;
        if hops_left_now != 0 {
            // possibility: packet is relatively at a HyperLAN Server, and must next go to a HyperLAN client (rebounds OK). This is true if hops_left == 1 and
            // endpoint_type == HyperLAN Client
            if hops_left_now == 1 && this_point_type == HYPERLAN_SERVER && endpoint_type == HYPERLAN_CLIENT {
                debug_assert_eq!(header.route_dest_nid.get(), 0);
                // We must update the current packet hop state, as well as the next packet hop state, as well as the next ip to send to, and finally decrement
                // the packet hop count by 1
                match local_network_map.read().get_nid_from_cid(header.route_dest_cid.get()) {
                    Some(nid) => {
                        header.route_dest_nid.set(nid);
                        header.current_packet_hop_state = HYPERLAN_SERVER;
                        header.next_hop_state = HYPERLAN_CLIENT;
                        header.hops_remaining = 1;
                    },

                    None => {
                        Err(ConnectError::BadRoute)
                    }
                }
            }

            // possibility: packet is relatively at a HyperLAN Server, and must next go to a HyperWAN Server (this is necessarily all other cases at this logical
            // point in the gate series, even if its endpoint is a HyperWAN Client)
            else if hops_left_now == 2 && this_point_type == HYPERLAN_SERVER && (endpoint_type == HYPERWAN_SERVER || endpoint_type == HYPERWAN_CLIENT) {
                header.current_packet_hop_state = HYPERLAN_SERVER;
                header.next_hop_state = HYPERWAN_SERVER;
                header.hops_remaining -= 1;
            }
            // possibility: packet is relatively at a HyperWAN Server, and must next go to a HyperWAN Client. This is true if hops_left == 1 and endpoint_type
            // == HyperWAN Client
            else if hops_left_now == 1 && this_point_type == HYPERWAN_SERVER && endpoint_type == HYPERWAN_CLIENT {
                debug_assert_eq!(header.route_dest_nid.get(), 0);
                // Since this packet is going to the destination in the HyperWAN, we must not forget to change the `route_dest_nid` from 0 to the actual value
                // To do this, we need only check the network map
                match local_network_map.read().get_nid_from_cid(header.route_dest_cid.get()) {
                    Some(nid) => {
                        header.route_dest_nid.set(nid);
                        header.current_packet_hop_state = HYPERWAN_SERVER;
                        header.next_hop_state = HYPERWAN_CLIENT;

                        header.hops_remaining = 1; // one hop left; from the HyperWAN Server to the HyperWAN Client
                    },

                    None => {
                        Err(ConnectError::BadRoute)
                    }
                }
            }

            else {
                return Err(ConnectError::BadRoute);
            }

            Ok(false)
        } else {
            // packet has reached its supposed destination
            Ok(true)
        }
    } else {
        Err(ConnectError::OutOfBoundsError)
    }
}

/// This asynchronously decrypts a packet's payload and then re-encrypts it as necessary. This should be called AFTER `translate_packet_route_details`.
/// The drill version and cid needed to undrill fields of the header should NOT be altered before this subroutine. Once this is done
/// executing, the packet's subfields will be appropriately altered thatway the next node can correctly undrill the information
/// `new_payload`: If this is None, then the payload will simply be decrypted and then re-encrypted
pub async fn translate_packet_payload<T: AsRef<[u8]>, DrxPrevious: DrillType, DrxNext: DrillType>(mut packet: StageDriverPacket, amplitudal_sigma_previous: usize, amplitudal_sigma_next: usize, drill_needed_to_undrill: &Drill<DrxPrevious>, drill_next: &Drill<DrxNext>, new_payload: Option<&T>) -> Result<(), CryptError<String>> {
    // Use an inner closure to confine the borrow lifetimes
    {
        let header = packet.get_header();

        let drill_version_needed_to_undrill = header.drill_version_needed_to_undrill.get();
        let cid_needed_to_undrill = header.cid_needed_to_undrill.get();
        let security_level = SecurityLevel::for_value_ok(header.security_level_drilled as usize)?;
        // These checks will be optimized-away for production release
        debug_assert_eq!(drill_version_needed_to_undrill, drill_needed_to_undrill.get_version());
        debug_assert_eq!(cid_needed_to_undrill, drill_needed_to_undrill.get_cid());
    }

    {
        let payload = packet.get_payload();

        let unencrypted_bytes = drill_needed_to_undrill.async_decrypt_to_vec(payload, amplitudal_sigma_previous, security_level).await?;
        packet.ensure_payload_capacity(security_level.get_expected_decrypted_len(unencrypted_bytes.len()));
    }

    {
        let payload = packet.get_mut_payload();
        let re_encrypted_bytes = drill_next.async_encrypt_into_slice(&unencrypted_bytes, payload, amplitudal_sigma_next, security_level).await?; // decrypts directly into the packet's payload
    }

    // Now that the payload has been decrypted and re-encrypted with the new drill, we must update the packet's header to ensure the next recipient can properly undrill the payload

    let header = packet.get_mut_header();

    // We only need to update the drill's CID owner as well as the drill version thereof.
    // The security level remains constant, as each middle node, by default, respects the
    // the request of the security level.
    header.cid_needed_to_undrill.set(drill_next.get_cid());
    header.drill_version_needed_to_undrill.set(drill_next.get_version());

    Ok(())
}

