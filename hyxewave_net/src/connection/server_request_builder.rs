/// For organization, I'll split the sink. Herein lies both the sink (which forwards data to the socket), as well as the OutboundRequestBuilder
pub mod outbound {
    use hyxe_crypt::drill::SecurityLevel;

    pub struct ServerRequest<'a, T: AsRef<[u8]> + 'a> {
        security_level: Option<SecurityLevel>,
        destination_nid: Option<u64>,
        destination_cid: Option<u64>,
        data: Option<&'a T>
    }

    impl<'a, T: AsRef<[u8]> + 'a> ServerRequest<'a, T> {
        pub fn new() -> Self {
            Self { ..Default::default() }
        }
    }

    /**

    expects_response: bool, command_flag: u8, packet_route: PacketRoute, data: &'cxn T

    fn create_packet_with_cfg<T: AsRef<[u8]>>(payload: &T, cfg: &BaseHeaderConfig, pid: f64, wid: f64) -> OutboundItem {
    let payload = payload.as_ref();

    let header = ProcessedPacketHeader::craft(cfg.cid_original,
                                              cfg.cid_needed_to_undrill,
                                              cfg.drill_version_needed_to_undrill,
                                              cfg.security_level_drilled,
                                              cfg.timestamp,
                                              cfg.current_packet_hop_state,
                                              cfg.next_hop_state,
                                              cfg.endpoint_destination_type,
                                              cfg.command_flag,
                                              cfg.expects_response,
                                              cfg.oid_eid,
                                              wid.to_bits(),
                                              pid.to_bits(),
                                              cfg.route_dest_nid,
                                              cfg.route_dest_cid,
                                              cfg.network_map_version);
    let mut packet = Vec::with_capacity(PACKET_HEADER_BYTE_COUNT + payload.len());
    header.inscribe_into(&mut packet);
    packet.extend(payload);
    packet
}
    */
}

/// This is for communicating with the internal [Server]
pub mod internal {
    /// This is for sending requests to the internal server. Examples include:
    /// [1] Scanning for HyperWAN client
    /// [2] Scanning for
    pub enum InternalRequest {

    }
}

///