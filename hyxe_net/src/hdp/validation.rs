pub(crate) mod do_connect {
    use byteorder::{BigEndian, ByteOrder};
    use secstr::SecVec;
    use zerocopy::LayoutVerified;

    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::error::NetworkError;
    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::peer::peer_layer::MailboxTransfer;
    use hyxe_fs::prelude::SyncIO;

    /// Here, Bob receives a payload of the encrypted username + password. We must verify the login data is valid
    pub(crate) fn validate_stage0_packet(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Result<(), NetworkError> {
        // Now, validate the username and password. The payload is already decrypted
        let split_idx = header.context_info.get() as usize;
        if split_idx > payload.len() {
            Err(NetworkError::InvalidPacket("Packet has an oob username/password split index. Dropping"))
        } else {
            let (username, password) = payload.split_at(split_idx);
            cnac.validate_credentials(username, SecVec::new(Vec::from(password))).map_err(|err| NetworkError::Generic(err.to_string()))?;
            log::info!("Success validating credentials!");
            Ok(())
        }
    }

    pub(crate) fn validate_final_status_packet(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Result<Option<(Vec<u8>, Option<MailboxTransfer>, Vec<u64>)>, ()> {
        let msg_len = header.context_info.get() as usize;
        let mailbox_len = header.group.get() as usize;

        let (msg, mailbox_transfer_and_peers_bytes) = payload.split_at(msg_len);
        let (mailbox_transfer_bytes, peers_bytes) = mailbox_transfer_and_peers_bytes.split_at(mailbox_len);

        let mailbox = if mailbox_transfer_bytes.len() != 0 {
            Some(MailboxTransfer::deserialize_from_vector(mailbox_transfer_bytes).map_err(|_|())?)
        } else {
            None
        };

        if peers_bytes.len() % 8 != 0 {
            log::error!("Final status packet has invalid peer_bytes length");
            return Err(());
        }

        let peers = peers_bytes.chunks_exact(8).map(|vals| BigEndian::read_u64(vals)).collect::<Vec<u64>>();

        Ok(Some((Vec::from(msg), mailbox, peers)))
    }
}

pub(crate) mod keep_alive {
    use bytes::{Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use hyxe_user::prelude::ClientNetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;

    /// Returns Ok(false) if expired.
            /// Returns Ok(true) if valid
            /// Return Err(_) if getting the drill failed or the security params were false
    pub(crate) fn validate_keep_alive<'a, 'b: 'a>(cnac: &ClientNetworkAccount, header: &'b Bytes, payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, HyperRatchet)> {
        super::aead::validate(cnac,header, payload)
    }
}

pub(crate) mod group {
    use std::ops::RangeInclusive;

    use byteorder::{BigEndian, ByteOrder};
    use bytes::{Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use hyxe_crypt::net::crypt_splitter::GroupReceiverConfig;

    //use crate::hdp::file_transfer::MAX_GROUP_PLAINTEXT_LEN;
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::error::NetworkError;
    use crate::hdp::hdp_packet::{HdpHeader, packet_sizes};
    use crate::hdp::state_container::VirtualTargetType;
    use serde::{Serialize, Deserialize};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransfer;
    use hyxe_fs::io::SyncIO;
    use crate::hdp::hdp_packet_crafter::group::DUAL_ENCRYPTION_ON;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate<'a, 'b: 'a>(hyper_ratchet: &HyperRatchet, security_level: SecurityLevel, header: &'b [u8], mut payload: BytesMut) -> Option<Bytes> {
        //let bytes = &header[..];
        //let header = LayoutVerified::new(bytes)? as LayoutVerified<&[u8], HdpHeader>;
        hyper_ratchet.validate_message_packet_in_place_split(Some(security_level), header, &mut payload).ok()?;
        Some(payload.freeze())
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) enum GroupHeader<'a> {
        Standard(GroupReceiverConfig, VirtualTargetType),
        FastMessage(Vec<u8>, VirtualTargetType, #[serde(borrow)]Option<AliceToBobTransfer<'a>>),
    }

    pub(crate) fn validate_header<'a>(payload: &'a [u8], hyper_ratchet: &'a HyperRatchet, header: &'a LayoutVerified<&'a [u8], HdpHeader>) -> Option<GroupHeader<'a>> {
        let mut group_header = GroupHeader::deserialize_from_vector(payload).ok()?;
        match &mut group_header {
            GroupHeader::Standard(group_receiver_config, _) => {
                if group_receiver_config.plaintext_length > hyxe_user::prelude::MAX_BYTES_PER_GROUP {
                    log::error!("The provided GroupReceiverConfiguration contains an oversized allocation request. Dropping ...");
                    return None
                }
            }

             GroupHeader::FastMessage(msg, _, _) => {
                 if header.algorithm == DUAL_ENCRYPTION_ON {
                     let truncated_len = hyper_ratchet.decrypt_in_place_custom_scrambler(header.wave_id.get(), header.group.get(), msg).ok()?;
                     msg.truncate(truncated_len);
                 }

                 // we need to decrypt the message. Use zero for wave-id here only
                 let truncated_len = hyper_ratchet.decrypt_in_place_custom(0, header.group.get(), msg).ok()?;
                 msg.truncate(truncated_len);
             }
        }

        Some(group_header)
    }


    #[derive(Serialize, Deserialize)]
    #[allow(variant_size_differences)]
    pub enum GroupHeaderAck {
        ReadyToReceive { fast_msg: bool, initial_window: Option<RangeInclusive<u32>>, transfer: KemTransferStatus },
        NotReady { fast_msg: bool }
    }

    /// Returns None if the packet is invalid. Returns Some(is_ready_to_accept) if the packet is valid
    pub(crate) fn validate_header_ack(payload: &[u8]) -> Option<GroupHeaderAck> {
        GroupHeaderAck::deserialize_from_vector(payload).ok()
    }

    pub(crate) fn validate_window_tail(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<RangeInclusive<u32>> {
        if payload.len() != packet_sizes::GROUP_WINDOW_TAIL_LEN - HDP_HEADER_BYTE_LEN {
            None
        } else {
            let start = header.wave_id.get();
            let end = BigEndian::read_u32(payload);
            Some(start..=end)
        }
    }

    pub(crate) fn validate_wave_do_retransmission(payload: &[u8]) -> Result<(), NetworkError> {
        // The payload must be greater than 4 bytes
        // but the protocol does not send an unnecessary WAVE_DO_RETRANSMISSION
        let payload_len = payload.len();
        if payload_len < 4 {
            Err(NetworkError::InvalidPacket("Bad payload size"))
        } else {
            if payload_len % 4 != 0 {
                Err(NetworkError::InvalidPacket("The payload of the packet must be groups of 2 16-bit values (4-byte chunks)"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct WaveAck {
        pub(crate) range: Option<RangeInclusive<u32>>
    }

    /// Will return Ok(_) if valid. Will return Ok(Some(_)) if the window is complete, or Ok(None) if just a simple ack
    pub(crate) fn validate_wave_ack(payload: &[u8]) -> Option<WaveAck> {
        WaveAck::deserialize_from_vector(payload).ok()
    }
}

pub(crate) mod do_register {
    use std::net::SocketAddr;
    use zerocopy::LayoutVerified;

    use hyxe_user::network_account::NetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;
    use crate::proposed_credentials::ProposedCredentials;
    use byteorder::{BigEndian, ByteOrder};
    use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransfer;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use bytes::BytesMut;
    use hyxe_fs::io::SyncIO;
    use hyxe_fs::env::DirectoryStore;

    pub(crate) fn validate_stage0<'a>(header: &'a LayoutVerified<&[u8], HdpHeader>, payload: &'a [u8]) -> Option<(AliceToBobTransfer<'a>, Vec<u64>)> {
        let cids_to_get = header.context_info.get() as usize;
        if cids_to_get > 10 {
            log::error!("Too many CIDs provided");
        }

        let cids_byte_len = cids_to_get * 8;
        if payload.len() < cids_byte_len {
            log::error!("Bad payload size");
            return None;
        }

        let mut cids = Vec::with_capacity(cids_to_get);
        for x in 0..cids_to_get {
            let start = x*8;
            let end = start + 8;
            cids.push(BigEndian::read_u64(&payload[start..end]));
        }

        let remaining_bytes = &payload[cids_to_get*8..];

        log::info!("Possible CIDs obtained: {:?}", &cids);
        let transfer = AliceToBobTransfer::deserialize_from(remaining_bytes)?;
        Some((transfer, cids))
    }

    /// Returns the decrypted username, password, and full name
    pub(crate) fn validate_stage2(hyper_ratchet: &HyperRatchet, header: &LayoutVerified<&[u8], HdpHeader>, payload: BytesMut, peer_addr: SocketAddr, dirs: &DirectoryStore) -> Option<(ProposedCredentials, NetworkAccount)> {
        let (_, plaintext_bytes) = super::aead::validate_custom(hyper_ratchet, &header.bytes(), payload)?;
        let proposed_credentials = ProposedCredentials::deserialize_from_vector(&plaintext_bytes).ok()?;

        //let proposed_credentials = ProposedCredentials::new_from_hashed(full_name, username, SecVec::new(password.to_vec()), nonce);
        let adjacent_nid = header.session_cid.get();
        let adjacent_nac = NetworkAccount::new_from_recent_connection(adjacent_nid, peer_addr, dirs.clone());
        Some((proposed_credentials, adjacent_nac))
    }

    /// Returns the decrypted Toolset text, as well as the welcome message
    pub(crate) fn validate_success(hyper_ratchet: &HyperRatchet, header: &LayoutVerified<&[u8], HdpHeader>, payload: BytesMut, remote_addr: SocketAddr, dirs: &DirectoryStore) -> Option<(Vec<u8>, NetworkAccount)> {
        let (_, payload) = super::aead::validate_custom(hyper_ratchet, &header.bytes(), payload)?;
        let adjacent_nac = NetworkAccount::new_from_recent_connection(header.session_cid.get(), remote_addr, dirs.clone());
        Some((payload.to_vec(), adjacent_nac))
    }

    /// Returns the error message
    pub(crate) fn validate_failure(_header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<Vec<u8>> {
        // no encryption used for this type
        Some(payload.to_vec())
    }
}

pub(crate) mod do_drill_update {

    use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransfer;
    use crate::hdp::hdp_packet_crafter::do_drill_update::{TruncatePacket, Stage1UpdatePacket};
    use hyxe_fs::io::SyncIO;

    pub(crate) fn validate_stage0(payload: &[u8]) -> Option<AliceToBobTransfer<'_>> {
        AliceToBobTransfer::deserialize_from(payload as &[u8])
    }

    pub(crate) fn validate_stage1(payload: &[u8]) -> Option<Stage1UpdatePacket> {
        Stage1UpdatePacket::deserialize_from_vector(payload as &[u8]).ok()
    }

    pub(crate) fn validate_truncate(payload: &[u8]) -> Option<TruncatePacket> {
        TruncatePacket::deserialize_from_vector(payload).ok()
    }
}

pub(crate) mod pre_connect {
    use byteorder::{ByteOrder, NetworkEndian};

    use hyxe_crypt::toolset::{Toolset, StaticAuxRatchet};
    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_nat::udp_traversal::NatTraversalMethod;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{packet_sizes, HdpPacket};
    use crate::hdp::hdp_packet_processor::includes::SocketAddr;
    use std::str::FromStr;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransfer, HyperRatchetConstructor, BobToAliceTransfer, BobToAliceTransferType};

    // +1 for node type, +2 for minimum 1 wave port inscribed
    const STAGE0_MIN_PAYLOAD_LEN: usize = 1 + 2;
    // +1 for node type, +1 for nat traversal type, +8 for sync_time, +2 for minimum 1 wave port inscribed
    const STAGE1_MIN_PAYLOAD_LEN: usize = 1 + 1 + 8 + 2;

    pub fn validate_syn(cnac: &ClientNetworkAccount, packet: HdpPacket) -> Option<(StaticAuxRatchet, BobToAliceTransfer)> {
        // refresh the toolset's ARA & get static aux hr
        let static_auxiliary_ratchet = cnac.refresh_static_hyper_ratchet();
        let (header, payload, _, _) = packet.decompose();
        let (header, payload) = super::aead::validate_custom(&static_auxiliary_ratchet, &header, payload)?;

        let transfer = AliceToBobTransfer::deserialize_from(&payload)?;
        let bob_constructor = HyperRatchetConstructor::new_bob(header.algorithm, header.session_cid.get(), 0, transfer)?;
        let transfer = bob_constructor.stage0_bob()?;
        let new_hyper_ratchet = bob_constructor.finish()?;
        debug_assert!(new_hyper_ratchet.verify_level(transfer.security_level.into()).is_ok());
        // below, we need to ensure the hyper ratchet stays constant throughout transformations
        let toolset = Toolset::from((static_auxiliary_ratchet.clone(), new_hyper_ratchet));

        cnac.replace_toolset(toolset);
        Some((static_auxiliary_ratchet, transfer))
    }

    /// This returns an error if the packet is maliciously invalid (e.g., due to a false packet)
    /// This returns Ok(true) if the system was already synchronized, or Ok(false) if the system needed to synchronize toolsets
    pub fn validate_syn_ack(cnac: &ClientNetworkAccount, mut alice_constructor: HyperRatchetConstructor, packet: HdpPacket) -> Option<(HyperRatchet, SocketAddr)> {
        let static_auxiliary_ratchet = cnac.get_static_auxiliary_hyper_ratchet();
        let (header, payload, _, _) = packet.decompose();
        let (header, payload) = super::aead::validate_custom(&static_auxiliary_ratchet, &header, payload)?;
        let external_addr_len = header.context_info.get() as usize;
        if payload.len() > external_addr_len {
            let external_addr_bytes = String::from_utf8((&payload[..external_addr_len]).to_vec()).ok()?;
            let external_ip = SocketAddr::from_str(&external_addr_bytes).ok()?;
            log::info!("External IP: {:?}", external_ip);
            let transfer_payload = &payload[external_addr_len..];

            let transfer = BobToAliceTransfer::deserialize_from(transfer_payload)?;
            let lvl = transfer.security_level;
            log::info!("Session security level based-on returned transfer: {:?}", lvl);
            alice_constructor.stage1_alice(BobToAliceTransferType::Default(transfer))?;
            let new_hyper_ratchet = alice_constructor.finish()?;
            debug_assert!(new_hyper_ratchet.verify_level(lvl.into()).is_ok());
            let toolset = Toolset::from((static_auxiliary_ratchet, new_hyper_ratchet.clone()));
            cnac.replace_toolset(toolset);
            Some((new_hyper_ratchet, external_ip))
        } else {
            log::error!("Bad payload len");
            None
        }
    }

    // Returns the adjacent node type, wave ports, and external IP. Serverside, we do not update the CNAC's toolset until this point
    // because we want to make sure the client passes the challenge
    pub fn validate_stage0<'a>(hyper_ratchet: &HyperRatchet, packet: HdpPacket) -> Option<(HyperNodeType, Vec<u16>, SocketAddr)> {
        let (header, payload, _, _) = packet.decompose();
        let (header, payload) = super::aead::validate_custom(hyper_ratchet, &header, payload)?;
        if payload.len() < STAGE0_MIN_PAYLOAD_LEN {
            return None;
        }

        if header.drill_version.get() != hyper_ratchet.version() {
            log::error!("Header drill version not equal to the new base drill");
            None
        } else {
            let adjacent_node_type = HyperNodeType::from_byte(payload[0])?;
            let external_ip_len = header.context_info.get() as usize;
            let remaining_bytes = &payload[1..];
            if remaining_bytes.len() < external_ip_len {
                log::error!("External IP not encoded properly");
                return None;
            }

            let external_ip_bytes = String::from_utf8((&remaining_bytes[..external_ip_len]).to_vec()).ok()?;
            let external_ip = SocketAddr::from_str(&external_ip_bytes).ok()?;
            log::info!("External IP: {:?}", &external_ip);
            let port_bytes = &remaining_bytes[external_ip_len..];
            if port_bytes.len() % 2 != 0 {
                log::error!("Bad port bytes len");
                return None;
            }
            // Remember: these wll be the UPnP ports if the other end already enabled UPnP. We figure that out later in the stage1 process that calls this closure
            let ports = ports_from_bytes(port_bytes);
            Some((adjacent_node_type, ports, external_ip))
        }
    }

    pub fn validate_stage1(hyper_ratchet: &HyperRatchet, packet: HdpPacket) -> Option<(HyperNodeType, NatTraversalMethod, i64, Vec<u16>)> {
        let (header, payload, _, _) = packet.decompose();
        let (_header, payload) = super::aead::validate_custom(hyper_ratchet,&header, payload)?;
        if payload.len() < STAGE1_MIN_PAYLOAD_LEN {
            log::error!("Bad payload len");
            return None;
        }

        let adjacent_node_type = HyperNodeType::from_byte(payload[0])?;
        let nat_traversal_method = NatTraversalMethod::from_byte(payload[1])?;
        let sync_time = NetworkEndian::read_i64(&payload[2..10]);
        let port_bytes = &payload[10..];
        if port_bytes.len() % 2 != 0 {
            log::error!("Bad port bytes len");
            return None;
        }

        let adjacent_ports = ports_from_bytes(port_bytes);
        Some((adjacent_node_type, nat_traversal_method, sync_time, adjacent_ports))
    }

    pub fn validate_try_next(cnac: &ClientNetworkAccount, packet: HdpPacket) -> Option<(HyperRatchet, NatTraversalMethod)> {
        let (header, payload, _, _) = packet.decompose();
        let (_, payload, hyper_ratchet) = super::aead::validate(cnac, &header, payload)?;

        if payload.len() != packet_sizes::do_preconnect::STAGE_TRY_NEXT - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        Some((hyper_ratchet, NatTraversalMethod::from_byte(payload[0])?))
    }

    /// Returns the drill and sync_time
    pub fn validate_try_next_ack(cnac: &ClientNetworkAccount, packet: HdpPacket) -> Option<(HyperRatchet, i64)> {
        let (header, payload, _, _) = packet.decompose();
        let (_, payload, hyper_ratchet) = super::aead::validate(cnac, &header, payload)?;
        if payload.len() != packet_sizes::do_preconnect::STAGE_TRY_NEXT_ACK - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }
        let sync_time = NetworkEndian::read_i64(&payload[..]);
        Some((hyper_ratchet, sync_time))
    }

    /// if the payload contains ports, it is expected that those ports are reflective of the ports reserved from the UPnP process.
    /// This returns the drill, the upnp ports, and TCP_ONLY mode
    pub fn validate_final(cnac: &ClientNetworkAccount, packet: HdpPacket, tcp_only: bool) -> Option<(HyperRatchet, Option<Vec<u16>>)> {
        let (header, payload, _, _) = packet.decompose();
        let (_, payload, hyper_ratchet) = super::aead::validate(cnac, &header, payload)?;

        if payload.len() % 2 != 0 {
            log::error!("Bad payload len");
            return None;
        }

        let upnp_ports = if payload.len() != 0 {
            Some(ports_from_bytes(payload))
        } else {
            None
        };

        if tcp_only && upnp_ports.is_some() {
            log::error!("Improper packet configuration. TCP only and Some(upnp_ports) cannot both be true");
            return None;
        }

        Some((hyper_ratchet, upnp_ports))
    }

    pub fn validate_begin_connect(cnac: &ClientNetworkAccount, packet: HdpPacket) -> Option<HyperRatchet> {
        let (header, payload, _, _) = packet.decompose();
        let (_,payload, hyper_ratchet) = super::aead::validate(cnac, &header, payload)?;

        if payload.len() != packet_sizes::do_preconnect::STAGE_SUCCESS_ACK - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        Some(hyper_ratchet)
    }

    pub fn validate_server_finished_hole_punch(hyper_ratchet: &HyperRatchet, packet: HdpPacket) -> Option<()> {
        let (header, payload, _, _) = packet.decompose();
        let (_header, _payload) = super::aead::validate_custom(hyper_ratchet, &header, payload)?;
        Some(())
    }

    #[inline]
    fn ports_from_bytes<T: AsRef<[u8]>>(input: T) -> Vec<u16> {
        let input = input.as_ref();
        let port_count = input.len() / 2; // 2 bytes per u16
        let mut ret = Vec::with_capacity(port_count);

        for x in 0..port_count {
            let start = x * 2;
            let end = start + 1;
            let port = NetworkEndian::read_u16(&input[start..=end]);
            ret.push(port);
        }

        ret
    }
}

pub(crate) mod file {
    use crate::hdp::file_transfer::VirtualFileMetadata;
    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::hdp_packet_processor::includes::LayoutVerified;
    use crate::hdp::state_container::VirtualTargetType;

    pub fn validate_file_header(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(VirtualTargetType, VirtualFileMetadata)> {
        let split_idx = header.wave_id.get() as usize;
        if payload.len() < split_idx {
            None
        } else {
            let (vtarget_bytes, vfm_bytes) = payload.split_at(split_idx);
            let vtarget = VirtualTargetType::deserialize_from(vtarget_bytes)?;
            let vfm = VirtualFileMetadata::deserialize_from(vfm_bytes)?;
            Some((vtarget, vfm))
        }
    }

    /// return Some(success, object_id) if valid, or None if invalid
    pub fn validate_file_header_ack(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(bool, u32, VirtualTargetType)> {
        // 16 bytes for the signature
        if payload.len() != 0 {
            let object_id = header.wave_id.get();
            let success = header.group.get() != 0;
            let v_target = VirtualTargetType::deserialize_from(payload)?;
            Some((success, object_id, v_target))
        } else {
            None
        }
    }
}

pub(crate) mod aead {
    use bytes::{Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM or chacha-poly
    pub(crate) fn validate<'a, 'b: 'a, H: AsRef<[u8]> + 'b>(cnac: &ClientNetworkAccount, header: &'b H, mut payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, HyperRatchet)> {
        let header_bytes = header.as_ref();
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        let hyper_ratchet = cnac.get_hyper_ratchet(Some(header.drill_version.get()))?;
        hyper_ratchet.validate_message_packet_in_place_split(Some(header.security_level.into()), header_bytes, &mut payload).ok()?;
        Some((header, payload.freeze(), hyper_ratchet))
    }

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate_custom<'a, 'b: 'a, H: AsRef<[u8]> + 'b>(hyper_ratchet: &HyperRatchet, header: &'b H, mut payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes)> {
        let header_bytes = header.as_ref();
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        if let Err(err) = hyper_ratchet.validate_message_packet_in_place_split(Some(header.security_level.into()), header_bytes, &mut payload) {
            log::error!("AES-GCM stage failed: {:?}. Supplied Ratchet Version: {} | Expected Ratchet Version: {} | Header CID: {} | Target CID: {}", err, hyper_ratchet.version(), header.drill_version.get(), header.session_cid.get(), header.target_cid.get());
            return None;
        }

        Some((header, payload.freeze()))
    }
}