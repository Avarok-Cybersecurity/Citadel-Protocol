pub(crate) mod do_connect {
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::error::NetworkError;
    use crate::hdp::hdp_packet_crafter::do_connect::{
        DoConnectFinalStatusPacket, DoConnectStage0Packet,
    };
    use hyxe_user::serialization::SyncIO;

    /// Here, Bob receives a payload of the encrypted username + password. We must verify the login data is valid
    pub(crate) async fn validate_stage0_packet(
        cnac: &ClientNetworkAccount,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        // Now, validate the username and password. The payload is already decrypted
        let payload = DoConnectStage0Packet::deserialize_from_vector(payload)
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        cnac.validate_credentials(payload.proposed_credentials)
            .await
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        log::trace!(target: "lusna", "Success validating credentials!");
        Ok(())
    }

    pub(crate) fn validate_final_status_packet(
        payload: &[u8],
    ) -> Option<DoConnectFinalStatusPacket> {
        DoConnectFinalStatusPacket::deserialize_from_vector(payload).ok()
    }
}

pub(crate) mod group {
    use std::ops::RangeInclusive;

    use bytes::{Bytes, BytesMut};

    use hyxe_crypt::net::crypt_splitter::GroupReceiverConfig;

    use crate::hdp::hdp_packet_crafter::SecureProtocolPacket;
    use crate::hdp::state_container::VirtualTargetType;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;
    use hyxe_crypt::prelude::SecBuffer;
    use hyxe_crypt::stacked_ratchet::constructor::AliceToBobTransfer;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate<'a, 'b: 'a>(
        hyper_ratchet: &StackedRatchet,
        security_level: SecurityLevel,
        header: &'b [u8],
        mut payload: BytesMut,
    ) -> Option<Bytes> {
        hyper_ratchet
            .validate_message_packet_in_place_split(Some(security_level), header, &mut payload)
            .ok()?;
        Some(payload.freeze())
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) enum GroupHeader {
        Standard(GroupReceiverConfig, VirtualTargetType),
        //FastMessage(SecBuffer, VirtualTargetType, #[serde(borrow)] Option<AliceToBobTransfer<'a>>)
    }

    pub(crate) fn validate_header(payload: &mut BytesMut) -> Option<GroupHeader> {
        let mut group_header = GroupHeader::deserialize_from_vector(payload).ok()?;
        match &mut group_header {
            GroupHeader::Standard(group_receiver_config, _) => {
                if group_receiver_config.plaintext_length > hyxe_user::prelude::MAX_BYTES_PER_GROUP
                {
                    log::error!(target: "lusna", "The provided GroupReceiverConfiguration contains an oversized allocation request. Dropping ...");
                    return None;
                }
            }
        }

        Some(group_header)
    }

    pub(crate) fn validate_message<'a>(
        payload: &'a mut BytesMut,
    ) -> Option<(SecBuffer, Option<AliceToBobTransfer<'a>>)> {
        let message = SecureProtocolPacket::extract_message(payload).ok()?;
        //let deser = bincode2::deserialize(&payload[..]).ok()?;
        let deser = hyxe_user::serialization::SyncIO::deserialize_from_vector(&payload[..]).ok()?;
        Some((message.into(), deser))
    }

    #[derive(Serialize, Deserialize)]
    #[allow(variant_size_differences)]
    pub enum GroupHeaderAck {
        ReadyToReceive {
            fast_msg: bool,
            initial_window: Option<RangeInclusive<u32>>,
            transfer: KemTransferStatus,
        },
        NotReady {
            fast_msg: bool,
        },
    }

    /// Returns None if the packet is invalid. Returns Some(is_ready_to_accept) if the packet is valid
    pub(crate) fn validate_header_ack(payload: &[u8]) -> Option<GroupHeaderAck> {
        GroupHeaderAck::deserialize_from_vector(payload).ok()
    }

    #[derive(Serialize, Deserialize)]
    pub struct WaveAck {
        pub(crate) range: Option<RangeInclusive<u32>>,
    }

    /// Will return Ok(_) if valid. Will return Ok(Some(_)) if the window is complete, or Ok(None) if just a simple ack
    pub(crate) fn validate_wave_ack(payload: &[u8]) -> Option<WaveAck> {
        WaveAck::deserialize_from_vector(payload).ok()
    }
}

pub(crate) mod do_register {
    use std::net::SocketAddr;
    use zerocopy::LayoutVerified;

    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::hdp_packet_crafter::do_register::{DoRegisterStage0, DoRegisterStage2Packet};
    use bytes::BytesMut;
    use hyxe_crypt::stacked_ratchet::constructor::AliceToBobTransfer;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::prelude::ConnectionInfo;
    use hyxe_user::serialization::SyncIO;

    pub(crate) fn validate_stage0<'a>(payload: &'a [u8]) -> Option<(AliceToBobTransfer<'a>, bool)> {
        DoRegisterStage0::deserialize_from_vector(payload)
            .ok()
            .map(|r| (r.transfer, r.passwordless))
    }

    /// Returns the decrypted username, password, and full name
    pub(crate) fn validate_stage2(
        hyper_ratchet: &StackedRatchet,
        header: &LayoutVerified<&[u8], HdpHeader>,
        payload: BytesMut,
        peer_addr: SocketAddr,
    ) -> Option<(DoRegisterStage2Packet, ConnectionInfo)> {
        let (_, plaintext_bytes) =
            super::aead::validate_custom(hyper_ratchet, &header.bytes(), payload)?;
        let packet = DoRegisterStage2Packet::deserialize_from_vector(&plaintext_bytes[..]).ok()?;

        //let proposed_credentials = ProposedCredentials::new_from_hashed(full_name, username, SecVec::new(password.to_vec()), nonce);
        let adjacent_addr = ConnectionInfo { addr: peer_addr };
        Some((packet, adjacent_addr))
    }

    /// Returns the decrypted Toolset text, as well as the welcome message
    pub(crate) fn validate_success(
        hyper_ratchet: &StackedRatchet,
        header: &LayoutVerified<&[u8], HdpHeader>,
        payload: BytesMut,
        remote_addr: SocketAddr,
    ) -> Option<(Vec<u8>, ConnectionInfo)> {
        let (_, payload) = super::aead::validate_custom(hyper_ratchet, &header.bytes(), payload)?;
        let adjacent_addr = ConnectionInfo { addr: remote_addr };
        Some((payload.to_vec(), adjacent_addr))
    }

    /// Returns the error message
    pub(crate) fn validate_failure(
        _header: &LayoutVerified<&[u8], HdpHeader>,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // no encryption used for this type
        Some(payload.to_vec())
    }
}

pub(crate) mod do_drill_update {

    use crate::hdp::hdp_packet_crafter::do_drill_update::{
        Stage1UpdatePacket, TruncateAckPacket, TruncatePacket,
    };
    use hyxe_crypt::stacked_ratchet::constructor::AliceToBobTransfer;
    use hyxe_user::serialization::SyncIO;

    pub(crate) fn validate_stage0(payload: &[u8]) -> Option<AliceToBobTransfer<'_>> {
        AliceToBobTransfer::deserialize_from(payload as &[u8])
    }

    pub(crate) fn validate_stage1(payload: &[u8]) -> Option<Stage1UpdatePacket> {
        Stage1UpdatePacket::deserialize_from_vector(payload as &[u8]).ok()
    }

    pub(crate) fn validate_truncate(payload: &[u8]) -> Option<TruncatePacket> {
        TruncatePacket::deserialize_from_vector(payload).ok()
    }

    pub(crate) fn validate_truncate_ack(payload: &[u8]) -> Option<TruncateAckPacket> {
        TruncateAckPacket::deserialize_from_vector(payload).ok()
    }
}

pub(crate) mod pre_connect {
    use hyxe_crypt::toolset::{StaticAuxRatchet, Toolset};
    use hyxe_user::client_account::ClientNetworkAccount;
    use hyxe_wire::hypernode_type::NodeType;

    use crate::error::NetworkError;
    use crate::hdp::hdp_node::ConnectMode;
    use crate::hdp::hdp_packet::HdpPacket;
    use crate::hdp::hdp_packet_crafter::pre_connect::{PreConnectStage0, SynPacket};
    use crate::hdp::hdp_session_manager::HdpSessionManager;
    use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
    use crate::hdp::packet_processor::includes::hdp_packet_crafter::pre_connect::SynAckPacket;
    use crate::hdp::peer::peer_layer::UdpMode;
    use hyxe_crypt::stacked_ratchet::constructor::{
        BobToAliceTransfer, BobToAliceTransferType, StackedRatchetConstructor,
    };
    use hyxe_crypt::stacked_ratchet::{Ratchet, StackedRatchet};
    use hyxe_user::prelude::ConnectProtocol;
    use hyxe_user::serialization::SyncIO;
    use hyxe_wire::nat_identification::NatType;

    pub(crate) fn validate_syn(
        cnac: &ClientNetworkAccount,
        packet: HdpPacket,
        session_manager: &HdpSessionManager,
    ) -> Result<
        (
            StaticAuxRatchet,
            BobToAliceTransfer,
            SessionSecuritySettings,
            ConnectProtocol,
            UdpMode,
            i64,
            NatType,
            StackedRatchet,
        ),
        NetworkError,
    > {
        // TODO: NOTE: This can interrupt any active session's. This should be moved up after checking the connect mode
        let static_auxiliary_ratchet = cnac.refresh_static_hyper_ratchet();
        let (header, payload, _, _) = packet.decompose();
        // After this point, we validate that the other end had the right static symmetric key. This proves device identity, thought not necessarily account identity
        let (header, payload) =
            super::aead::validate_custom(&static_auxiliary_ratchet, &header, payload).ok_or(
                NetworkError::InternalError("Unable to validate initial packet"),
            )?;

        let transfer = SynPacket::deserialize_from_vector(&payload)
            .map_err(|err| NetworkError::Generic(err.into_string()))?;

        // TODO: Consider adding connect_mode to the HdpSession to sync between both nodes. For now, there's no need
        match transfer.connect_mode {
            ConnectMode::Fetch { force_login: false }
            | ConnectMode::Standard { force_login: false } => {
                // before going further, make sure the user isn't already logged-in. We wouldn't want to replace the toolset that is already being used
                if session_manager.session_active(header.session_cid.get()) {
                    return Err(NetworkError::InternalError("User is already logged in"));
                }
            }

            _ => {}
        }

        let session_security_settings = transfer.session_security_settings;
        let peer_only_connect_mode = transfer.peer_only_connect_protocol;
        let nat_type = transfer.nat_type;
        let udp_mode = transfer.udp_mode;
        let kat = transfer.keep_alive_timeout;
        let _ = static_auxiliary_ratchet
            .verify_level(Some(transfer.session_security_settings.security_level))
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        let opts = static_auxiliary_ratchet
            .get_next_constructor_opts()
            .into_iter()
            .take((transfer.session_security_settings.security_level.value() + 1) as usize)
            .collect();
        //let opts = ConstructorOpts::new_vec_init(Some(transfer.transfer.params), (transfer.transfer.security_level.value() + 1) as usize).into_i;
        let bob_constructor = StackedRatchetConstructor::new_bob(
            header.session_cid.get(),
            0,
            opts,
            transfer.transfer,
        )
        .ok_or(NetworkError::InternalError(
            "Unable to create bob container",
        ))?;
        let transfer = bob_constructor
            .stage0_bob()
            .ok_or(NetworkError::InternalError("Unable to execute stage0_bob"))?;
        let new_hyper_ratchet = bob_constructor.finish().ok_or(NetworkError::InternalError(
            "Unable to finish bob constructor",
        ))?;
        let _ = new_hyper_ratchet
            .verify_level(transfer.security_level.into())
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        // below, we need to ensure the hyper ratchet stays constant throughout transformations
        let toolset = Toolset::from((static_auxiliary_ratchet.clone(), new_hyper_ratchet.clone()));

        cnac.replace_toolset(toolset);
        Ok((
            static_auxiliary_ratchet,
            transfer,
            session_security_settings,
            peer_only_connect_mode,
            udp_mode,
            kat,
            nat_type,
            new_hyper_ratchet,
        ))
    }

    /// This returns an error if the packet is maliciously invalid (e.g., due to a false packet)
    /// This returns Ok(true) if the system was already synchronized, or Ok(false) if the system needed to synchronize toolsets
    pub fn validate_syn_ack(
        cnac: &ClientNetworkAccount,
        mut alice_constructor: StackedRatchetConstructor,
        packet: HdpPacket,
    ) -> Option<(StackedRatchet, NatType)> {
        let static_auxiliary_ratchet = cnac.get_static_auxiliary_hyper_ratchet();
        let (header, payload, _, _) = packet.decompose();
        let (_, payload) =
            super::aead::validate_custom(&static_auxiliary_ratchet, &header, payload)?;
        let packet = SynAckPacket::deserialize_from_vector(&payload).ok()?;

        let lvl = packet.transfer.security_level;
        log::trace!(target: "lusna", "Session security level based-on returned transfer: {:?}", lvl);
        alice_constructor.stage1_alice(&BobToAliceTransferType::Default(packet.transfer))?;

        let new_hyper_ratchet = alice_constructor.finish()?;
        let _ = new_hyper_ratchet.verify_level(lvl.into()).ok()?;
        let toolset = Toolset::from((static_auxiliary_ratchet, new_hyper_ratchet.clone()));
        cnac.replace_toolset(toolset);
        Some((new_hyper_ratchet, packet.nat_type))
    }

    // Returns the adjacent node type, wave ports, and external IP. Serverside, we do not update the CNAC's toolset until this point
    // because we want to make sure the client passes the challenge
    pub fn validate_stage0(hyper_ratchet: &StackedRatchet, packet: HdpPacket) -> Option<NodeType> {
        let (header, payload, _, _) = packet.decompose();
        let (_header, payload) = super::aead::validate_custom(hyper_ratchet, &header, payload)?;
        let packet = PreConnectStage0::deserialize_from_vector(&payload).ok()?;
        Some(packet.node_type)
    }
}

pub(crate) mod file {
    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::packet_processor::includes::LayoutVerified;
    use crate::hdp::state_container::VirtualTargetType;
    use hyxe_user::backend::utils::VirtualObjectMetadata;

    pub fn validate_file_header(
        header: &LayoutVerified<&[u8], HdpHeader>,
        payload: &[u8],
    ) -> Option<(VirtualTargetType, VirtualObjectMetadata)> {
        let split_idx = header.wave_id.get() as usize;
        if payload.len() < split_idx {
            None
        } else {
            let (vtarget_bytes, vfm_bytes) = payload.split_at(split_idx);
            let vtarget = VirtualTargetType::deserialize_from(vtarget_bytes)?;
            let vfm = VirtualObjectMetadata::deserialize_from(vfm_bytes)?;
            Some((vtarget, vfm))
        }
    }

    /// return Some(success, object_id) if valid, or None if invalid
    pub fn validate_file_header_ack(
        header: &LayoutVerified<&[u8], HdpHeader>,
        payload: &[u8],
    ) -> Option<(bool, u32, VirtualTargetType)> {
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

    use crate::hdp::hdp_packet::HdpHeader;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM or chacha-poly
    pub(crate) fn validate<'a, 'b: 'a, H: AsRef<[u8]> + 'b>(
        proper_hr: StackedRatchet,
        header: &'b H,
        mut payload: BytesMut,
    ) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, StackedRatchet)> {
        let header_bytes = header.as_ref();
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        proper_hr
            .validate_message_packet_in_place_split(
                Some(header.security_level.into()),
                header_bytes,
                &mut payload,
            )
            .ok()?;
        Some((header, payload.freeze(), proper_hr))
    }

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate_custom<'a, 'b: 'a, H: AsRef<[u8]> + 'b>(
        hyper_ratchet: &StackedRatchet,
        header: &'b H,
        mut payload: BytesMut,
    ) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, BytesMut)> {
        let header_bytes = header.as_ref();
        let header = LayoutVerified::new(header_bytes)? as LayoutVerified<&[u8], HdpHeader>;
        if let Err(err) = hyper_ratchet.validate_message_packet_in_place_split(
            Some(header.security_level.into()),
            header_bytes,
            &mut payload,
        ) {
            log::error!(target: "lusna", "AES-GCM stage failed: {:?}. Supplied Ratchet Version: {} | Expected Ratchet Version: {} | Header CID: {} | Target CID: {}\nPacket: {:?}\nPayload len: {}", err, hyper_ratchet.version(), header.drill_version.get(), header.session_cid.get(), header.target_cid.get(), &header, payload.len());
            return None;
        }

        Some((header, payload))
    }
}
