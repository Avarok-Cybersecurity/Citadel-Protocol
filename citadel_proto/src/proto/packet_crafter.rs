//! # Citadel Protocol Packet Crafting
//!
//! This module provides the functionality to create various types of protocol packets
//! used in the Citadel Protocol. Each packet type is carefully crafted with appropriate
//! headers, encryption, and security measures.
//!
//! ## Packet Types
//!
//! The module supports crafting several types of packets:
//!
//! - **Connection Management**
//!   - Pre-connect packets for initial handshake
//!   - Connect packets for establishing connections
//!   - Disconnect packets for clean connection termination
//!
//! - **Authentication**
//!   - Register packets for user registration
//!   - Deregister packets for account removal
//!
//! - **Data Transfer**
//!   - File transfer packets with metadata
//!   - Group message packets for broadcast
//!   - Channel packets for direct communication
//!
//! - **Maintenance**
//!   - Keep-alive packets for connection health
//!   - Drill update packets for key rotation
//!   - Hole punch packets for NAT traversal
//!
//! ## Security Features
//!
//! Each packet is secured with:
//! - Post-quantum encryption
//! - Integrity protection
//! - Replay attack prevention
//! - Perfect forward secrecy
//!
//! ## Implementation Details
//!
//! The packet crafting process involves:
//! 1. Header construction with appropriate flags
//! 2. Payload serialization and encryption
//! 3. Security level enforcement
//! 4. Timestamp and sequence number management

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::remote::Ticket;
use crate::proto::session::UserMessage;
use crate::proto::state_container::VirtualTargetType;
use bytes::BytesMut;
use citadel_crypt::messaging::MessengerLayerOrderedMessage;
use citadel_crypt::ratchets::ratchet_manager::RatchetMessage;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::crypt_splitter::{GroupReceiverConfig, GroupSenderDevice};
use citadel_types::crypto::SecurityLevel;
use citadel_types::prelude::ObjectId;
use netbeam::time_tracker::TimeTracker;

/// Manages the transmission of group messages and file transfers with support
/// for encryption, scrambling, and packet management. This structure handles
/// the complexities of breaking large transfers into manageable chunks while
/// maintaining security.
///
/// # Features
///
/// - Secure group transmission
/// - Automatic packet chunking
/// - Progress tracking
/// - Error handling
pub struct ObjectTransmitter<R: Ratchet> {
    ratchet: R,
    to_primary_stream: OutboundPrimaryStreamSender,
    // Handles the encryption and scrambling asynchronously. Also manages missing packets
    pub(crate) group_transmitter: Option<GroupSenderDevice<HDP_HEADER_BYTE_LEN>>,
    /// Contained within Self::group_transmitter, but is here for convenience
    group_config: Option<GroupReceiverConfig>,
    /// The ID of the object that is being transmitted
    pub object_id: ObjectId,
    pub group_id: u64,
    /// For interfacing with the higher-level kernel
    ticket: Ticket,
    security_level: SecurityLevel,
    bytes_encrypted: usize,
    time_tracker: TimeTracker,
    is_message: Option<RatchetMessage<MessengerLayerOrderedMessage<UserMessage>>>,
}

impl<R: Ratchet> ObjectTransmitter<R> {
    /// Scrambled packets will use this
    pub fn new_from_group_sender(
        to_primary_stream: OutboundPrimaryStreamSender,
        group_sender: GroupSenderDevice<HDP_HEADER_BYTE_LEN>,
        ratchet: R,
        object_id: ObjectId,
        ticket: Ticket,
        security_level: SecurityLevel,
        time_tracker: TimeTracker,
    ) -> Self {
        let cfg = group_sender.get_receiver_config();
        let group_id = cfg.group_id;
        let bytes_encrypted = cfg.plaintext_length as usize;
        Self {
            ratchet,
            is_message: None,
            group_transmitter: Some(group_sender),
            to_primary_stream,
            group_config: Some(cfg),
            object_id,
            group_id,
            ticket,
            security_level,
            bytes_encrypted,
            time_tracker,
        }
    }

    /// Creates a new stream for a request
    #[allow(clippy::too_many_arguments)]
    pub fn transmit_message(
        to_primary_stream: OutboundPrimaryStreamSender,
        object_id: ObjectId,
        ratchet: R,
        input_message: RatchetMessage<MessengerLayerOrderedMessage<UserMessage>>,
        security_level: SecurityLevel,
        group_id: u64,
        ticket: Ticket,
        time_tracker: TimeTracker,
        virtual_target_type: VirtualTargetType,
    ) -> Result<(), NetworkError> {
        // Gets the latest entropy_bank version by default for this operation
        log::trace!(target: "citadel", "Will use {ratchet:?} to encrypt group {group_id}");
        let mut this = Self {
            ratchet,
            is_message: Some(input_message),
            object_id,
            to_primary_stream,
            group_transmitter: None,
            group_config: None,
            bytes_encrypted: 0, // Irrelevant
            security_level,
            group_id,
            ticket,
            time_tracker,
        };

        this.transmit_group_header(virtual_target_type)
    }

    pub fn transmit_group_header(
        &mut self,
        virtual_target: VirtualTargetType,
    ) -> Result<(), NetworkError> {
        let header = self.generate_group_header(virtual_target);
        self.to_primary_stream
            .unbounded_send(header)
            .map_err(|err| NetworkError::msg(format!("Unable to transmit group header: {err:?}")))
    }

    /// Generates the group header for this set using the pre-allocated slab. Since the group header is always sent through the primary port,
    /// and the wave ports are what receive the packet stream, this should be ran BEFORE streaming self
    pub fn generate_group_header(&mut self, virtual_target: VirtualTargetType) -> BytesMut {
        group::craft_group_header_packet(self, virtual_target)
    }

    /// Returns the number of bytes that would be encrypted
    pub fn get_total_plaintext_bytes(&self) -> usize {
        self.bytes_encrypted
    }

    #[allow(unused_results)]
    pub fn transmit_tcp_file_transfer(&mut self) -> bool {
        let group_config = self.group_config.as_ref().unwrap();
        log::trace!(target: "citadel", "[Q-TCP] Payload packets to send: {} | Max packets per wave: {}", group_config.packets_needed, group_config.max_packets_per_wave);

        if let Some(transmitter) = &mut self.group_transmitter {
            let to_primary_stream = &self.to_primary_stream;
            let packets = transmitter.take_all_packets();

            log::trace!(target: "citadel", "Will transfer {} packets", packets.len());
            for packet in packets {
                if let Err(err) = to_primary_stream.unbounded_send(packet.packet) {
                    log::error!(target: "citadel", "[FILE] to_primary_stream died {:?}", err);
                }
            }

            log::trace!(target: "citadel", "Group {} has finished transmission", self.group_id);

            true
        } else {
            false
        }
    }
}

pub(crate) mod group {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use citadel_crypt::prelude::*;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::packet_sizes;
    use crate::proto::packet::packet_sizes::GROUP_HEADER_ACK_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use crate::proto::packet_crafter::ObjectTransmitter;
    use crate::proto::remote::Ticket;
    use crate::proto::state_container::VirtualTargetType;
    use crate::proto::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::proto::ObjectId;
    use citadel_user::serialization::SyncIO;
    use std::ops::RangeInclusive;

    /// Crafts a group header packet for a given group transmitter and virtual target
    pub(super) fn craft_group_header_packet<R: Ratchet>(
        processor: &mut ObjectTransmitter<R>,
        virtual_target: VirtualTargetType,
    ) -> BytesMut {
        let target_cid = virtual_target.get_target_cid();

        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER,
            algorithm: 0,
            security_level: processor.security_level.value(),
            context_info: U128::new(processor.ticket.0),
            group: U64::new(processor.group_id),
            wave_id: U32::new(0),
            session_cid: U64::new(processor.ratchet.get_cid()),
            entropy_bank_version: U32::new(processor.ratchet.version()),
            timestamp: I64::new(processor.time_tracker.get_global_time_ns()),
            target_cid: U64::new(target_cid),
        };

        let mut packet = if let Some(ratchet_message) = processor.is_message.take() {
            // For messages, the RatchetManager/Messenger will provide SecureMessagePackets for us, stored inside the below field
            // The header, as always, will need to be written
            // We no long have to worry about setting up key exchange here; that is taken care of by the Messenger
            // In fact, on the receiving end, we just forward this packet to the messenger, where it will automatically
            // be forwarded to the consumer, bytpassing the kernel
            let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_HEADER_BASE_LEN);
            header.inscribe_into(&mut packet);
            let header = GroupHeader::Ratchet(ratchet_message, processor.object_id);
            header.serialize_into_buf(&mut packet).unwrap();
            packet
        } else {
            let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_HEADER_BASE_LEN);
            header.inscribe_into(&mut packet);
            let header =
                GroupHeader::Standard(processor.group_config.clone().unwrap(), virtual_target);
            header.serialize_into_buf(&mut packet).unwrap();
            packet
        };

        processor
            .ratchet
            .protect_message_packet(
                Some(processor.security_level),
                HDP_HEADER_BYTE_LEN,
                &mut packet,
            )
            .unwrap();

        packet
    }

    /// Crafts a group header acknowledgement packet for a given group transmitter and virtual target
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_group_header_ack<R: Ratchet>(
        ratchet: &R,
        group_id: u64,
        target_cid: u64,
        object_id: ObjectId,
        ticket: Ticket,
        initial_wave_window: Option<RangeInclusive<u32>>,
        fast_msg: bool,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(group_id),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let header_ack = GroupHeaderAck::ReadyToReceive {
            fast_msg,
            initial_window: initial_wave_window,
            object_id,
        };

        let mut packet =
            BytesMut::with_capacity(GROUP_HEADER_ACK_LEN + header_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);

        header_ack.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// Crafts a wave payload packet for a given group transmitter and virtual target
    pub(crate) fn craft_wave_payload_packet_into(
        coords: &PacketVector,
        scramble_entropy_bank: &EntropyBank,
        object_id: ObjectId,
        target_cid: u64,
        mut buffer: &mut BytesMut,
    ) {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_PAYLOAD,
            algorithm: 0,
            security_level: 0, // Irrelevant; supplied by the wave header anyways
            context_info: U128::new(object_id.0),
            group: U64::new(coords.group_id),
            wave_id: U32::new(coords.wave_id),
            session_cid: U64::new(scramble_entropy_bank.get_cid()),
            entropy_bank_version: U32::new(scramble_entropy_bank.get_version()),
            timestamp: I64::new(0), // Irrelevant; supplied by the wave header anyways
            target_cid: U64::new(target_cid),
        };

        // inscribe the header into the supplied buffer
        header.inscribe_into(&mut buffer);
        let src_port = coords.local_port;
        let remote_port = coords.remote_port;
        debug_assert!(src_port <= scramble_entropy_bank.get_multiport_width() as u16);
        debug_assert!(remote_port <= scramble_entropy_bank.get_multiport_width() as u16);
        buffer.put_u8(src_port as u8);
        buffer.put_u8(remote_port as u8);
    }

    /// Crafts a wave acknowledgement packet for a given group transmitter and virtual target
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_wave_ack<R: Ratchet>(
        ratchet: &R,
        object_id: ObjectId,
        target_cid: u64,
        group_id: u64,
        wave_id: u32,
        timestamp: i64,
        range: Option<RangeInclusive<u32>>,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(object_id.0),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let wave_ack = WaveAck { range };
        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + wave_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        wave_ack.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_connect {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use crate::proto::peer::peer_layer::MailboxTransfer;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::user::MutualPeer;
    use citadel_user::auth::proposed_credentials::ProposedCredentials;
    use citadel_user::backend::BackendType;
    use citadel_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    /// Crafts a do-connect stage 0 packet for a given proposed credentials and timestamp
    #[derive(Serialize, Deserialize)]
    pub struct DoConnectStage0Packet {
        pub proposed_credentials: ProposedCredentials,
        pub uses_filesystem: bool,
    }

    /// Alice receives the nonce from Bob. She must now inscribe her username/password
    #[allow(unused_results)]
    pub(crate) fn craft_stage0_packet<R: Ratchet>(
        ratchet: &R,
        proposed_credentials: ProposedCredentials,
        timestamp: i64,
        security_level: SecurityLevel,
        backend_type: &BackendType,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            // place username len here to allow the other end to know where to split the payload
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let uses_filesystem = matches!(backend_type, BackendType::Filesystem(..));

        let payload = DoConnectStage0Packet {
            proposed_credentials,
            uses_filesystem,
        };

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// Crafts a do-connect final status packet for a given mailbox transfer, peers, and post-login object
    #[derive(Serialize, Deserialize)]
    pub struct DoConnectFinalStatusPacket<'a> {
        pub mailbox: Option<MailboxTransfer>,
        pub peers: Vec<MutualPeer>,
        // in order to allow interoperability between protocols that have fields in the services object
        // and those that don't, default on error
        #[serde(deserialize_with = "ok_or_default")]
        #[serde(default)]
        pub post_login_object: citadel_user::external_services::ServicesObject,
        #[serde(borrow)]
        pub message: &'a [u8],
    }

    fn ok_or_default<'a, T, D>(deserializer: D) -> Result<T, <D as serde::Deserializer<'a>>::Error>
    where
        T: Deserialize<'a> + Default,
        D: serde::Deserializer<'a>,
    {
        Ok(T::deserialize(deserializer).unwrap_or_default())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_final_status_packet<T: AsRef<[u8]>, R: Ratchet>(
        ratchet: &R,
        success: bool,
        mailbox: Option<MailboxTransfer>,
        post_login_object: citadel_user::external_services::ServicesObject,
        message: T,
        peers: Vec<MutualPeer>,
        timestamp: i64,
        security_level: SecurityLevel,
        backend_type: &BackendType,
    ) -> BytesMut {
        let payload = DoConnectFinalStatusPacket {
            mailbox,
            peers,
            message: message.as_ref(),
            post_login_object,
        };

        let cmd_aux = if success {
            packet_flags::cmd::aux::do_connect::SUCCESS
        } else {
            packet_flags::cmd::aux::do_connect::FAILURE
        };

        let is_filesystem = matches!(backend_type, BackendType::Filesystem(..));

        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(is_filesystem as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a do-connect success acknowledgement packet for a given timestamp and security level
    #[allow(unused_results)]
    pub(crate) fn craft_success_ack<R: Ratchet>(
        ratchet: &R,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::SUCCESS_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod keep_alive {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use zerocopy::{I64, U128, U32, U64};

    /// Crafts a keep-alive packet for a given timestamp and security level
    pub(crate) fn craft_keep_alive_packet<R: Ratchet>(
        ratchet: &R,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::KEEP_ALIVE,
            cmd_aux: 0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_register {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_user::auth::proposed_credentials::ProposedCredentials;
    use citadel_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    /// Crafts a do-register stage 0 packet for a given transfer and passwordless flag
    #[derive(Serialize, Deserialize)]
    pub(crate) struct DoRegisterStage0<R: Ratchet> {
        #[serde(bound = "")]
        pub(crate) transfer:
            <R::Constructor as EndpointRatchetConstructor<R>>::AliceToBobWireTransfer,
        pub(crate) passwordless: bool,
    }

    /// At this stage, the entropy_bank does not exist. There is no verifying such packets. The payload contains Alice's public key.
    /// Since this is sent over TCP, the size of the packet can be up to ~64k bytes
    /// We also use the NID in place of the CID because the CID only exists AFTER registration completes
    pub(crate) fn craft_stage0<R: Ratchet>(
        algorithm: u8,
        timestamp: i64,
        transfer: <R::Constructor as EndpointRatchetConstructor<R>>::AliceToBobWireTransfer,
        passwordless: bool,
        proposed_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE0,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            entropy_bank_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        packet.put(header.as_packet());

        DoRegisterStage0::<R> {
            transfer,
            passwordless,
        }
        .serialize_into_buf(&mut packet)
        .unwrap();

        packet
    }

    /// Crafts a do-register stage 1 packet for a given transfer and proposed CID
    pub(crate) fn craft_stage1<R: Ratchet>(
        algorithm: u8,
        timestamp: i64,
        transfer: <R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
        proposed_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE1,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            entropy_bank_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);

        header.inscribe_into(&mut packet);
        SyncIO::serialize_into_buf(&transfer, &mut packet).unwrap();

        packet
    }

    /// Crafts a do-register stage 2 packet for a given credentials and timestamp
    #[derive(Serialize, Deserialize)]
    pub struct DoRegisterStage2Packet {
        pub credentials: ProposedCredentials,
    }

    /// Alice sends this. The stage 3 packet contains the encrypted username, password, and full name of the registering client
    #[allow(unused_results)]
    pub(crate) fn craft_stage2<R: Ratchet>(
        ratchet: &R,
        algorithm: u8,
        timestamp: i64,
        credentials: &ProposedCredentials,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE2,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let total_len = HDP_HEADER_BYTE_LEN;
        let mut packet = BytesMut::with_capacity(total_len);
        let payload = DoRegisterStage2Packet {
            credentials: credentials.clone(),
        };
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a do-register success packet for a given success message and timestamp
    pub(crate) fn craft_success<T: AsRef<[u8]>, R: Ratchet>(
        ratchet: &R,
        algorithm: u8,
        timestamp: i64,
        success_message: T,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let success_message = success_message.as_ref();
        let success_message_len = success_message.len();
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::SUCCESS,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + success_message_len);
        header.inscribe_into(&mut packet);
        packet.put(success_message);

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a do-register failure packet for a given error message and proposed CID
    pub(crate) fn craft_failure<T: AsRef<[u8]>>(
        algorithm: u8,
        timestamp: i64,
        error_message: T,
        proposed_cid: u64,
    ) -> BytesMut {
        let error_message = error_message.as_ref();

        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::FAILURE,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            entropy_bank_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + error_message.len());
        header.inscribe_into(&mut packet);
        packet.put(error_message);

        packet
    }
}

pub(crate) mod do_disconnect {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use crate::proto::remote::Ticket;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;

    /// Crafts a do-disconnect stage 0 packet for a given ticket, timestamp, and security level
    #[allow(unused_results)]
    pub(crate) fn craft_stage0<R: Ratchet>(
        ratchet: &R,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a do-disconnect final packet for a given ticket, timestamp, and security level
    #[allow(unused_results)]
    pub(crate) fn craft_final<R: Ratchet>(
        ratchet: &R,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::FINAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_deregister {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use zerocopy::{I64, U128, U32, U64};

    /// Crafts a do-deregister stage 0 packet for a given timestamp and security level
    pub(crate) fn craft_stage0<R: Ratchet>(
        ratchet: &R,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux: packet_flags::cmd::aux::do_deregister::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a do-deregister final packet for a given success flag, timestamp, and security level
    #[allow(unused_results)]
    pub(crate) fn craft_final<R: Ratchet>(
        ratchet: &R,
        success: bool,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let cmd_aux = if success {
            packet_flags::cmd::aux::do_deregister::SUCCESS
        } else {
            packet_flags::cmd::aux::do_deregister::FAILURE
        };

        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod pre_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use citadel_wire::hypernode_type::NodeType;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::packet_flags::payload_identifiers;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::proto::ConnectMode;
    use citadel_types::proto::SessionSecuritySettings;
    use citadel_types::proto::UdpMode;
    use citadel_user::prelude::ConnectProtocol;
    use citadel_user::serialization::SyncIO;
    use citadel_wire::nat_identification::NatType;
    use serde::{Deserialize, Serialize};

    /// Crafts a pre-connect SYN packet for a given transfer, NAT type, UDP mode, timestamp, keep-alive timeout, security level, session security settings, peer-only connect protocol, and connect mode
    #[derive(Serialize, Deserialize)]
    pub struct SynPacket<R: Ratchet> {
        #[serde(bound = "")]
        pub transfer: <R::Constructor as EndpointRatchetConstructor<R>>::AliceToBobWireTransfer,
        pub session_security_settings: SessionSecuritySettings,
        pub peer_only_connect_protocol: ConnectProtocol,
        pub connect_mode: ConnectMode,
        pub nat_type: NatType,
        pub udp_mode: UdpMode,
        pub keep_alive_timeout: i64,
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_syn<R: Ratchet>(
        static_aux_hr: &R,
        transfer: <R::Constructor as EndpointRatchetConstructor<R>>::AliceToBobWireTransfer,
        nat_type: NatType,
        udp_mode: UdpMode,
        timestamp: i64,
        keep_alive_timeout: i64,
        security_level: SecurityLevel,
        session_security_settings: SessionSecuritySettings,
        peer_only_connect_protocol: ConnectProtocol,
        connect_mode: ConnectMode,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            entropy_bank_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        SynPacket::<R> {
            transfer,
            session_security_settings,
            peer_only_connect_protocol,
            connect_mode,
            udp_mode,
            keep_alive_timeout,
            nat_type,
        }
        .serialize_into_buf(&mut packet)
        .unwrap();

        static_aux_hr
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// Crafts a pre-connect SYN acknowledgement packet for a given transfer, NAT type, timestamp, and security level
    #[derive(Serialize, Deserialize)]
    pub struct SynAckPacket<R: Ratchet> {
        #[serde(bound = "")]
        pub transfer: <R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
        pub nat_type: NatType,
    }

    pub(crate) fn craft_syn_ack<R: Ratchet>(
        static_aux_hr: &R,
        transfer: <R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
        nat_type: NatType,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            entropy_bank_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        SynAckPacket::<R> { transfer, nat_type }
            .serialize_into_buf(&mut packet)
            .unwrap();

        static_aux_hr
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a pre-connect stage 0 packet for a given node type, timestamp, and security level
    #[derive(Serialize, Deserialize)]
    pub struct PreConnectStage0 {
        pub node_type: NodeType,
    }

    // This gets sent from Alice to Bob
    pub(crate) fn craft_stage0<R: Ratchet>(
        ratchet: &R,
        timestamp: i64,
        node_type: NodeType,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::new();
        header.inscribe_into(&mut packet);

        PreConnectStage0 { node_type }
            .serialize_into_buf(&mut packet)
            .unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a pre-connect final packet for a given success flag, TCP-only flag, timestamp, and security level
    pub(crate) fn craft_stage_final<R: Ratchet>(
        ratchet: &R,
        success: bool,
        tcp_only: bool,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let cmd_aux = if success {
            packet_flags::cmd::aux::do_preconnect::SUCCESS
        } else {
            packet_flags::cmd::aux::do_preconnect::FAILURE
        };

        let algorithm = if tcp_only {
            payload_identifiers::do_preconnect::TCP_ONLY
        } else {
            0
        };

        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// Crafts a pre-connect begin connect packet for a given timestamp and security level
    pub(crate) fn craft_begin_connect<R: Ratchet>(
        ratchet: &R,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.as_packet();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// Crafts a pre-connect halt packet for a given previous header and fail reason
    pub fn craft_halt<T: AsRef<[u8]>>(prev_header: &HdpHeader, fail_reason: T) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::HALT,
            algorithm: 0,
            security_level: 0,
            context_info: prev_header.context_info,
            group: prev_header.group,
            wave_id: prev_header.wave_id,
            session_cid: prev_header.session_cid,
            entropy_bank_version: prev_header.entropy_bank_version,
            timestamp: prev_header.timestamp,
            target_cid: U64::new(0),
        };

        let fail_reason = fail_reason.as_ref();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + fail_reason.len());
        header.inscribe_into(&mut packet);
        packet.put(fail_reason);

        packet
    }
}

pub(crate) mod peer_cmd {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
    use crate::proto::peer::peer_layer::ChannelPacket;
    use crate::proto::remote::Ticket;
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_crypt::scramble::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use citadel_types::crypto::SecurityLevel;
    use citadel_user::serialization::SyncIO;
    use serde::Serialize;
    use zerocopy::{I64, U128, U32, U64};

    /// Crafts a peer signal packet for a given peer command, ticket, timestamp, and security level
    pub(crate) const C2S_IDENTITY_CID: u64 = 0;
    /*

    */
    /// Peer signals, unlike channels, DO NOT get a target_cid because they require the central server's participation to increase security between the
    /// two nodes
    pub(crate) fn craft_peer_signal<T: SyncIO + Serialize, R: Ratchet>(
        ratchet: &R,
        peer_command: T,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(C2S_IDENTITY_CID),
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a peer signal endpoint packet for a given peer command, ticket, timestamp, target CID, and security level
    #[allow(dead_code)]
    pub(crate) fn craft_peer_signal_endpoint<T: SyncIO + Serialize, R: Ratchet>(
        ratchet: &R,
        peer_command: T,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a channel packet for a given payload, ticket, proxy target CID, timestamp, and security level
    #[allow(dead_code)]
    pub(crate) fn craft_channel_packet<R: Ratchet>(
        ratchet: &R,
        payload: ChannelPacket,
        ticket: Ticket,
        proxy_target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::CHANNEL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid),
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a group message packet for a given payload, ticket, proxy target CID, timestamp, and security level
    #[allow(dead_code)]
    pub(crate) fn craft_group_message_packet<R: Ratchet>(
        ratchet: &R,
        payload: &GroupBroadcast,
        ticket: Ticket,
        proxy_target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid),
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod file {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet_processor::includes::{packet_flags, HdpHeader};
    use crate::proto::remote::Ticket;
    use crate::proto::state_container::VirtualTargetType;
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::prelude::TransferType;
    use citadel_types::proto::{ObjectId, VirtualObjectMetadata};
    use citadel_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use zerocopy::{I64, U128, U32, U64};

    /// Crafts a file transfer error packet for a given error message, object ID, ticket, security level, virtual target, timestamp, and transfer type
    #[derive(Serialize, Deserialize, Debug)]
    pub struct FileTransferErrorPacket {
        pub error_message: String,
        pub object_id: ObjectId,
    }

    pub(crate) fn craft_file_error_packet<R: Ratchet>(
        ratchet: &R,
        ticket: Ticket,
        security_level: SecurityLevel,
        virtual_target: VirtualTargetType,
        timestamp: i64,
        error_message: String,
        object_id: ObjectId,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_ERROR,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(virtual_target.get_target_cid()),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        let payload = FileTransferErrorPacket {
            error_message,
            object_id,
        };

        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a file header packet for a given file metadata, virtual target, local encryption level, group start, ticket, security level, timestamp, and transfer type
    #[derive(Serialize, Deserialize, Debug)]
    pub struct FileHeaderPacket {
        pub file_metadata: VirtualObjectMetadata,
        pub virtual_target: VirtualTargetType,
        pub local_encryption_level: Option<SecurityLevel>,
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_file_header_packet<R: Ratchet>(
        ratchet: &R,
        group_start: u64,
        ticket: Ticket,
        security_level: SecurityLevel,
        virtual_target: VirtualTargetType,
        file_metadata: VirtualObjectMetadata,
        timestamp: i64,
        local_encryption_level: Option<SecurityLevel>,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(group_start),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(virtual_target.get_target_cid()),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        let payload = FileHeaderPacket {
            file_metadata,
            virtual_target,
            local_encryption_level,
        };

        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a file header acknowledgement packet for a given success flag, object ID, target CID, ticket, security level, virtual target, timestamp, and transfer type
    #[derive(Serialize, Deserialize, Debug)]
    pub struct FileHeaderAckPacket {
        pub success: bool,
        pub virtual_target: VirtualTargetType,
        pub object_id: ObjectId,
        pub transfer_type: TransferType,
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn craft_file_header_ack_packet<R: Ratchet>(
        ratchet: &R,
        success: bool,
        object_id: ObjectId,
        target_cid: u64,
        ticket: Ticket,
        security_level: SecurityLevel,
        virtual_target: VirtualTargetType,
        timestamp: i64,
        transfer_type: TransferType,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        let payload = FileHeaderAckPacket {
            success,
            virtual_target,
            object_id,
            transfer_type,
        };

        payload.serialize_into_buf(&mut packet).unwrap();

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a ReVFSPull packet for a given virtual path, delete on pull flag, security level, ticket, timestamp, and target CID
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ReVFSPullPacket {
        pub virtual_path: PathBuf,
        pub delete_on_pull: bool,
        pub security_level: SecurityLevel,
    }

    pub fn craft_revfs_pull<R: Ratchet>(
        ratchet: &R,
        security_level: SecurityLevel,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        virtual_path: PathBuf,
        delete_on_pull: bool,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::REVFS_PULL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        let payload = ReVFSPullPacket {
            virtual_path,
            delete_on_pull,
            security_level,
        };

        payload.serialize_into_buf(&mut packet).unwrap();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a ReVFSDelete packet for a given virtual path, ticket, timestamp, and target CID
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ReVFSDeletePacket {
        pub virtual_path: PathBuf,
    }

    pub fn craft_revfs_delete<R: Ratchet>(
        ratchet: &R,
        security_level: SecurityLevel,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        virtual_path: PathBuf,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::REVFS_DELETE,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        let payload = ReVFSDeletePacket { virtual_path };

        payload.serialize_into_buf(&mut packet).unwrap();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a ReVFSAck packet for a given success flag, error message, ticket, timestamp, and target CID
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ReVFSAckPacket {
        pub success: bool,
        pub error_msg: Option<String>,
    }

    pub fn craft_revfs_ack<R: Ratchet>(
        ratchet: &R,
        security_level: SecurityLevel,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        error_msg: Option<String>,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::REVFS_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        let success = error_msg.is_none();
        let payload = ReVFSAckPacket { success, error_msg };

        payload.serialize_into_buf(&mut packet).unwrap();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Crafts a ReVFSPullAck packet for a given payload, ticket, timestamp, and target CID
    #[derive(Serialize, Deserialize, Debug)]
    pub enum ReVFSPullAckPacket {
        Success,
        Error { error: String },
    }

    pub fn craft_revfs_pull_ack<R: Ratchet>(
        ratchet: &R,
        security_level: SecurityLevel,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        payload: ReVFSPullAckPacket,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::REVFS_PULL_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        payload.serialize_into_buf(&mut packet).unwrap();
        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod udp {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use zerocopy::{U32, U64};

    /// Crafts a UDP packet for a given command auxiliary, payload, target CID, and security level
    pub(crate) fn craft_udp_packet<R: Ratchet>(
        ratchet: &R,
        cmd_aux: u8,
        payload: BytesMut,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::UDP,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: Default::default(),
            group: Default::default(),
            wave_id: Default::default(),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: Default::default(),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.len());
        header.inscribe_into(&mut packet);
        packet.extend_from_slice(&payload[..]);

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod hole_punch {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::packet::{packet_flags, HdpHeader};
    use bytes::{BufMut, BytesMut};
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use zerocopy::{U32, U64};

    /// Crafts a hole punch packet for a given plaintext, security level, target CID, and hyper ratchet
    pub fn generate_packet<R: Ratchet>(
        ratchet: &R,
        plaintext: &[u8],
        security_level: SecurityLevel,
        target_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
            cmd_primary: packet_flags::cmd::primary::HOLE_PUNCH,
            cmd_aux: packet_flags::cmd::aux::udp::HOLE_PUNCH,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: Default::default(),
            group: Default::default(),
            wave_id: Default::default(),
            session_cid: U64::new(ratchet.get_cid()),
            entropy_bank_version: U32::new(ratchet.version()),
            timestamp: Default::default(),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::new();
        header.inscribe_into(&mut packet);
        packet.put(plaintext);

        ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Decrypts a hole punch packet for a given packet, hyper ratchet, security level, and target CID
    pub fn decrypt_packet<R: Ratchet>(
        ratchet: &R,
        packet: &[u8],
        security_level: SecurityLevel,
    ) -> Option<BytesMut> {
        if packet.len() < HDP_HEADER_BYTE_LEN {
            log::warn!(target: "citadel", "Bad hole-punch packet size. Len: {} | {:?}", packet.len(), packet);
            return None;
        }

        let mut packet = BytesMut::from(packet);
        let header = packet.split_to(HDP_HEADER_BYTE_LEN);

        ratchet
            .validate_message_packet_in_place_split(Some(security_level), &header, &mut packet)
            .ok()?;

        Some(packet)
    }
}
