use bytes::BytesMut;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::net::crypt_splitter::{GroupReceiverConfig, GroupSenderDevice};
use netbeam::time_tracker::TimeTracker;

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::proto::hdp_node::Ticket;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::state_container::VirtualTargetType;
use hyxe_crypt::net::crypt_splitter::oneshot_unencrypted_group_unified;
use hyxe_crypt::secure_buffer::sec_packet::SecureMessagePacket;
use hyxe_crypt::stacked_ratchet::{Ratchet, StackedRatchet};

#[derive(Debug)]
/// A thin wrapper used for convenient creation of zero-copy outgoing buffers
pub struct SecureProtocolPacket {
    inner: SecureMessagePacket<HDP_HEADER_BYTE_LEN>,
}

impl SecureProtocolPacket {
    pub(crate) fn new() -> Self {
        Self {
            inner: SecureMessagePacket::new().unwrap(),
        }
    }

    pub(crate) fn extract_message(input: &mut BytesMut) -> std::io::Result<BytesMut> {
        SecureMessagePacket::<HDP_HEADER_BYTE_LEN>::extract_payload(input)
    }

    pub(crate) fn from_inner(inner: SecureMessagePacket<HDP_HEADER_BYTE_LEN>) -> Self {
        Self { inner }
    }
}

impl<T: AsRef<[u8]>> From<T> for SecureProtocolPacket {
    fn from(bytes: T) -> Self {
        let bytes = bytes.as_ref();
        let mut this = Self::new();
        this.inner
            .write_payload(bytes.len() as u32, |slice| Ok(slice.copy_from_slice(bytes)))
            .unwrap();
        this
    }
}

impl Into<SecureMessagePacket<HDP_HEADER_BYTE_LEN>> for SecureProtocolPacket {
    fn into(self) -> SecureMessagePacket<HDP_HEADER_BYTE_LEN> {
        self.inner
    }
}

pub struct GroupTransmitter {
    pub hyper_ratchet_container: RatchetPacketCrafterContainer,
    to_primary_stream: OutboundPrimaryStreamSender,
    // Handles the encryption and scrambling asynchronously. Also manages missing packets
    pub(crate) group_transmitter: GroupSenderDevice<HDP_HEADER_BYTE_LEN>,
    /// Contained within Self::group_transmitter, but is here for convenience
    group_config: GroupReceiverConfig,
    object_id: u32,
    pub group_id: u64,
    /// For interfacing with the higher-level kernel
    ticket: Ticket,
    security_level: SecurityLevel,
    bytes_encrypted: usize,
    time_tracker: TimeTracker,
    is_message: bool,
}

/// The base ratchet is always required, whether between HyperLAN peer to server or hyperlan p2p.
/// base_constructor may not be present, since a concurrent update may already be occuring
///
/// Fcm may be present, in which case, the innermost encryption pass goes through the fcm ratchet to ensure
/// Google can't see the information. The fcm constructor may not be present either, since a concurrent update may
/// be occuring
pub struct RatchetPacketCrafterContainer<R: Ratchet = StackedRatchet> {
    pub base: R,
    pub base_constructor: Option<R::Constructor>,
}

impl<R: Ratchet> RatchetPacketCrafterContainer<R> {
    pub fn new(base: R, base_constructor: Option<R::Constructor>) -> Self {
        Self {
            base,
            base_constructor,
        }
    }
}

impl GroupTransmitter {
    /// Scrambled packets will use this
    pub fn new_from_group_sender(
        to_primary_stream: OutboundPrimaryStreamSender,
        group_sender: GroupSenderDevice<HDP_HEADER_BYTE_LEN>,
        hyper_ratchet: RatchetPacketCrafterContainer,
        object_id: u32,
        ticket: Ticket,
        security_level: SecurityLevel,
        time_tracker: TimeTracker,
    ) -> Self {
        let cfg = group_sender.get_receiver_config();
        let group_id = cfg.group_id as u64;
        let bytes_encrypted = cfg.plaintext_length;
        Self {
            hyper_ratchet_container: hyper_ratchet,
            // This must be false
            is_message: false,
            group_transmitter: group_sender,
            to_primary_stream,
            group_config: cfg,
            object_id,
            group_id,
            ticket,
            security_level,
            bytes_encrypted,
            time_tracker,
        }
    }

    /// Creates a new stream for a request
    pub fn new_message(
        to_primary_stream: OutboundPrimaryStreamSender,
        object_id: u32,
        hyper_ratchet: RatchetPacketCrafterContainer,
        input_packet: SecureProtocolPacket,
        security_level: SecurityLevel,
        group_id: u64,
        ticket: Ticket,
        time_tracker: TimeTracker,
    ) -> Option<Self> {
        // Gets the latest drill version by default for this operation
        log::trace!(target: "lusna", "Will use StackedRatchet v{} to encrypt group {}", hyper_ratchet.base.version(), group_id);

        let bytes_encrypted = input_packet.inner.message_len(); //the number of bytes that will be encrypted
                                                                // + 1 byte source port offset (needed for sending across port-address-translation networks)
                                                                // + 1 byte recv port offset
        const HDP_HEADER_EXTENDED_BYTE_LEN: usize = HDP_HEADER_BYTE_LEN + 2;
        //let res = encrypt_group_unified(input_packet.into_buffer(), &hyper_ratchet.base, HDP_HEADER_EXTENDED_BYTE_LEN, target_cid, object_id, group_id, craft_wave_payload_packet_into);
        let res = oneshot_unencrypted_group_unified(
            input_packet.into(),
            HDP_HEADER_EXTENDED_BYTE_LEN,
            group_id,
        );

        match res {
            Ok(group_transmitter) => {
                let group_config: GroupReceiverConfig = group_transmitter.get_receiver_config();
                Some(Self {
                    hyper_ratchet_container: hyper_ratchet,
                    is_message: true,
                    object_id,
                    to_primary_stream,
                    group_transmitter,
                    group_config,
                    bytes_encrypted,
                    security_level,
                    group_id,
                    ticket,
                    time_tracker,
                })
            }

            Err(_err) => {
                log::error!(target: "lusna", "The udp packet processor stream was unable to generate the sender for group {}. Aborting", group_id);
                None
            }
        }
    }

    pub fn transmit_group_header(
        &mut self,
        virtual_target: VirtualTargetType,
    ) -> Result<(), NetworkError> {
        let header = self.generate_group_header(virtual_target);
        self.to_primary_stream
            .unbounded_send(header)
            .map_err(|err| NetworkError::msg(format!("Unable to transmit group header: {:?}", err)))
    }

    /// Generates the group header for this set using the pre-allocated slab. Since the group header is always sent through the primary port,
    /// and the wave ports are what receive the packet stream, this should be ran BEFORE streaming self
    pub fn generate_group_header(&mut self, virtual_target: VirtualTargetType) -> BytesMut {
        group::craft_group_header_packet(self, virtual_target)
    }

    pub(super) fn get_unencrypted_oneshot_packet(&mut self) -> Option<SecureProtocolPacket> {
        self.group_transmitter
            .get_oneshot()
            .map(SecureProtocolPacket::from_inner)
    }

    /// Returns the number of bytes that would be encrypted
    pub fn get_total_plaintext_bytes(&self) -> usize {
        self.bytes_encrypted
    }

    #[allow(unused_results)]
    pub fn transmit_tcp_file_transfer(&mut self) -> bool {
        let ref to_primary_stream = self.to_primary_stream;
        log::trace!(target: "lusna", "[Q-TCP] Payload packets to send: {} | Max packets per wave: {}", self.group_config.packets_needed, self.group_config.max_packets_per_wave);
        let to_primary_stream = to_primary_stream.clone();
        let packets = self.group_transmitter.take_all_packets();

        log::trace!(target: "lusna", "Will transfer {} packets", packets.len());
        for packet in packets {
            if let Err(err) = to_primary_stream.unbounded_send(packet.packet) {
                log::error!(target: "lusna", "[FILE] to_primary_stream died {:?}", err);
            }
        }

        log::trace!(target: "lusna", "Group {} has finished transmission", self.group_id);

        true
    }
}

pub(crate) mod group {

    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use hyxe_crypt::packet_vector::PacketVector;
    use hyxe_crypt::prelude::*;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_node::Ticket;
    use crate::proto::hdp_packet::packet_sizes;
    use crate::proto::hdp_packet::packet_sizes::GROUP_HEADER_ACK_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use crate::proto::hdp_packet_crafter::GroupTransmitter;
    use crate::proto::state_container::VirtualTargetType;
    use crate::proto::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::serialization::SyncIO;
    use std::ops::RangeInclusive;

    pub(super) fn craft_group_header_packet(
        processor: &mut GroupTransmitter,
        virtual_target: VirtualTargetType,
    ) -> BytesMut {
        let target_cid = virtual_target.get_target_cid();
        let is_fast_message = if processor.is_message { 1 } else { 0 };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER,
            algorithm: is_fast_message,
            security_level: processor.security_level.value(),
            context_info: U128::new(processor.ticket.0),
            group: U64::new(processor.group_id),
            wave_id: U32::new(processor.object_id),
            session_cid: U64::new(processor.hyper_ratchet_container.base.get_cid()),
            drill_version: U32::new(processor.hyper_ratchet_container.base.version()),
            timestamp: I64::new(processor.time_tracker.get_global_time_ns()),
            target_cid: U64::new(target_cid),
        };

        let mut packet = if processor.is_message {
            let mut packet = processor.get_unencrypted_oneshot_packet().unwrap().inner;
            packet
                .write_header(|buf| Ok(header.inscribe_into_slice(&mut *buf)))
                .unwrap();
            // both the header and payload are now written. Just have to extend the kem info
            let kem = processor
                .hyper_ratchet_container
                .base_constructor
                .as_ref()
                .map(|res| res.stage0_alice());
            let expected_len = kem.serialized_size().unwrap();
            packet
                .write_payload_extension(expected_len as _, |slice| {
                    kem.serialize_into_slice(slice).map_err(|err| {
                        std::io::Error::new(std::io::ErrorKind::Other, err.into_string())
                    })
                })
                .unwrap()
        } else {
            let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_HEADER_BASE_LEN);
            header.inscribe_into(&mut packet);
            let header = GroupHeader::Standard(processor.group_config.clone(), virtual_target);
            header.serialize_into_buf(&mut packet).unwrap();
            packet
        };

        processor
            .hyper_ratchet_container
            .base
            .protect_message_packet(
                Some(processor.security_level),
                HDP_HEADER_BYTE_LEN,
                &mut packet,
            )
            .unwrap();
        packet
    }

    /// `initial_wave_window` should be set the Some if this node is ready to begin receiving the data
    /// `message`: Is appended to the end of the payload
    /// `fast_msg`: If this is true, then that implies the receiver already got the message. The initiator that gets the header ack
    /// needs to only delete the outbound container
    #[allow(unused_results)]
    pub(crate) fn craft_group_header_ack(
        hyper_ratchet: &StackedRatchet,
        object_id: u32,
        group_id: u64,
        target_cid: u64,
        ticket: Ticket,
        initial_wave_window: Option<RangeInclusive<u32>>,
        fast_msg: bool,
        timestamp: i64,
        transfer: KemTransferStatus,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(group_id),
            wave_id: U32::new(object_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let header_ack = GroupHeaderAck::ReadyToReceive {
            fast_msg,
            initial_window: initial_wave_window,
            transfer,
        };

        let mut packet =
            BytesMut::with_capacity(GROUP_HEADER_ACK_LEN + header_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);

        header_ack.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    /// This is called by the scrambler. NOTE: the scramble_drill MUST have the same drill/cid as the message_drill, otherwise
    /// packets will not be rendered on the otherside
    #[inline]
    pub(crate) fn craft_wave_payload_packet_into(
        coords: &PacketVector,
        scramble_drill: &Drill,
        object_id: u32,
        target_cid: u64,
        buffer: &mut BytesMut,
    ) {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_PAYLOAD,
            algorithm: 0,
            security_level: 0, // Irrelevant; supplied by the wave header anyways
            context_info: U128::new(object_id as _),
            group: U64::new(coords.group_id),
            wave_id: U32::new(coords.wave_id),
            session_cid: U64::new(scramble_drill.get_cid()),
            drill_version: U32::new(scramble_drill.get_version()),
            timestamp: I64::new(0), // Irrelevant; supplied by the wave header anyways
            target_cid: U64::new(target_cid),
        };

        // inscribe the header into the supplied buffer
        header.inscribe_into(buffer);
        let src_port = coords.local_port;
        let remote_port = coords.remote_port;
        debug_assert!(src_port <= scramble_drill.get_multiport_width() as u16);
        debug_assert!(remote_port <= scramble_drill.get_multiport_width() as u16);
        buffer.put_u8(src_port as u8);
        buffer.put_u8(remote_port as u8)
    }

    // NOTE: context infos contain the object ID in most of the GROUP packets
    #[allow(dead_code)]
    pub(crate) fn craft_wave_ack(
        hyper_ratchet: &StackedRatchet,
        object_id: u32,
        target_cid: u64,
        group_id: u64,
        wave_id: u32,
        timestamp: i64,
        range: Option<RangeInclusive<u32>>,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(object_id as _),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let wave_ack = WaveAck { range };
        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + wave_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        wave_ack.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_connect {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use crate::proto::peer::peer_layer::MailboxTransfer;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::auth::proposed_credentials::ProposedCredentials;
    use hyxe_user::external_services::ServicesObject;
    use hyxe_user::prelude::MutualPeer;
    use hyxe_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct DoConnectStage0Packet {
        pub proposed_credentials: ProposedCredentials,
    }

    /// Alice receives the nonce from Bob. She must now inscribe her username/password
    #[allow(unused_results)]
    pub(crate) fn craft_stage0_packet(
        hyper_ratchet: &StackedRatchet,
        proposed_credentials: ProposedCredentials,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            // place username len here to allow the other end to know where to split the payload
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let payload = DoConnectStage0Packet {
            proposed_credentials,
        };

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub struct DoConnectFinalStatusPacket<'a> {
        pub mailbox: Option<MailboxTransfer>,
        pub peers: Vec<MutualPeer>,
        pub post_login_object: ServicesObject,
        #[serde(borrow)]
        pub message: &'a [u8],
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final_status_packet<T: AsRef<[u8]>>(
        hyper_ratchet: &StackedRatchet,
        success: bool,
        mailbox: Option<MailboxTransfer>,
        post_login_object: ServicesObject,
        message: T,
        peers: Vec<MutualPeer>,
        timestamp: i64,
        security_level: SecurityLevel,
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

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_success_ack(
        hyper_ratchet: &StackedRatchet,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::SUCCESS_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod keep_alive {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;

    pub(crate) fn craft_keep_alive_packet(
        hyper_ratchet: &StackedRatchet,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::KEEP_ALIVE,
            cmd_aux: 0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();
        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_register {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer};
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::auth::proposed_credentials::ProposedCredentials;
    use hyxe_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub(crate) struct DoRegisterStage0<'a> {
        #[serde(borrow)]
        pub(crate) transfer: AliceToBobTransfer<'a>,
        pub(crate) passwordless: bool,
    }

    /// At this stage, the drill does not exist. There is no verifying such packets. The payload contains Alice's public key.
    ///
    /// Since this is sent over TCP, the size of the packet can be up to ~64k bytes
    ///
    /// We also use the NID in place of the CID because the CID only exists AFTER registration completes
    pub(crate) fn craft_stage0(
        algorithm: u8,
        timestamp: i64,
        transfer: AliceToBobTransfer<'_>,
        passwordless: bool,
        proposed_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE0,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        packet.put(header.into_packet());

        DoRegisterStage0 {
            transfer,
            passwordless,
        }
        .serialize_into_buf(&mut packet)
        .unwrap();

        packet
    }

    /// Bob crafts a packet with the ciphertext
    pub(crate) fn craft_stage1(
        algorithm: u8,
        timestamp: i64,
        transfer: BobToAliceTransfer,
        proposed_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE1,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);

        header.inscribe_into(&mut packet);
        transfer.serialize_into(&mut packet).unwrap();

        packet
    }

    #[derive(Serialize, Deserialize)]
    pub struct DoRegisterStage2Packet {
        pub credentials: ProposedCredentials,
    }

    /// Alice sends this. The stage 3 packet contains the encrypted username, password, and full name of the registering client
    #[allow(unused_results)]
    pub(crate) fn craft_stage2(
        hyper_ratchet: &StackedRatchet,
        algorithm: u8,
        timestamp: i64,
        credentials: &ProposedCredentials,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE2,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(0),
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

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// `success_message`: This is NOT encrypted in this closure. Make sure to encrypt it beforehand if necessary
    pub(crate) fn craft_success<T: AsRef<[u8]>>(
        hyper_ratchet: &StackedRatchet,
        algorithm: u8,
        timestamp: i64,
        success_message: T,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let success_message = success_message.as_ref();
        let success_message_len = success_message.len();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::SUCCESS,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + success_message_len);
        header.inscribe_into(&mut packet);
        packet.put(success_message);

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// No encryption used for this packet
    pub(crate) fn craft_failure<T: AsRef<[u8]>>(
        algorithm: u8,
        timestamp: i64,
        error_message: T,
        proposed_cid: u64,
    ) -> BytesMut {
        let error_message = error_message.as_ref();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::FAILURE,
            algorithm,
            security_level: 0,
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(proposed_cid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + error_message.len());
        header.inscribe_into(&mut packet);
        packet.put(error_message);

        packet
    }
}

/// For creating disconnect packets
pub mod do_disconnect {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_node::Ticket;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;

    /// The drill used should be an unused one. (generate a new drill)
    #[allow(unused_results)]
    pub(crate) fn craft_stage0(
        hyper_ratchet: &StackedRatchet,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();
        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Bob sends Alice an message implying the disconnect has been handled
    #[allow(unused_results)]
    pub(crate) fn craft_final(
        hyper_ratchet: &StackedRatchet,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::FINAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();
        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod do_drill_update {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, packet_sizes, HdpHeader};
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::constructor::AliceToBobTransfer;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::serialization::SyncIO;
    use serde::{Deserialize, Serialize};

    #[allow(unused_results)]
    pub(crate) fn craft_stage0(
        hyper_ratchet: &StackedRatchet,
        transfer: AliceToBobTransfer<'_>,
        timestamp: i64,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        transfer.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct Stage1UpdatePacket {
        pub(crate) update_status: KemTransferStatus,
    }

    #[allow(unused_results)]
    pub(crate) fn craft_stage1(
        hyper_ratchet: &StackedRatchet,
        update_status: KemTransferStatus,
        timestamp: i64,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE1,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);

        let stage1_packet = Stage1UpdatePacket { update_status };
        stage1_packet.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct TruncatePacket {
        pub(crate) truncate_version: Option<u32>,
    }

    #[allow(unused_results)]
    pub(crate) fn craft_truncate(
        hyper_ratchet: &StackedRatchet,
        truncate_version: Option<u32>,
        target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::TRUNCATE,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);
        // encrypt the nonce into the packet
        TruncatePacket { truncate_version }
            .serialize_into_buf(&mut packet)
            .unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct TruncateAckPacket {
        pub(crate) truncated_version: u32,
    }

    pub(crate) fn craft_truncate_ack(
        hyper_ratchet: &StackedRatchet,
        truncated_version: u32,
        target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::TRUNCATE_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);

        TruncateAckPacket { truncated_version }
            .serialize_into_buf(&mut packet)
            .unwrap();
        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod do_deregister {
    use bytes::BytesMut;
    use zerocopy::{I64, U128, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;

    pub(crate) fn craft_stage0(
        hyper_ratchet: &StackedRatchet,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final(
        hyper_ratchet: &StackedRatchet,
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
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }
}

pub(crate) mod pre_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U128, U32, U64};

    use hyxe_wire::hypernode_type::NodeType;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_node::ConnectMode;
    use crate::proto::hdp_packet::packet_flags::payload_identifiers;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use crate::proto::misc::session_security_settings::SessionSecuritySettings;
    use crate::proto::peer::peer_layer::UdpMode;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer};
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_crypt::toolset::StaticAuxRatchet;
    use hyxe_user::prelude::ConnectProtocol;
    use hyxe_user::serialization::SyncIO;
    use hyxe_wire::nat_identification::NatType;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct SynPacket<'a> {
        #[serde(borrow)]
        pub transfer: AliceToBobTransfer<'a>,
        pub session_security_settings: SessionSecuritySettings,
        pub peer_only_connect_protocol: ConnectProtocol,
        pub connect_mode: ConnectMode,
        pub nat_type: NatType,
        pub udp_mode: UdpMode,
        pub keep_alive_timeout: i64,
    }

    pub(crate) fn craft_syn(
        static_aux_hr: &StaticAuxRatchet,
        transfer: AliceToBobTransfer<'_>,
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
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(crate::constants::BUILD_VERSION as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            drill_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        SynPacket {
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

    #[derive(Serialize, Deserialize)]
    pub struct SynAckPacket {
        pub transfer: BobToAliceTransfer,
        pub nat_type: NatType,
    }

    pub(crate) fn craft_syn_ack(
        static_aux_hr: &StaticAuxRatchet,
        transfer: BobToAliceTransfer,
        nat_type: NatType,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            drill_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        SynAckPacket { transfer, nat_type }
            .serialize_into_buf(&mut packet)
            .unwrap();

        static_aux_hr
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    #[derive(Serialize, Deserialize)]
    pub struct PreConnectStage0 {
        pub node_type: NodeType,
    }

    // This gets sent from Alice to Bob
    pub(crate) fn craft_stage0(
        hyper_ratchet: &StackedRatchet,
        timestamp: i64,
        node_type: NodeType,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = BytesMut::new();
        header.inscribe_into(&mut packet);

        PreConnectStage0 { node_type }
            .serialize_into_buf(&mut packet)
            .unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// If `tcp_only` is set to true, then the primary stream will be used for sharing information instead of the wave ports
    pub(crate) fn craft_stage_final(
        hyper_ratchet: &StackedRatchet,
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
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux,
            algorithm,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    pub(crate) fn craft_begin_connect(
        hyper_ratchet: &StackedRatchet,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0),
        };

        let mut packet = header.into_packet();
        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();
        packet
    }

    pub fn craft_halt<T: AsRef<[u8]>>(prev_header: &HdpHeader, fail_reason: T) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::HALT,
            algorithm: 0,
            security_level: 0,
            context_info: prev_header.context_info,
            group: prev_header.group,
            wave_id: prev_header.wave_id,
            session_cid: prev_header.session_cid,
            drill_version: prev_header.drill_version,
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
    use crate::proto::hdp_node::Ticket;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
    use crate::proto::peer::peer_layer::ChannelPacket;
    use bytes::BytesMut;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::serialization::SyncIO;
    use serde::Serialize;
    use zerocopy::{I64, U128, U32, U64};

    pub(crate) const C2S_ENCRYPTION_ONLY: u64 = 0;
    /*

    */
    /// Peer signals, unlike channels, DO NOT get a target_cid because they require the central server's participation to increase security between the
    /// two nodes
    pub(crate) fn craft_peer_signal<T: SyncIO + Serialize>(
        hyper_ratchet: &StackedRatchet,
        peer_command: T,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(C2S_ENCRYPTION_ONLY),
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    #[allow(dead_code)]
    pub(crate) fn craft_peer_signal_endpoint<T: SyncIO + Serialize>(
        hyper_ratchet: &StackedRatchet,
        peer_command: T,
        ticket: Ticket,
        timestamp: i64,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Channel packets ALWAYS get rerouted, and hence NEED a target_cid
    #[allow(dead_code)]
    pub(crate) fn craft_channel_packet(
        hyper_ratchet: &StackedRatchet,
        payload: ChannelPacket,
        ticket: Ticket,
        proxy_target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::CHANNEL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid),
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// Group message packets, unlike channel packets, do not always get rerouted
    #[allow(dead_code)]
    pub(crate) fn craft_group_message_packet(
        hyper_ratchet: &StackedRatchet,
        payload: &GroupBroadcast,
        ticket: Ticket,
        proxy_target_cid: u64,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid),
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet =
            BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod file {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_node::Ticket;
    use crate::proto::packet_processor::includes::{packet_flags, HdpHeader, SecurityLevel};
    use crate::proto::state_container::VirtualTargetType;
    use bytes::{BufMut, BytesMut};
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_user::backend::utils::VirtualObjectMetadata;
    use zerocopy::{I64, U128, U32, U64};

    pub(crate) fn craft_file_header_packet(
        hyper_ratchet: &StackedRatchet,
        group_start: u64,
        ticket: Ticket,
        security_level: SecurityLevel,
        virtual_target: VirtualTargetType,
        file_metadata: VirtualObjectMetadata,
        timestamp: i64,
    ) -> BytesMut {
        let metadata_serialized = file_metadata.serialize();
        let serialized_vt = virtual_target.serialize();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(group_start),
            wave_id: U32::new(serialized_vt.len() as u32),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(virtual_target.get_target_cid()),
        };

        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN
                + serialized_vt.len()
                + metadata_serialized.len()
                + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        //processor.group_config.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());
        packet.put(metadata_serialized.as_slice());

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    pub(crate) fn craft_file_header_ack_packet(
        hyper_ratchet: &StackedRatchet,
        success: bool,
        object_id: u32,
        target_cid: u64,
        ticket: Ticket,
        security_level: SecurityLevel,
        virtual_target: VirtualTargetType,
        timestamp: i64,
    ) -> BytesMut {
        let success: u64 = if success { 1 } else { 0 };
        let serialized_vt = virtual_target.serialize();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U128::new(ticket.0),
            group: U64::new(success),
            wave_id: U32::new(object_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(
            HDP_HEADER_BYTE_LEN + serialized_vt.len() + AES_GCM_GHASH_OVERHEAD,
        );
        header.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod udp {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use bytes::BytesMut;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use zerocopy::{U32, U64};

    pub(crate) fn craft_udp_packet(
        hyper_ratchet: &StackedRatchet,
        cmd_aux: u8,
        payload: BytesMut,
        target_cid: u64,
        security_level: SecurityLevel,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::UDP,
            cmd_aux,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: Default::default(),
            group: Default::default(),
            wave_id: Default::default(),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: Default::default(),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.len());
        header.inscribe_into(&mut packet);
        packet.extend_from_slice(&payload[..]);

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }
}

pub(crate) mod hole_punch {
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::proto::hdp_packet::{packet_flags, HdpHeader};
    use bytes::{BufMut, BytesMut};
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use zerocopy::{U32, U64};

    pub fn generate_packet(
        hyper_ratchet: &StackedRatchet,
        plaintext: &[u8],
        security_level: SecurityLevel,
        target_cid: u64,
    ) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::HOLE_PUNCH,
            cmd_aux: packet_flags::cmd::aux::udp::HOLE_PUNCH,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: Default::default(),
            group: Default::default(),
            wave_id: Default::default(),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: Default::default(),
            target_cid: U64::new(target_cid),
        };

        let mut packet = BytesMut::new();
        header.inscribe_into(&mut packet);
        packet.put(plaintext);

        hyper_ratchet
            .protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)
            .unwrap();

        packet
    }

    /// this is called assuming the CORRECT hyper ratchet is used (i.e., the same one used above)
    /// This strips the header, since it's only relevant to the networking protocol and NOT the hole-puncher
    pub fn decrypt_packet(
        _hyper_ratchet: &StackedRatchet,
        packet: &[u8],
        _security_level: SecurityLevel,
    ) -> Option<BytesMut> {
        if packet.len() < HDP_HEADER_BYTE_LEN {
            log::warn!(target: "lusna", "Bad hole-punch packet size. Len: {} | {:?}", packet.len(), packet);
            return None;
        }

        let mut packet = BytesMut::from(packet);
        let _header = packet.split_to(HDP_HEADER_BYTE_LEN);

        _hyper_ratchet
            .validate_message_packet_in_place_split(Some(_security_level), &_header, &mut packet)
            .ok()?;

        Some(packet)
    }
}
