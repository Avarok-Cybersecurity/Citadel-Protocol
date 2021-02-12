use bytes::{Bytes, BytesMut};
use num::Integer;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::net::crypt_splitter::{GroupReceiverConfig, encrypt_group_unified};
use hyxe_nat::time_tracker::TimeTracker;

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::hdp::hdp_packet_crafter::group::craft_wave_payload_packet_into;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::outbound_sender::{OutboundUdpSender, OutboundTcpSender};
use std::ops::RangeInclusive;
use crate::hdp::state_container::{VirtualTargetType, GroupSender};
use hyxe_crypt::sec_bytes::SecBuffer;
use crate::error::NetworkError;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;

/// Sends the header (manual!) and tail (auto!) packets through the primary stream directly, and
/// the rest of the packets (the payload packets) get streamed to the [HdpServer] layer
pub struct GroupTransmitter {
    hyper_ratchet: HyperRatchet,
    to_primary_stream: OutboundTcpSender,
    // Handles the encryption and scrambling asynchronously. Also manages missing packets
    group_transmitter: GroupSender,
    /// Contained within Self::group_transmitter, but is here for convenience
    group_config: GroupReceiverConfig,
    object_id: u32,
    pub group_id: u64,
    target_cid: u64,
    /// For interfacing with the higher-level kernel
    ticket: Ticket,
    security_level: SecurityLevel,
    bytes_encrypted: usize,
    /// Denotes the current wave being sent
    current_wave: usize,
    packets_sent: usize,
    time_tracker: TimeTracker,
    is_message: bool
}

/// For communicating between the packet crafter and the higher-levels
pub enum CraftResult {
    /// Data, local_port, remote_port
    Packet(Bytes, u16, u16),
    /// And error occured
    Error(String),
}

/// For determining the type of packet
#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum WavePacketType {
    /// A payload type (contains the partitions of the scrambled ciphertext)
    WAVE_PAYLOAD,
    /// Tells the receiving end that it has sent all the packets
    WAVE_TAIL,
}

impl GroupTransmitter {
    pub fn new_from_group_sender(to_primary_stream: OutboundTcpSender, group_sender: GroupSender, hyper_ratchet: HyperRatchet, object_id: u32, target_cid: u64, ticket: Ticket, security_level: SecurityLevel, time_tracker: TimeTracker) -> Self {
        let cfg = inner!(group_sender).get_receiver_config();
        let group_id = cfg.group_id as u64;
        let bytes_encrypted = cfg.plaintext_length;
        Self {
            hyper_ratchet,
            // This must be false
            is_message: false,
            group_transmitter: group_sender,
            to_primary_stream,
            group_config: cfg,
            object_id,
            group_id,
            target_cid,
            ticket,
            security_level,
            bytes_encrypted,
            current_wave: 0,
            packets_sent: 0,
            time_tracker
        }
    }
    /// Creates a new stream for a request
    pub fn new_message(to_primary_stream: OutboundTcpSender, object_id: u32, target_cid: u64, hyper_ratchet: HyperRatchet, input_packet: SecBuffer, security_level: SecurityLevel, group_id: u64, ticket: Ticket, time_tracker: TimeTracker) -> Option<Self> {
        // Gets the latest drill version by default for this operation
        log::trace!("Will use HyperRatchet v{} to encrypt group {}", hyper_ratchet.version(), group_id);

        let bytes_encrypted = input_packet.len(); //the number of bytes that will be encrypted
        // + 1 byte source port offset (needed for sending across port-address-translation networks)
        // + 1 byte recv port offset
        const HDP_HEADER_EXTENDED_BYTE_LEN: usize = HDP_HEADER_BYTE_LEN + 2;
        match encrypt_group_unified(input_packet.into_buffer(), &hyper_ratchet, HDP_HEADER_EXTENDED_BYTE_LEN, target_cid, object_id, group_id, craft_wave_payload_packet_into) {
            Ok(group_transmitter) => {
                let group_config: GroupReceiverConfig = group_transmitter.get_receiver_config();
                let group_transmitter = GroupSender::from(group_transmitter);
                let current_wave = 0;
                let packets_sent = 0;
                Some(Self {
                    hyper_ratchet,
                    is_message: true,
                    target_cid,
                    object_id,
                    to_primary_stream,
                    group_transmitter,
                    group_config,
                    bytes_encrypted,
                    security_level,
                    packets_sent,
                    group_id,
                    ticket,
                    current_wave,
                    time_tracker
                })
            }

            Err(_err) => {
                log::error!("The wavepacket processor stream was unable to generate the sender for group {}. Aborting", group_id);
                None
            }
        }
    }

    pub fn transmit_group_header(&mut self, virtual_target: VirtualTargetType, alice_transfer: Option<&HyperRatchetConstructor>) -> Result<(), NetworkError> {
        let header = self.generate_group_header(virtual_target, alice_transfer);
        self.to_primary_stream.unbounded_send(header)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// Generates the group header for this set using the pre-allocated slab. Since the group header is always sent through the primary port,
    /// and the wave ports are what receive the packet stream, this should be ran BEFORE streaming self
    pub fn generate_group_header(&mut self, virtual_target: VirtualTargetType, alice_transfer: Option<&HyperRatchetConstructor>) -> BytesMut {
        group::craft_group_header_packet(self, virtual_target, alice_transfer)
    }

    /// Sometimes, we only need a single packet to represent the data. When this happens, we don't scramble
    /// and instead place the ciphertext into the payload of the GROUP_HEADER
    pub(super) fn get_fast_message_payload(&mut self) -> Option<BytesMut> {
        if self.group_config.packets_needed == 1  && self.is_message {
            Some(inner_mut!(self.group_transmitter).get_next_packet().unwrap().packet)
        } else {
            None
        }
    }

    /// Determines how many packets are in the current wave
    pub fn get_packets_in_current_wave(&self) -> usize {
        self.group_config.get_packet_count_in_wave(self.current_wave)
    }

    /// Returns the number of bytes that would be encrypted
    pub fn get_total_plaintext_bytes(&self) -> usize {
        self.bytes_encrypted
    }

    /// Returns the reliability container
    pub fn get_reliability_container(&self) -> GroupSender {
        self.group_transmitter.clone()
    }

    #[allow(unused_comparisons)]
    pub fn transmit_next_window_udp(&mut self, udp_sender: &OutboundUdpSender, wave_window: RangeInclusive<u32>) -> bool {
        let packets_needed = self.group_config.packets_needed;
        let security_level = self.security_level;
        let waves_needed = self.group_config.wave_count;
        let group_id = self.group_id;
        let ref hyper_ratchet = self.hyper_ratchet;
        let ref time_tracker = self.time_tracker;
        let target_cid = self.target_cid;
        let object_id = self.object_id;
        let ref to_primary_stream = self.to_primary_stream;

        let (last_packets_per_wave, packets_per_wave) = packets_needed.div_mod_floor(&self.group_config.max_packets_per_wave);

        debug_assert!(*wave_window.end() < waves_needed as u32);
        log::info!("[Q-UDP] Payload packets to send: {} | Waves: {} | Packets per wave: {} | Last packets per wave: {}", packets_needed, waves_needed, packets_per_wave, last_packets_per_wave);
        let mut transmitter = inner_mut!(self.group_transmitter);
        log::info!("Wave window: ({}, {}]", wave_window.start(), wave_window.end());

        let packets_in_window = wave_window.clone().into_iter().map(|wave_id| transmitter.get_packets_in_wave(wave_id)).sum::<usize>();
        log::info!("[Q-UDP] Packet count in current window: {}", packets_in_window);

        let res = (0..packets_in_window).into_iter().map(|_| transmitter.get_next_packet().unwrap()).try_for_each(|packet| -> Result<(), ()> {
            // for debugging purposes (the >= 0 part), can easily check WAVE_DO_RETRANSMISSIONS by setting the value to > 0
            if packet.vector.true_sequence >= 0 {
                log::info!("[Q-UDP] Sending packet {}", packet.vector.true_sequence);
                if !udp_sender.unbounded_send(packet.packet) {
                    Err(())
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        });

        if res.is_err() {
            log::error!("Unable to send using UDP. Aborting");
            return false;
        }

        let window_tail = group::craft_window_tail(hyper_ratchet, object_id, target_cid, group_id, wave_window.clone(), time_tracker.get_global_time_ns(), security_level);
        if let Err(_) = to_primary_stream.unbounded_send(window_tail) {
            log::error!("TCP send failed");
            return false;
        }

        log::info!("[Q-UDP] Window ({}, {}] of group {} transmitted", wave_window.start(), wave_window.end(), group_id);

        self.packets_sent += packets_in_window;
        self.current_wave += (*wave_window.end() - *wave_window.start()) as usize;
        true
    }

    pub fn transmit_tcp(&mut self) -> bool {
        log::info!("[Q-TCP] Payload packets to send: {} | Max packets per wave: {}", self.group_config.packets_needed, self.group_config.max_packets_per_wave);
        let ref to_primary_stream = self.to_primary_stream;
        let ref mut transmitter = inner_mut!(self.group_transmitter);
        while let Some(ret) = transmitter.get_next_packet() {
            self.packets_sent += 1;
            if to_primary_stream.unbounded_send(ret.packet).is_err() {
                return false;
            }
        }

        log::info!("Group {} has been transmitted", self.group_id);
        true
    }

    #[allow(unused_results)]
    pub fn transmit_tcp_file_transfer(&self) -> bool {
        let packets_needed = self.group_config.packets_needed;
        let ref to_primary_stream = self.to_primary_stream;
        log::info!("[Q-TCP] Payload packets to send: {} | Max packets per wave: {}", self.group_config.packets_needed, self.group_config.max_packets_per_wave);
        let transmitter = self.group_transmitter.clone();
        let to_primary_stream = to_primary_stream.clone();
        spawn!(async move {
            let mut transmitter = inner_mut!(transmitter);
            if let Some(packets) = transmitter.get_next_packets(packets_needed) {
                std::mem::drop(transmitter);
                for packet in packets {
                    if let Err(err) = to_primary_stream.unbounded_send(packet.packet) {
                        log::error!("[FILE] to_primary_stream died {:?}", err);
                    }
                }
            } else {
                log::error!("Unable to load all packets");
            }
        });

        log::info!("Group {} has begun transmission", self.group_id);
        true
    }
}

pub(crate) mod group {

    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use hyxe_crypt::drill_algebra::PacketVector;
    use hyxe_crypt::prelude::*;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::hdp::hdp_packet::packet_sizes;
    use crate::hdp::hdp_packet_crafter::GroupTransmitter;
    use std::ops::RangeInclusive;
    use crate::hdp::state_container::VirtualTargetType;
    use crate::hdp::hdp_packet::packet_sizes::GROUP_HEADER_ACK_LEN;
    use crate::hdp::hdp_server::Ticket;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use crate::hdp::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
    use hyxe_fs::io::SyncIO;
    use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;

    pub const DUAL_ENCRYPTION_ON: u8 = 1;
    // TODO: all GROUP packets require a target_cid. If target_cid != 0, then the packet will get proxied unless sent through direct-p2p
    pub(super) fn craft_group_header_packet(processor: &mut GroupTransmitter, virtual_target: VirtualTargetType, alice_transfer: Option<&HyperRatchetConstructor>) -> BytesMut {
        let mut header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER,
            algorithm: 0,
            security_level: processor.security_level.value(),
            context_info: U64::new(processor.ticket.0),
            group: U64::new(processor.group_id),
            wave_id: U32::new(processor.object_id),
            session_cid: U64::new(processor.hyper_ratchet.get_cid()),
            drill_version: U32::new(processor.hyper_ratchet.version()),
            timestamp: I64::new(processor.time_tracker.get_global_time_ns()),
            target_cid: U64::new(virtual_target.get_target_cid())
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_HEADER_BASE_LEN);

        // first byte in the payload goes to the bool "fast_msg"
        if let Some(fast_msg_payload) = processor.get_fast_message_payload() {
            // set the algorithm to 1
            header.algorithm = DUAL_ENCRYPTION_ON;
            header.inscribe_into(&mut packet);
            // we omit the scrambling, because it's the group is the same as the group in this packet's header, and the wave id is always zero
            // However, is it possible for the drill version to be different? NO. Because it is constructed with a fixed HyperRatchet
            let fast_msg_payload = &fast_msg_payload[HDP_HEADER_BYTE_LEN + 1 + 1 ..];
            let inner_encrypted = processor.hyper_ratchet.encrypt_custom_scrambler(header.wave_id.get(), header.group.get(), fast_msg_payload).unwrap();
            let header = GroupHeader::FastMessage(inner_encrypted, virtual_target, alice_transfer.map(|res| res.stage0_alice()));
            header.serialize_into_buf(&mut packet).unwrap();
            //log::info!("[FAST] len: {} | {:?}", fast_msg_payload.len(), fast_msg_payload);
        } else {
            header.inscribe_into(&mut packet);
            let header = GroupHeader::Standard(processor.group_config.clone(), virtual_target);
            header.serialize_into_buf(&mut packet).unwrap();
        }

        processor.hyper_ratchet.protect_message_packet(Some(processor.security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// `initial_wave_window` should be set the Some if this node is ready to begin receiving the data
    /// `message`: Is appended to the end of the payload
    /// `fast_msg`: If this is true, then that implies the receiver already got the message. The initiator that gets the header ack
    /// needs to only delete the outbound container
    #[allow(unused_results)]
    pub(crate) fn craft_group_header_ack(hyper_ratchet: &HyperRatchet, object_id: u32, group_id: u64, target_cid: u64, ticket: Ticket, initial_wave_window: Option<RangeInclusive<u32>>, fast_msg: bool, timestamp: i64, transfer: KemTransferStatus, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(group_id),
            wave_id: U32::new(object_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let header_ack = GroupHeaderAck::ReadyToReceive { fast_msg, initial_window: initial_wave_window, transfer };

        let mut packet = BytesMut::with_capacity(GROUP_HEADER_ACK_LEN + header_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);

        header_ack.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// This is called by the scrambler. NOTE: the scramble_drill MUST have the same drill/cid as the message_drill, otherwise
    /// packets will not be rendered on the otherside
    #[inline]
    pub(crate) fn craft_wave_payload_packet_into(coords: &PacketVector, scramble_drill: &Drill, object_id: u32, target_cid: u64, buffer: &mut BytesMut) {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_PAYLOAD,
            algorithm: 0,
            security_level: 0, // Irrelevant; supplied by the wave header anyways
            context_info: U64::new(object_id as u64),
            group: U64::new(coords.group_id),
            wave_id: U32::new(coords.wave_id),
            session_cid: U64::new(scramble_drill.get_cid()),
            drill_version: U32::new(scramble_drill.get_version()),
            timestamp: I64::new(0), // Irrelevant; supplied by the wave header anyways
            target_cid: U64::new(target_cid)
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

    #[allow(dead_code)]
    pub(crate) fn craft_window_tail(hyper_ratchet: &HyperRatchet, object_id: u32, target_cid: u64, group_id: u64, waves_in_window: RangeInclusive<u32>, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_WINDOW_TAIL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(*waves_in_window.start()),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_WINDOW_TAIL_LEN);

        header.inscribe_into(&mut packet);
        packet.put_u32(*waves_in_window.end()); // + 4 bytes

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// This is always sent from Bob's side. This a retransmission request packet, and occurs when a timeout for a specific wave occured
    #[allow(unused_results)]
    pub(crate) fn craft_wave_do_retransmission(hyper_ratchet: &HyperRatchet, object_id: u32, target_cid: u64, group_id: u64, wave_id: u32, vectors_missing: &Vec<PacketVector>, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_DO_RETRANSMISSION,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        // Each vector missing will require a u16+u16, or 4 bytes total
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + (vectors_missing.len() * 4));
        header.inscribe_into(&mut packet);

        for missing_vector in vectors_missing {
            // The "local port" refers to Alice, not bob. This should have read "source port" to be more clear
            packet.put_u16(missing_vector.local_port);
            packet.put_u16(missing_vector.remote_port);
            log::info!("Added: {} -> {}", missing_vector.local_port, missing_vector.remote_port);
        }

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    // NOTE: context infos contain the object ID in most of the GROUP packets
    pub(crate) fn craft_wave_ack(hyper_ratchet: &HyperRatchet, object_id: u32, target_cid: u64, group_id: u64, wave_id: u32, timestamp: i64, range: Option<RangeInclusive<u32>>, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let wave_ack = WaveAck { range };
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + wave_ack.serialized_size().unwrap());
        header.inscribe_into(&mut packet);
        wave_ack.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod do_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};


    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::proposed_credentials::ProposedCredentials;
    use crate::hdp::peer::peer_layer::MailboxTransfer;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_fs::prelude::SyncIO;


    /// Alice receives the nonce from Bob. She must now inscribe her username/password
    #[allow(unused_results)]
    pub(crate) fn craft_stage0_packet(hyper_ratchet: &HyperRatchet, proposed_credentials: ProposedCredentials, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let (username, password) = proposed_credentials.decompose_credentials();

        let encrypted_len = hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(username.len() + username.len());
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + encrypted_len);

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            // place username len here to allow the other end to know where to split the payload
            context_info: U64::new(username.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        header.inscribe_into(&mut packet);
        packet.put(username);
        packet.put(password);

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final_status_packet<T: AsRef<[u8]>>(hyper_ratchet: &HyperRatchet, success: bool, mailbox_items_opt: Option<MailboxTransfer>, message: T, peers: Vec<u64>, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let payload = message.as_ref();
        let (mailbox_transfer_len ,mailbox_items) = if let Some(mailbox_items) = mailbox_items_opt {
            let serialized = mailbox_items.serialize_to_vector().unwrap();
            (serialized.len(), Some(serialized))
        } else {
            (0, None)
        };

        let peer_inscribe_len = peers.len() * 8;

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + payload.len() + mailbox_transfer_len + peer_inscribe_len);

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
            context_info: U64::new(payload.len() as u64),
            group: U64::new(mailbox_transfer_len as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        header.inscribe_into(&mut packet);
        packet.put(payload);

        if let Some(mailbox_transfer) = mailbox_items {
            packet.put(mailbox_transfer.as_slice());
        }

        for peer in peers {
            packet.put_u64(peer);
        }

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }
}

pub(crate) mod keep_alive {
    use bytes::BytesMut;
    use zerocopy::{I64, U32, U64};

    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;

    pub(crate) fn craft_keep_alive_packet(hyper_ratchet: &HyperRatchet, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::KEEP_ALIVE,
            cmd_aux: 0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet_mut();
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod do_register {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};


    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::proposed_credentials::ProposedCredentials;
    use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;

    /// At this stage, the drill does not exist. There is no verifying such packets. The payload contains Alice's public key.
    ///
    /// Since this is sent over TCP, the size of the packet can be up to ~64k bytes
    ///
    /// We also use the NID in place of the CID because the CID only exists AFTER registration completes
    pub(crate) fn craft_stage0(algorithm: u8, timestamp: i64, local_nid: u64, transfer: AliceToBobTransfer<'_>, potential_cids_alice: &Vec<u64>) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE0,
            algorithm,
            security_level: 0,
            context_info: U64::new(potential_cids_alice.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + potential_cids_alice.len() * 8);

        packet.put(header.into_packet());
        potential_cids_alice.iter().for_each(|val| packet.put_u64(*val));
        transfer.serialize_into(&mut packet).unwrap();

        packet
    }

    /// Bob crafts a packet with the ciphertext
    pub(crate) fn craft_stage1(algorithm: u8, timestamp: i64, local_nid: u64, transfer: BobToAliceTransfer, reserved_true_cid: u64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE1,
            algorithm,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(reserved_true_cid),
            wave_id: U32::new(0),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);

        header.inscribe_into(&mut packet);
        transfer.serialize_into(&mut packet).unwrap();

        packet
    }

    /// Alice sends this. The stage 3 packet contains the encrypted username, password, and full name of the registering client
    #[allow(unused_results)]
    pub(crate) fn craft_stage2(hyper_ratchet: &HyperRatchet, algorithm: u8, local_nid: u64, timestamp: i64, proposed_credentials: &ProposedCredentials, security_level: SecurityLevel) -> BytesMut {
        let (username_len, password_len, full_name_len) = proposed_credentials.get_item_lengths();
        let ciphertext_payload_len = proposed_credentials.get_expected_ciphertext_length();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE2,
            algorithm,
            security_level: security_level.value(),
            context_info: U64::new(username_len as u64),
            group: U64::new(password_len as u64),
            wave_id: U32::new(full_name_len as u32),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let total_len = HDP_HEADER_BYTE_LEN + ciphertext_payload_len;
        let mut packet = BytesMut::with_capacity(total_len);
        header.inscribe_into(&mut packet);
        proposed_credentials.inscribe_into(&mut packet);
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// `success_message`: This is NOT encrypted in this closure. Make sure to encrypt it beforehand if necessary
    pub(crate) fn craft_success<T: AsRef<[u8]>>(hyper_ratchet: &HyperRatchet, algorithm: u8, local_nid: u64, timestamp: i64, success_message: T, security_level: SecurityLevel) -> BytesMut {
        let success_message = success_message.as_ref();
        let success_message_len = success_message.len();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::SUCCESS,
            algorithm,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };


        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + success_message_len);
        header.inscribe_into(&mut packet);
        packet.put(success_message);

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// No encryption used for this packet
    pub(crate) fn craft_failure<T: AsRef<[u8]>>(algorithm: u8, local_nid: u64, timestamp: i64, error_message: T) -> BytesMut {
        let error_message = error_message.as_ref();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::FAILURE,
            algorithm,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
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
    use zerocopy::{I64, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::hdp::hdp_server::Ticket;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;

    /// The drill used should be an unused one. (generate a new drill)
    #[allow(unused_results)]
    pub(crate) fn craft_stage0(hyper_ratchet: &HyperRatchet, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet_mut();
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// Bob sends Alice an message implying the disconnect has been handled
    #[allow(unused_results)]
    pub(crate) fn craft_final(hyper_ratchet: &HyperRatchet, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::FINAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet_mut();
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }
}

pub(crate) mod do_drill_update {
    use bytes::BytesMut;
    use zerocopy::{I64, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransfer;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_fs::io::SyncIO;
    use serde::{Serialize, Deserialize};
    use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;

    #[allow(unused_results)]
    pub(crate) fn craft_stage0(hyper_ratchet: &HyperRatchet, transfer: AliceToBobTransfer<'_>, timestamp: i64, target_cid: u64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        transfer.serialize_into(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct Stage1UpdatePacket {
        pub(crate) update_status: KemTransferStatus
    }

    #[allow(unused_results)]
    pub(crate) fn craft_stage1(hyper_ratchet: &HyperRatchet, update_status: KemTransferStatus, timestamp: i64, target_cid: u64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE1,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);

        let stage1_packet = Stage1UpdatePacket { update_status };
        stage1_packet.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[derive(Serialize, Deserialize)]
    pub(crate) struct TruncatePacket {
        pub(crate) truncate_version: u32
    }

    #[allow(unused_results)]
    pub(crate) fn craft_truncate(hyper_ratchet: &HyperRatchet, truncate_version: u32, target_cid: u64, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::TRUNCATE,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);
        // encrypt the nonce into the packet
        TruncatePacket { truncate_version }.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod do_deregister {
    use bytes::BytesMut;
    use zerocopy::{I64, U32, U64};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;

    pub(crate) fn craft_stage0(hyper_ratchet: &HyperRatchet, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final(hyper_ratchet: &HyperRatchet, success: bool, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
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
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod pre_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64, LayoutVerified};

    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_nat::udp_traversal::NatTraversalMethod;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use crate::hdp::hdp_packet::packet_flags::payload_identifiers;
    use crate::hdp::hdp_packet_processor::includes::SocketAddr;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use hyxe_crypt::toolset::StaticAuxRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::{AliceToBobTransfer, BobToAliceTransfer};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::drill::SecurityLevel;

    pub(crate) fn craft_syn(static_aux_hr: &StaticAuxRatchet, transfer: AliceToBobTransfer<'_>, tcp_only: bool, timestamp: i64, keep_alive_timeout_ns: i64, security_level: SecurityLevel) -> BytesMut {
        let tcp_only = if tcp_only {
            1
        } else {
            0
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(tcp_only),
            group: U64::new(crate::constants::BUILD_VERSION as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            drill_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(keep_alive_timeout_ns as u64)
        };

        let mut packet  = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        transfer.serialize_into(&mut packet).unwrap();

        static_aux_hr.protect_message_packet(Some(security_level),HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// Must synchronize drills using the static auxiliary drill (which supplies the nonce) and the pqc
    /// TODO: Limit the use of this to a certain frequency. An attacker could flood the node with false
    /// PRE_CONNECT packets. Could limit the number of recoveries by IP, or, node-wide
    pub(crate) fn craft_syn_ack(static_aux_hr: &StaticAuxRatchet, transfer: BobToAliceTransfer, timestamp: i64, peer_external_addr: SocketAddr, security_level: SecurityLevel) -> BytesMut {
        let external_addr_bytes = peer_external_addr.to_string();
        let external_addr_bytes = external_addr_bytes.as_bytes();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(external_addr_bytes.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_hr.get_cid()),
            drill_version: U32::new(static_aux_hr.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + external_addr_bytes.len());
        header.inscribe_into(&mut packet);
        packet.put(external_addr_bytes);
        transfer.serialize_into(&mut packet).unwrap();

        static_aux_hr.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    // This gets sent from Alice to Bob
    pub(crate) fn craft_stage0(hyper_ratchet: &HyperRatchet, local_node_type: HyperNodeType, local_wave_ports: &Vec<u16>, timestamp: i64, peer_external_ip: SocketAddr, security_level: SecurityLevel) -> BytesMut {
        let external_ip_bytes = peer_external_ip.to_string();
        let external_ip_bytes = external_ip_bytes.as_bytes();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE0,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(external_ip_bytes.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let wave_ports_inscribe_len = local_wave_ports.len() * 2; //2bytes/u16
        let packet_len = HDP_HEADER_BYTE_LEN + 1 + external_ip_bytes.len() + wave_ports_inscribe_len;
        let mut packet = BytesMut::with_capacity(packet_len);
        header.inscribe_into(&mut packet);
        packet.put_u8(local_node_type.into_byte());
        packet.put(external_ip_bytes);
        for wave_port in local_wave_ports {
            packet.put_u16(*wave_port);
        }

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_stage1(hyper_ratchet: &HyperRatchet, local_node_type: HyperNodeType, local_wave_ports: &Vec<u16>, initial_nat_traversal_method: NatTraversalMethod, timestamp: i64, sync_time: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE1,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let wave_ports_inscribe_len = local_wave_ports.len() * 2; //2bytes/u16
        // +1 for local node type, +1 for nat traversal method
        let packet_len = HDP_HEADER_BYTE_LEN + 1 + 1 + 8 + wave_ports_inscribe_len + AES_GCM_GHASH_OVERHEAD;
        let mut packet = BytesMut::with_capacity(packet_len);
        header.inscribe_into(&mut packet);
        packet.put_u8(local_node_type.into_byte());
        packet.put_u8(initial_nat_traversal_method.into_byte());
        packet.put_i64(sync_time);

        for wave_port in local_wave_ports {
            packet.put_u16(*wave_port);
        }

        hyper_ratchet.protect_message_packet(Some(security_level),HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_stage_try_next(hyper_ratchet: &HyperRatchet, next_nat_traversal_method: NatTraversalMethod, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_preconnect::STAGE_TRY_NEXT);
        header.inscribe_into(&mut packet);
        packet.put_u8(next_nat_traversal_method.into_byte());
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_stage_try_next_ack(hyper_ratchet: &HyperRatchet, timestamp: i64, sync_time: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_preconnect::STAGE_TRY_NEXT_ACK);
        header.inscribe_into(&mut packet);
        packet.put_i64(sync_time);

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// If `tcp_only` is set to true, then the primary stream will be used for sharing information instead of the wave ports
    pub(crate) fn craft_stage_final(hyper_ratchet: &HyperRatchet, success: bool, tcp_only: bool, timestamp: i64, upnp_ports: Option<Vec<u16>>, security_level: SecurityLevel) -> BytesMut {
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
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = if let Some(upnp_ports) = upnp_ports {
            let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + (2 * upnp_ports.len()));
            header.inscribe_into(&mut packet);
            for upnp_port in upnp_ports {
                packet.put_u16(upnp_port);
            }

            packet
        } else {
            header.into_packet()
        };

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    pub(crate) fn craft_begin_connect(hyper_ratchet: &HyperRatchet, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet();
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    pub(crate) fn craft_server_finished_hole_punch(hyper_ratchet: &HyperRatchet, success: bool, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let algorithm = if success {
            1
        } else {
            0
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::RECEIVER_FINISHED_HOLE_PUNCH,
            algorithm,
            security_level: security_level.value(),
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet();
        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }


    pub fn craft_halt<T: AsRef<[u8]>>(prev_header: &LayoutVerified<&[u8], HdpHeader>, fail_reason: T) -> BytesMut {
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
            target_cid: prev_header.target_cid
        };

        let fail_reason = fail_reason.as_ref();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + fail_reason.len());
        header.inscribe_into(&mut packet);
        packet.put(fail_reason);

        packet
    }
}

pub(crate) mod peer_cmd {
    use bytes::BytesMut;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use zerocopy::{U64, U32, I64};
    use crate::hdp::hdp_server::Ticket;
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use crate::hdp::peer::peer_layer::ChannelPacket;
    use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_fs::io::SyncIO;
    use serde::Serialize;

    pub(crate) const ENDPOINT_ENCRYPTION_OFF: u64 = 0;
    /*

     */
    /// Peer signals, unlike channels, DO NOT get a target_cid because they require the central server's participation to increase security between the
    /// two nodes
    pub(crate) fn craft_peer_signal<T: SyncIO + Serialize>(hyper_ratchet: &HyperRatchet, peer_command: T, ticket: Ticket, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(ENDPOINT_ENCRYPTION_OFF)
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_peer_signal_endpoint<T: SyncIO + Serialize>(hyper_ratchet: &HyperRatchet, peer_command: T, ticket: Ticket, timestamp: i64, target_cid: u64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let peer_cmd_serialized_len = peer_command.serialized_size().unwrap();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + peer_cmd_serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        peer_command.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// Channel packets ALWAYS get rerouted, and hence NEED a target_cid
    #[allow(dead_code)]
    pub(crate) fn craft_channel_packet(hyper_ratchet: &HyperRatchet, payload: ChannelPacket, ticket: Ticket, proxy_target_cid: u64, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::CHANNEL,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid)
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// Group message packets, unlike channel packets, do not always get rerouted
    #[allow(dead_code)]
    pub(crate) fn craft_group_message_packet(hyper_ratchet: &HyperRatchet, payload: &GroupBroadcast, ticket: Ticket, proxy_target_cid: u64, timestamp: i64, security_level: SecurityLevel) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid)
        };
        let serialized_len = payload.serialized_size().unwrap();

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_len + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        payload.serialize_into_buf(&mut packet).unwrap();

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

}

pub(crate) mod file {
    use crate::hdp::hdp_packet_processor::includes::{SecurityLevel, HdpHeader, packet_flags};
    use crate::hdp::hdp_server::Ticket;
    use crate::hdp::state_container::VirtualTargetType;
    use crate::hdp::file_transfer::VirtualFileMetadata;
    use zerocopy::{U64, U32, I64};
    use bytes::{BytesMut, BufMut};
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;

    pub(crate) fn craft_file_header_packet(hyper_ratchet: &HyperRatchet, group_start: u64, ticket: Ticket, security_level: SecurityLevel, virtual_target: VirtualTargetType, file_metadata: VirtualFileMetadata, timestamp: i64) -> BytesMut {
        let metadata_serialized = file_metadata.serialize();
        let serialized_vt = virtual_target.serialize();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(group_start),
            wave_id: U32::new(serialized_vt.len() as u32),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(virtual_target.get_target_cid())
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_vt.len() + metadata_serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        //processor.group_config.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());
        packet.put(metadata_serialized.as_slice());

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_file_header_ack_packet(hyper_ratchet: &HyperRatchet, success: bool, object_id: u32, target_cid: u64, ticket: Ticket, security_level: SecurityLevel, virtual_target: VirtualTargetType, timestamp: i64) -> BytesMut {
        let success: u64 = if success {
            1
        } else {
            0
        };
        let serialized_vt = virtual_target.serialize();
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::FILE,
            cmd_aux: packet_flags::cmd::aux::file::FILE_HEADER_ACK,
            algorithm: 0,
            security_level: security_level.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(success),
            wave_id: U32::new(object_id),
            session_cid: U64::new(hyper_ratchet.get_cid()),
            drill_version: U32::new(hyper_ratchet.version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_vt.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());

        hyper_ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }
}

pub(crate) mod hole_punch {
    use bytes::{BytesMut, BufMut};
    use std::iter::FromIterator;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::prelude::SecurityLevel;

    pub fn generate_packet(hyper_ratchet: &HyperRatchet, local_port: u16, security_level: SecurityLevel) -> BytesMut {
        let mut packet = BytesMut::new();
        packet.put_u16(local_port);
        hyper_ratchet.protect_message_packet(Some(security_level), 0, &mut packet).unwrap();

        packet
    }

    pub fn decrypt_packet(hyper_ratchet: &HyperRatchet, packet: &[u8], security_level: SecurityLevel) -> Option<BytesMut> {
        let mut packet = BytesMut::from_iter(packet);
        hyper_ratchet.validate_message_packet_in_place_split(Some(security_level), &[], &mut packet).ok()?;
        Some(packet)
    }
}