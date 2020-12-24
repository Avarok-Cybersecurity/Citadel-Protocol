use bytes::{Bytes, BytesMut};
use num::Integer;

use ez_pqcrypto::PostQuantumContainer;
use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::net::crypt_splitter::{GroupReceiverConfig, scramble_encrypt_group};
use hyxe_crypt::prelude::Drill;
use hyxe_nat::time_tracker::TimeTracker;

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::hdp::hdp_packet_crafter::group::craft_wave_payload_packet_into;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::outbound_sender::{OutboundUdpSender, OutboundTcpSender};
use std::ops::RangeInclusive;
use crate::hdp::state_container::{VirtualTargetType, GroupSender};
use std::sync::Arc;
use hyxe_crypt::sec_bytes::SecBuffer;
use crate::error::NetworkError;

/// Sends the header (manual!) and tail (auto!) packets through the primary stream directly, and
/// the rest of the packets (the payload packets) get streamed to the [HdpServer] layer
pub struct GroupTransmitter {
    pqc: Arc<PostQuantumContainer>,
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
    drill: Drill,
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
    pub fn new_from_group_sender(to_primary_stream: OutboundTcpSender, group_sender: GroupSender, pqc: Arc<PostQuantumContainer>, drill: Drill, object_id: u32, target_cid: u64, ticket: Ticket, security_level: SecurityLevel, time_tracker: TimeTracker) -> Self {
        let cfg = inner!(group_sender).get_receiver_config();
        let group_id = cfg.group_id as u64;
        let bytes_encrypted = cfg.plaintext_length;
        Self {
            // This must be false
            is_message: false,
            pqc,
            group_transmitter: group_sender,
            to_primary_stream,
            group_config: cfg,
            object_id,
            group_id,
            target_cid,
            ticket,
            drill,
            security_level,
            bytes_encrypted,
            current_wave: 0,
            packets_sent: 0,
            time_tracker
        }
    }
    /// Creates a new stream for a request
    pub fn new(to_primary_stream: OutboundTcpSender, object_id: u32, target_cid: u64, drill: Drill, pqc: &Arc<PostQuantumContainer>, input_packet: SecBuffer, security_level: SecurityLevel, group_id: u64, ticket: Ticket, time_tracker: TimeTracker) -> Option<Self> {
        // Gets the latest drill version by default for this operation
        log::trace!("Will use drill v{} to encrypt group {}", drill.get_version(), group_id);

        let bytes_encrypted = input_packet.len();
        // + 1 byte source port offset (needed for sending across port-address-translation networks)
        // + 1 byte recv port offset
        const HDP_HEADER_EXTENDED_BYTE_LEN: usize = HDP_HEADER_BYTE_LEN + 2;
        match scramble_encrypt_group(input_packet, security_level, &drill, pqc, HDP_HEADER_EXTENDED_BYTE_LEN, target_cid, object_id, group_id, craft_wave_payload_packet_into) {
            Ok(group_transmitter) => {
                let group_config: GroupReceiverConfig = group_transmitter.get_receiver_config();
                let group_transmitter = GroupSender::from(group_transmitter);
                let current_wave = 0;
                let packets_sent = 0;
                Some(Self {
                    is_message: true,
                    pqc: pqc.clone(),
                    target_cid,
                    object_id,
                    to_primary_stream,
                    group_transmitter,
                    drill,
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

    pub fn transmit_group_header(&mut self, virtual_target: VirtualTargetType) -> Result<(), NetworkError> {
        let header = self.generate_group_header(virtual_target);
        self.to_primary_stream.unbounded_send(header)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// Generates the group header for this set using the pre-allocated slab. Since the group header is always sent through the primary port,
    /// and the wave ports are what receive the packet stream, this should be ran BEFORE streaming self
    pub fn generate_group_header(&mut self, virtual_target: VirtualTargetType) -> BytesMut {
        group::craft_group_header_packet(self, virtual_target)
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
        let waves_needed = self.group_config.wave_count;
        let group_id = self.group_id;
        let ref drill = self.drill;
        let ref time_tracker = self.time_tracker;
        let ref pqc = self.pqc;
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

        let window_tail = group::craft_window_tail(pqc, drill, object_id, target_cid, group_id, wave_window.clone(), time_tracker.get_global_time_ns());
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
                /*
                debug_assert_eq!(packets.len(), packets_needed);
                if let Err(_) = to_primary_stream.send_all(&mut tokio::stream::iter(packets.into_iter().map(|packet| Ok(packet.packet)).collect::<Vec<Result<Bytes, futures::channel::mpsc::SendError>>>())).await {
                    log::error!("Unable to send_all stream through TCP channel");
                }*/
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

    // TODO: all GROUP packets require a target_cid. If target_cid != 0, then the packet will get proxied unless sent through direct-p2p
    pub(super) fn craft_group_header_packet(processor: &mut GroupTransmitter, virtual_target: VirtualTargetType) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER,
            algorithm: 0,
            security_level: processor.security_level.value(),
            context_info: U64::new(processor.ticket.0),
            group: U64::new(processor.group_id),
            wave_id: U32::new(processor.object_id),
            session_cid: U64::new(processor.drill.get_cid()),
            drill_version: U32::new(processor.drill.get_version()),
            timestamp: I64::new(processor.time_tracker.get_global_time_ns()),
            target_cid: U64::new(virtual_target.get_target_cid())
        };

        let serialized_vt = virtual_target.serialize();
        let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_HEADER_BASE_LEN + serialized_vt.len());
        header.inscribe_into(&mut packet);
        // first byte in the payload goes to the bool "fast_msg"
        if let Some(fast_msg_payload) = processor.get_fast_message_payload() {
            // we need to parse just the payload of the wave packet
            let fast_msg_payload = &fast_msg_payload[(HDP_HEADER_BYTE_LEN + 1 + 1)..];
            // in this case, we do not attach the group config. The other end will decrypt payload with wave_idx = 0, group_id = group_id in header
            packet.put_u8(1);
            packet.put_u64(fast_msg_payload.len() as u64);
            packet.put(fast_msg_payload);
            packet.put(serialized_vt.as_slice());

            //log::info!("[FAST] len: {} | {:?}", fast_msg_payload.len(), fast_msg_payload);
        } else {
            packet.put_u8(0);
            processor.group_config.inscribe_into(&mut packet);
            packet.put(serialized_vt.as_slice());
        }

        let ref pqc = processor.pqc;
        processor.drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// `initial_wave_window` should be set the Some if this node is ready to begin receiving the data
    /// `message`: Is appended to the end of the payload
    /// `fast_msg`: If this is true, then that implies the receiver already got the message. The initiator that gets the header ack
    /// needs to only delete the outbound container
    #[allow(unused_results)]
    pub(crate) fn craft_group_header_ack(pqc: &PostQuantumContainer, object_id: u32, group_id: u64, target_cid: u64, ticket: Ticket, drill: &Drill, initial_wave_window: Option<RangeInclusive<u32>>, fast_msg: bool, timestamp: i64) -> BytesMut {
        const SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;
        //log::info!("Creating header ACK with session_cid of {}", drill.get_cid());
        let fast_msg = if fast_msg { 1 } else { 0 };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_HEADER_ACK,
            algorithm: 0,
            security_level: SECURITY_LEVEL.value(),
            context_info: U64::new(ticket.0),
            group: U64::new(group_id),
            wave_id: U32::new(object_id),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(GROUP_HEADER_ACK_LEN);
        header.inscribe_into(&mut packet);
        if let Some(initial_wave_window) = initial_wave_window {
            packet.put_u8(1);
            packet.put_u8(fast_msg);
            packet.put_u32(*initial_wave_window.start());
            packet.put_u32(*initial_wave_window.end());
        } else {
            packet.put_u8(0);
            packet.put_u8(fast_msg);
            packet.put_u32(0);
            packet.put_u32(0);
        }

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// This is called by the scrambler
    #[inline]
    pub(crate) fn craft_wave_payload_packet_into(coords: &PacketVector, drill: &Drill, object_id: u32, target_cid: u64, buffer: &mut BytesMut) {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_PAYLOAD,
            algorithm: 0,
            security_level: 0, // Irrelevant; supplied by the wave header anyways
            context_info: U64::new(object_id as u64),
            group: U64::new(coords.group_id),
            wave_id: U32::new(coords.wave_id),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(0), // Irrelevant; supplied by the wave header anyways
            target_cid: U64::new(target_cid)
        };

        // inscribe the header into the supplied buffer
        header.inscribe_into(buffer);
        let src_port = coords.local_port;
        let remote_port = coords.remote_port;
        debug_assert!(src_port <= drill.get_multiport_width() as u16);
        debug_assert!(remote_port <= drill.get_multiport_width() as u16);
        buffer.put_u8(src_port as u8);
        buffer.put_u8(remote_port as u8)
    }

    #[allow(dead_code)]
    pub(crate) fn craft_window_tail(pqc: &PostQuantumContainer, drill: &Drill, object_id: u32, target_cid: u64, group_id: u64, waves_in_window: RangeInclusive<u32>, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::GROUP_WINDOW_TAIL,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(*waves_in_window.start()),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::GROUP_WINDOW_TAIL_LEN);

        header.inscribe_into(&mut packet);
        packet.put_u32(*waves_in_window.end()); // + 4 bytes

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// This is always sent from Bob's side. This a retransmission request packet, and occurs when a timeout for a specific wave occured
    #[allow(unused_results)]
    pub(crate) fn craft_wave_do_retransmission(pqc: &PostQuantumContainer, object_id: u32, target_cid: u64, group_id: u64, wave_id: u32, vectors_missing: &Vec<PacketVector>, drill: &Drill, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_DO_RETRANSMISSION,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
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

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    // NOTE: context infos contain the object ID in most of the GROUP packets
    pub(crate) fn craft_wave_ack(pqc: &PostQuantumContainer, object_id: u32, target_cid: u64, group_id: u64, wave_id: u32, timestamp: i64, next_window: Option<RangeInclusive<u32>>, drill: &Drill) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::GROUP_PACKET,
            cmd_aux: packet_flags::cmd::aux::group::WAVE_ACK,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(object_id as u64),
            group: U64::new(group_id),
            wave_id: U32::new(wave_id),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        if let Some(next_window) = next_window {
            let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + 8);
            header.inscribe_into(&mut packet);
            packet.put_u32(*next_window.start());
            packet.put_u32(*next_window.end());
            drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
            packet
        } else {
            let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + 4);
            header.inscribe_into(&mut packet);
            packet.put_u32(drill.get_high()[0][0]);
            drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
            packet
        }
    }
}

pub(crate) mod do_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::{Drill, SecurityLevel};

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::proposed_credentials::ProposedCredentials;
    use nanoserde::SerBin;
    use crate::hdp::peer::peer_layer::MailboxTransfer;

    /// This goes from Alice to Bob. This returns a drill to ensure that it may stored for client/registration persistence
                ///
                /// /// This returns a drill in hopes that it gets stored in Alice's container
    #[allow(unused_results)]
    pub(crate) fn craft_stage0_packet<T: AsRef<[u8]>>(drill: &Drill, public_key: T, algorithm: u8, timestamp: i64) -> Option<BytesMut> {
        let public_key = public_key.as_ref();
        //log::info!("PUBLIC KEY(len: {}): {:?}", public_key.len(), public_key);
        // The values below are quasi
        //let context_info = drill.get_ultra()[0][0];
        let group = drill.get_ultra()[0][1];
        let sequence = drill.get_high()[0][2];

        const SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE0,
            algorithm,
            security_level: SECURITY_LEVEL.value(),
            context_info: U64::new(public_key.len() as u64),
            group: U64::new(group),
            wave_id: U32::new(sequence),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + public_key.len());
        header.inscribe_into(&mut packet);
        drill.encrypt_to_buf(public_key, &mut packet, 0, SECURITY_LEVEL).unwrap();

        Some(packet)
    }

    /// This goes from Bob to Alice. It contains the nonce which is to be applied OVER the post quantum key.
    /// Will return None if validation failed
    /// This returns a drill in hopes that it gets stored in Bob's container
    #[allow(unused_results)]
    pub(crate) fn craft_stage1_packet<T: AsRef<[u8]>>(drill: &Drill, algorithm: u8, ciphertext: T, timestamp: i64) -> ([u8; AES_GCM_NONCE_LEN_BYTES], BytesMut) {
        let nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = drill.get_random_aes_gcm_nonce();

        const SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;

        let encrypted_nonce = drill.encrypt_to_vec(&nonce as &[u8], 0, SECURITY_LEVEL).unwrap();
        // The values before are quasi
        let sec0 = drill.get_ultra()[0][3];
        let sec1 = drill.get_high()[0][4];

        let unencrypted_ciphertext = ciphertext.as_ref();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE1,
            algorithm,
            security_level: SECURITY_LEVEL.value(),
            context_info: U64::new(unencrypted_ciphertext.len() as u64),
            group: U64::new(sec0),
            wave_id: U32::new(sec1),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let expected_len = HDP_HEADER_BYTE_LEN + encrypted_nonce.len() + unencrypted_ciphertext.len();

        let mut packet = BytesMut::with_capacity(expected_len);
        header.inscribe_into(&mut packet);
        packet.put(encrypted_nonce.as_ref());
        drill.encrypt_to_buf(unencrypted_ciphertext, &mut packet, 0, SECURITY_LEVEL).unwrap();

        debug_assert_eq!(expected_len, packet.len());

        (nonce, packet)
    }

    /// Alice receives the nonce from Bob. She must now inscribe her username/password
    #[allow(unused_results)]
    pub(crate) fn craft_stage2_packet(proposed_credentials: ProposedCredentials, pqc: &PostQuantumContainer, drill: &Drill, timestamp: i64) -> BytesMut {
        let (username, password) = proposed_credentials.decompose_credentials();

        let encrypted_len = hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(username.len() + username.len());
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + encrypted_len);

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_connect::STAGE2,
            algorithm: 0,
            security_level: 0,
            // place username len here to allow the other end to know where to split the payload
            context_info: U64::new(username.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        header.inscribe_into(&mut packet);
        packet.put(username);
        packet.put(password);

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final_status_packet<T: AsRef<[u8]>>(success: bool, mailbox_items_opt: Option<MailboxTransfer>, message: T, peers: Vec<u64>, drill: &Drill, pqc: &PostQuantumContainer, timestamp: i64) -> BytesMut {
        let payload = message.as_ref();
        let (mailbox_transfer_len ,mailbox_items) = if let Some(mailbox_items) = mailbox_items_opt {
            let serialized = SerBin::serialize_bin(&mailbox_items);
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
            security_level: 0,
            context_info: U64::new(payload.len() as u64),
            group: U64::new(mailbox_transfer_len as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
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

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }
}

pub(crate) mod keep_alive {
    use bytes::BytesMut;
    use zerocopy::{I64, U32, U64};

    use hyxe_crypt::prelude::Drill;

    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use ez_pqcrypto::PostQuantumContainer;
    use crate::constants::HDP_HEADER_BYTE_LEN;

    pub(crate) fn craft_keep_alive_packet(drill: &Drill, pqc: &PostQuantumContainer, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::KEEP_ALIVE,
            cmd_aux: 0,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = header.into_packet_mut();
        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod do_register {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use crate::proposed_credentials::ProposedCredentials;

    /// At this stage, the drill does not exist. There is no verifying such packets. The payload contains Alice's public key.
                ///
                /// Since this is sent over TCP, the size of the packet can be up to ~64k bytes
                ///
                /// We also use the NID in place of the CID because the CID only exists AFTER registration completes
    pub(crate) fn craft_stage0<T: AsRef<[u8]>>(algorithm: u8, timestamp: i64, local_nid: u64, alice_public_key: T, potential_cids_alice: &Vec<u64>) -> BytesMut {
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

        let public_key = alice_public_key.as_ref();
        let pk_len = public_key.len();
        let mut packet = BytesMut::with_capacity(pk_len + HDP_HEADER_BYTE_LEN + potential_cids_alice.len() * 8);

        packet.put(header.into_packet());
        potential_cids_alice.iter().for_each(|val| packet.put_u64(*val));
        packet.put(public_key);

        packet
    }

    /// Bob crafts a packet with the ciphertext
    pub(crate) fn craft_stage1<T: AsRef<[u8]>>(algorithm: u8, timestamp: i64, local_nid: u64, ciphertext: T, reserved_true_cid: u64) -> BytesMut {
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

        let ciphertext = ciphertext.as_ref();
        let cipher_len = ciphertext.len();
        let mut packet = BytesMut::with_capacity(cipher_len + HDP_HEADER_BYTE_LEN);

        packet.put(header.into_packet());
        packet.put(ciphertext);

        packet
    }

    /// Alice sends this. It is expected that the nonce is generated
    pub(crate) fn craft_stage2(nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], algorithm: u8, local_nid: u64, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE2,
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

        let mut packet = BytesMut::with_capacity(packet_sizes::DO_REGISTER_STAGE2_PACKET);
        header.inscribe_into(&mut packet);
        packet.put(&*nonce as &[u8]);

        packet
    }

    /// Bob sends this. It tells Alice that it is ready to receive the proposed credentials
    pub(crate) fn craft_stage3(algorithm: u8, local_nid: u64, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE3,
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

        header.into_packet()
    }

    /// Alice sends this. The stage 3 packet contains the encrypted username, password, and full name of the registering client
    #[allow(unused_results)]
    pub(crate) fn craft_stage4(nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], algorithm: u8, local_nid: u64, timestamp: i64, post_quantum: &PostQuantumContainer, proposed_credentials: &ProposedCredentials) -> BytesMut {
        let (username_len, password_len, full_name_len) = proposed_credentials.get_item_lengths();
        let ciphertext_payload_len = proposed_credentials.get_expected_ciphertext_length();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::STAGE4,
            algorithm,
            security_level: 0,
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
        proposed_credentials.inscribe_into(&mut packet, nonce, post_quantum);
        packet
    }

    /// `success_message`: This is NOT encrypted in this closure. Make sure to encrypt it beforehand if necessary
    pub(crate) fn craft_success<T: AsRef<[u8]>>(cnac: &ClientNetworkAccount, algorithm: u8, local_nid: u64, timestamp: i64, post_quantum: &PostQuantumContainer, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], success_message: T) -> BytesMut {
        let serialized_bytes: Vec<u8> = cnac.serialize_toolset_to_vec().unwrap();
        let success_message = success_message.as_ref();
        let success_message_len = success_message.len();

        let expected_ciphertext_payload_len = hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(serialized_bytes.len());
        log::info!("Serialized Toolset. Plaintext Bytes: {} | Ciphertext len: {}", serialized_bytes.len(), expected_ciphertext_payload_len);

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_REGISTER,
            cmd_aux: packet_flags::cmd::aux::do_register::SUCCESS,
            algorithm,
            security_level: 0,
            context_info: U64::new(expected_ciphertext_payload_len as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(local_nid),
            drill_version: U32::new(0),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };


        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + expected_ciphertext_payload_len + success_message_len);
        header.inscribe_into(&mut packet);

        let cnac_ciphertext = post_quantum.encrypt(&serialized_bytes, nonce).unwrap();
        packet.put(cnac_ciphertext.as_ref());
        packet.put(success_message);

        packet
    }

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
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::{BYTES_IN_LOW, E_OF_X_START_INDEX};
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill::SecurityLevel;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use crate::hdp::hdp_server::Ticket;
    use crate::hdp::state_container::VirtualConnectionType;

    /// The drill used should be an unused one. (generate a new drill)
    #[allow(unused_results)]
    pub(crate) fn craft_stage0(virtual_connection_type: VirtualConnectionType, drill: &Drill, ticket: Ticket, timestamp: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[0][0];
        let sec1 = drill.get_high()[0][1];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE0,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(sec0),
            wave_id: U32::new(sec1),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let virtual_connection_bytes = virtual_connection_type.serialize();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + virtual_connection_bytes.len());
        header.inscribe_into(&mut packet);
        drill.encrypt_to_buf(virtual_connection_bytes.as_slice(), &mut packet, 0, SecurityLevel::LOW).unwrap();
        packet
    }

    /// Bob sends Alice an encrypted nonce
    #[allow(unused_results)]
    pub(crate) fn craft_stage1(drill: &Drill, ticket: Ticket, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], timestamp: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[0][2];
        let sec1 = drill.get_high()[0][3];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE1,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(sec0),
            wave_id: U32::new(sec1),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::disconnect::STAGE1);
        header.inscribe_into(&mut packet);
        drill.encrypt_to_buf(nonce as &[u8], &mut packet, 0, SecurityLevel::LOW).unwrap();
        //log::info!("Len of output stage1 packet: {}", packet.len());
        packet
    }

    pub(crate) fn craft_stage2(drill: &Drill, ticket: Ticket, post_quantum: &PostQuantumContainer, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], timestamp: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[0][4];
        let sec1 = drill.get_high()[0][5];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux: packet_flags::cmd::aux::do_disconnect::STAGE2,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(sec0),
            wave_id: U32::new(sec1),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::disconnect::STAGE2);
        //pub fn aes_gcm_encrypt_custom_nonce<T: AsRef<[u8]>>(&self, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        header.inscribe_into(&mut packet);
        let mut payload = Vec::with_capacity(BYTES_IN_LOW);
        let low_subdrill = drill.get_low();
        let port_range = drill.get_multiport_width();
        for x in 0..E_OF_X_START_INDEX {
            for y in 0..port_range {
                payload.push(low_subdrill[x][y]);
            }
        }

        let encrypted_payload = drill.aes_gcm_encrypt_custom_nonce(nonce, post_quantum, &payload).unwrap();
        packet.put_slice(&encrypted_payload);
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final<T: AsRef<[u8]>>(success: bool, drill: &Drill, ticket: Ticket, timestamp: i64, message: T) -> BytesMut {
        let sec0 = drill.get_ultra()[0][6];
        let sec1 = drill.get_high()[0][7];

        let message = message.as_ref();

        let cmd_aux = if success {
            packet_flags::cmd::aux::do_disconnect::SUCCESS
        } else {
            packet_flags::cmd::aux::do_disconnect::FAILURE
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DISCONNECT,
            cmd_aux,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(sec0),
            wave_id: U32::new(sec1),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + message.len());
        header.inscribe_into(&mut packet);
        drill.encrypt_to_buf(message, &mut packet, 0, SecurityLevel::LOW).unwrap();

        packet
    }
}

pub(crate) mod do_drill_update {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill_update::DrillUpdateObject;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};

    #[allow(unused_results)]
    pub(crate) fn craft_stage0(drill: &Drill, pqc: &PostQuantumContainer, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + AES_GCM_NONCE_LEN_BYTES);
        header.inscribe_into(&mut packet);
        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_stage1(drill: &Drill, pqc: &PostQuantumContainer, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE1,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE1);
        header.inscribe_into(&mut packet);
        // encrypt the nonce into the packet
        packet.put(nonce as &[u8]);

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_stage2(drill: &Drill, drill_update_object: DrillUpdateObject, post_quantum: &PostQuantumContainer, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], timestamp: i64) -> Option<BytesMut> {
        if let Ok(ref serialized_dou) = drill_update_object.serialize_to_vector() {
            let encrypted_dou = drill.aes_gcm_encrypt_custom_nonce(nonce, post_quantum, &serialized_dou).unwrap();
            let header = HdpHeader {
                cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
                cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE2,
                algorithm: 0,
                security_level: 0,
                context_info: U64::new(0),
                group: U64::new(0),
                wave_id: U32::new(0),
                session_cid: U64::new(drill.get_cid()),
                drill_version: U32::new(drill.get_version()),
                timestamp: I64::new(timestamp),
                target_cid: U64::new(0)
            };

            let len = HDP_HEADER_BYTE_LEN + encrypted_dou.len();

            let mut packet = BytesMut::with_capacity(len);
            header.inscribe_into(&mut packet);
            // encrypt the nonce into the packet
            packet.put_slice(&encrypted_dou);
            drill.protect_packet(post_quantum, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
            Some(packet)
        } else {
            log::error!("Error serializing the drill update object");
            None
        }
    }

    /// To verify the validity of the new drill, thise node encrypts the earlier-obtained nonce.
    /// The other node has the new drill, and as such, does not need to receive the DOU
    pub(crate) fn craft_stage3(old_drill: &Drill, new_drill: &Drill, stage1_nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE3,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(old_drill.get_cid()),
            drill_version: U32::new(old_drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_drill_update::STAGE3);
        header.inscribe_into(&mut packet);

        let encrypted_nonce = new_drill.aes_gcm_encrypt_custom_nonce(stage1_nonce, post_quantum, stage1_nonce).unwrap();
        packet.put_slice(&encrypted_nonce);
        old_drill.protect_packet(post_quantum, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final(old_drill: &Drill, pqc: &PostQuantumContainer, success: bool, timestamp: i64) -> BytesMut {
        let cmd_aux = if success {
            packet_flags::cmd::aux::do_drill_update::SUCCESS
        } else {
            packet_flags::cmd::aux::do_drill_update::FAILURE
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DRILL_UPDATE,
            cmd_aux,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(old_drill.get_cid()),
            drill_version: U32::new(old_drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        old_drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod do_deregister {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64};

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::drill::Drill;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use crate::hdp::state_container::VirtualConnectionType;

    #[allow(unused_results)]
    pub(crate) fn craft_stage0(drill: &Drill, pqc: &PostQuantumContainer, timestamp: i64, virtual_connection_type: VirtualConnectionType) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux: packet_flags::cmd::aux::do_drill_update::STAGE0,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let virtual_conn_bytes = virtual_connection_type.serialize();

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + virtual_conn_bytes.len());
        header.inscribe_into(&mut packet);
        packet.put(virtual_conn_bytes.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    #[allow(unused_results)]
    pub(crate) fn craft_final(drill: &Drill, pqc: &PostQuantumContainer, success: bool, timestamp: i64) -> BytesMut {
        let cmd_aux = if success {
            packet_flags::cmd::aux::do_deregister::SUCCESS
        } else {
            packet_flags::cmd::aux::do_deregister::FAILURE
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_DEREGISTER,
            cmd_aux,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }
}

pub(crate) mod pre_connect {
    use bytes::{BufMut, BytesMut};
    use zerocopy::{I64, U32, U64, LayoutVerified};

    use hyxe_crypt::drill::Drill;
    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_nat::udp_traversal::NatTraversalMethod;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use crate::hdp::hdp_packet::packet_flags::payload_identifiers;
    use ez_pqcrypto::PostQuantumContainer;
    use crate::hdp::hdp_packet_processor::includes::SocketAddr;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;

    pub(crate) fn craft_syn(static_aux_drill: &Drill, old_pqc: &PostQuantumContainer, tcp_only: bool, timestamp: i64) -> BytesMut {
        let tcp_only = if tcp_only {
            1
        } else {
            0
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(tcp_only),
            group: U64::new(crate::constants::BUILD_VERSION as u64),
            wave_id: U32::new(0),
            session_cid: U64::new(static_aux_drill.get_cid()),
            drill_version: U32::new(static_aux_drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet  = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        header.inscribe_into(&mut packet);
        static_aux_drill.protect_packet(old_pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        packet
    }

    /// Must synchronize drills using the static auxiliar drill (which supplies the nonce) and the pqc
    /// TODO: Limit the use of this to a certain frequency. An attacker could flood the node with false
    /// PRE_CONNECT packets. Could limit the number of recoveries by IP, or, node-wide
    pub(crate) fn craft_syn_ack<T: AsRef<[u8]>>(static_auxilliary_drill: &Drill, pqc: &PostQuantumContainer, dou_bytes: T, timestamp: i64, peer_external_addr: SocketAddr) -> BytesMut {
        let external_addr_bytes = peer_external_addr.to_string();
        let external_addr_bytes = external_addr_bytes.as_bytes();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::SYN_ACK,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(external_addr_bytes.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(static_auxilliary_drill.get_cid()),
            drill_version: U32::new(static_auxilliary_drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let dou_bytes = dou_bytes.as_ref();

        let ciphertext_len = hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(dou_bytes.len());
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + ciphertext_len);
        header.inscribe_into(&mut packet);
        packet.put(external_addr_bytes);
        packet.put(dou_bytes);
        static_auxilliary_drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
        //let _ = static_auxilliary_drill.aes_gcm_encrypt_into(0, pqc, dou_bytes, &mut packet).unwrap();
        packet
    }

    // This gets sent from Alice to Bob
    pub(crate) fn craft_stage0(drill: &Drill, pqc: &PostQuantumContainer, local_node_type: HyperNodeType, local_wave_ports: &Vec<u16>, timestamp: i64, peer_external_ip: SocketAddr) -> BytesMut {
        let external_ip_bytes = peer_external_ip.to_string();
        let external_ip_bytes = external_ip_bytes.as_bytes();

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE0,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(external_ip_bytes.len() as u64),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
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

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_stage1(drill: &Drill, pqc: &PostQuantumContainer, local_node_type: HyperNodeType, local_wave_ports: &Vec<u16>, initial_nat_traversal_method: NatTraversalMethod, timestamp: i64, sync_time: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE1,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
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

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_stage_try_next(drill: &Drill, next_nat_traversal_method: NatTraversalMethod, timestamp: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[1][6];
        let sec1 = drill.get_ultra()[1][7];
        let sec2 = drill.get_high()[1][8];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(sec0),
            group: U64::new(sec1),
            wave_id: U32::new(sec2),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_preconnect::STAGE_TRY_NEXT);
        header.inscribe_into(&mut packet);
        packet.put_u8(next_nat_traversal_method.into_byte());

        packet
    }

    pub(crate) fn craft_stage_try_next_ack(drill: &Drill, timestamp: i64, sync_time: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[1][9];
        let sec1 = drill.get_ultra()[1][10];
        let sec2 = drill.get_high()[1][11];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::STAGE_TRY_NEXT_ACK,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(sec0),
            group: U64::new(sec1),
            wave_id: U32::new(sec2),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(packet_sizes::do_preconnect::STAGE_TRY_NEXT_ACK);
        header.inscribe_into(&mut packet);
        packet.put_i64(sync_time);

        packet
    }

    /// If `tcp_only` is set to true, then the primary stream will be used for sharing information instead of the wave ports
    pub(crate) fn craft_stage_final(drill: &Drill, success: bool, tcp_only: bool, timestamp: i64, upnp_ports: Option<Vec<u16>>) -> BytesMut {
        let sec0 = drill.get_ultra()[2][0];
        let sec1 = drill.get_ultra()[2][1];
        let sec2 = drill.get_high()[2][2];

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
            security_level: 0,
            context_info: U64::new(sec0),
            group: U64::new(sec1),
            wave_id: U32::new(sec2),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        if let Some(upnp_ports) = upnp_ports {
            let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + (2 * upnp_ports.len()));
            header.inscribe_into(&mut packet);
            for upnp_port in upnp_ports {
                packet.put_u16(upnp_port);
            }

            packet
        } else {
            header.into_packet()
        }
    }

    pub(crate) fn craft_begin_connect(drill: &Drill, timestamp: i64) -> BytesMut {
        let sec0 = drill.get_ultra()[2][3];
        let sec1 = drill.get_ultra()[2][4];
        let sec2 = drill.get_high()[2][5];

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::BEGIN_CONNECT,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(sec0),
            group: U64::new(sec1),
            wave_id: U32::new(sec2),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        header.into_packet()
    }

    pub(crate) fn craft_server_finished_hole_punch(drill: &Drill, pqc: &PostQuantumContainer, success: bool, timestamp: i64) -> BytesMut {
        let algorithm = if success {
            1
        } else {
            0
        };

        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::DO_PRE_CONNECT,
            cmd_aux: packet_flags::cmd::aux::do_preconnect::RECEIVER_FINISHED_HOLE_PUNCH,
            algorithm,
            security_level: 0,
            context_info: U64::new(0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(0)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + 1);
        header.inscribe_into(&mut packet);
        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();
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
    use hyxe_crypt::drill::Drill;
    use bytes::{BytesMut, BufMut};
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags};
    use zerocopy::{U64, U32, I64};
    use crate::hdp::hdp_server::Ticket;
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
    use nanoserde::SerBin;
    use crate::hdp::peer::peer_layer::ChannelPacket;
    use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;

    pub(crate) const ENDPOINT_ENCRYPTION_OFF: u64 = 0;
    /*

     */
    /// Peer signals, unlike channels, DO NOT get a target_cid because they require the central server's participation to increase security between the
    /// two nodes
    pub(crate) fn craft_peer_signal<T: SerBin>(pqc: &PostQuantumContainer, drill: &Drill, peer_command: T, ticket: Ticket, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(ENDPOINT_ENCRYPTION_OFF)
        };

        let peer_cmd_serialized = peer_command.serialize_bin();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + peer_cmd_serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(peer_cmd_serialized.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_peer_signal_endpoint<T: SerBin>(pqc: &PostQuantumContainer, drill: &Drill, peer_command: T, ticket: Ticket, timestamp: i64, target_cid: u64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::SIGNAL,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let peer_cmd_serialized = peer_command.serialize_bin();
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + peer_cmd_serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(peer_cmd_serialized.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// Channel packets ALWAYS get rerouted, and hence NEED a target_cid
    #[allow(dead_code)]
    pub(crate) fn craft_channel_packet(pqc: &PostQuantumContainer, drill: &Drill, payload: ChannelPacket, ticket: Ticket, proxy_target_cid: u64, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::CHANNEL,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid)
        };
        let serialized: Vec<u8> = payload.serialize_bin();

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(serialized.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    /// Group message packets, unlike channel packets, do not always get rerouted
    #[allow(dead_code)]
    pub(crate) fn craft_group_message_packet(pqc: &PostQuantumContainer, drill: &Drill, payload: &GroupBroadcast, ticket: Ticket, proxy_target_cid: u64, timestamp: i64) -> BytesMut {
        let header = HdpHeader {
            cmd_primary: packet_flags::cmd::primary::PEER_CMD,
            cmd_aux: packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST,
            algorithm: 0,
            security_level: 0,
            context_info: U64::new(ticket.0),
            group: U64::new(0),
            wave_id: U32::new(0),
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(proxy_target_cid)
        };
        let serialized: Vec<u8> = SerBin::serialize_bin(payload);

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(serialized.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

}

pub(crate) mod file {
    use crate::hdp::hdp_packet_processor::includes::{Drill, PostQuantumContainer, SecurityLevel, HdpHeader, packet_flags};
    use crate::hdp::hdp_server::Ticket;
    use crate::hdp::state_container::VirtualTargetType;
    use crate::hdp::file_transfer::VirtualFileMetadata;
    use zerocopy::{U64, U32, I64};
    use bytes::{BytesMut, BufMut};
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;

    pub(crate) fn craft_file_header_packet(group_start: u64, drill: &Drill, pqc: &PostQuantumContainer, ticket: Ticket, security_level: SecurityLevel, virtual_target: VirtualTargetType, file_metadata: VirtualFileMetadata, timestamp: i64) -> BytesMut {
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
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(virtual_target.get_target_cid())
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_vt.len() + metadata_serialized.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        //processor.group_config.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());
        packet.put(metadata_serialized.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }

    pub(crate) fn craft_file_header_ack_packet(success: bool, object_id: u32, target_cid: u64, drill: &Drill, pqc: &PostQuantumContainer, ticket: Ticket, security_level: SecurityLevel, virtual_target: VirtualTargetType, timestamp: i64) -> BytesMut {
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
            session_cid: U64::new(drill.get_cid()),
            drill_version: U32::new(drill.get_version()),
            timestamp: I64::new(timestamp),
            target_cid: U64::new(target_cid)
        };

        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + serialized_vt.len() + AES_GCM_GHASH_OVERHEAD);
        header.inscribe_into(&mut packet);
        packet.put(serialized_vt.as_slice());

        drill.protect_packet(pqc, HDP_HEADER_BYTE_LEN, &mut packet).unwrap();

        packet
    }
}

pub(crate) mod hole_punch {
    use hyxe_crypt::drill::Drill;
    use ez_pqcrypto::PostQuantumContainer;
    use bytes::{BytesMut, BufMut};
    use std::iter::FromIterator;

    pub fn generate_packet(drill: &Drill, pqc: &PostQuantumContainer, local_port: u16) -> BytesMut {
        let mut packet = BytesMut::new();
        packet.put_u16(local_port);
        drill.protect_packet(pqc,0, &mut packet).unwrap();

        packet
    }

    pub fn decrypt_packet(drill: &Drill, pqc: &PostQuantumContainer, packet: &[u8]) -> Option<BytesMut> {
        let mut packet = BytesMut::from_iter(packet);
        drill.validate_packet_in_place_split(pqc, &[], &mut packet).ok()?;
        Some(packet)
    }
}