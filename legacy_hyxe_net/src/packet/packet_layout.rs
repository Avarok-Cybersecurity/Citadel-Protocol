//! The [PacketLayout] module is crucial to the construction of sendable virtual waveforms. This DOES NOT package the pro-headers;
//! this only packages payloads of data into properly formatted HyxePackets. TODO: Implement the Modulator/Demodulator (Modem)
//! TODO: Implement asynchronous versions of packet layout constructors, as well as parallel (if possible?)
use num::Integer;
use zerocopy::{AsBytes, ByteSlice};

use hyxe_crypt::drill::{PORT_RANGE, SecurityLevel};
use hyxe_crypt::misc::CryptError;
use hyxe_crypt::prelude::{DrillType, Drill};
use hyxe_netdata::packet::{PACKET_HEADER_BYTE_COUNT, ProcessedPacketHeader};

use crate::connection::stream_wrappers::old::OutboundItem;
use crate::packet::MAX_PAYLOAD_SIZE;
use crate::packet::misc::ConnectError;
use std::io::Read;

//cid_original: u64, cid_needed_to_undrill: u64, drill_version_needed_to_undrill: u32, security_level_drilled: u8,
//                     timestamp: i64,
//                     current_packet_hop_state: u8, next_hop_state: u8, endpoint_destination_type: u8,
//                     command_flag: u8, expects_response: u8,
//                     oid_eid: u64, wid: u64, pid: u64,
//                     route_dest_nid: u64, route_dest_cid: u64, network_map_version: u32
/// This contains the data that is necessary for a end-to-end transmission. This does NOT
/// contain the WID and PID. The oid_eid should really just be a counter that starts off
/// at zero, and increments upwards. There is no real algorithm for the oid_eid, since
/// this value is really just for differentiating between different transmissions of objects
pub struct BaseHeaderConfig {
    cid_original: u64,
    nid_original: u64,
    cid_needed_to_undrill: u64,
    drill_version_needed_to_undrill: u32,
    security_level_drilled: u8,
    timestamp: i32,
    current_packet_hop_state: u8,
    next_hop_state: u8,
    endpoint_destination_type: u8,
    hops_remaining: u8,
    command_flag: u8,
    packet_type: u8,
    expects_response: u8,
    oid_eid: u64,
    route_dest_nid: u64,
    route_dest_cid: u64,
    network_map_version: u32,
}

/// The number of packets per wave
#[deprecated]
pub const MAX_PACKETS_PER_WAVE: usize = PORT_RANGE;

/// This is the structure passed directly to the outbound sender.
///
/// This is for data that only needs 1 packet. The amplitudal sigma is zero
pub struct PacketLayout0D {
    /// The packet's bytes. Equivalent to the [UnpreparedOutboundPacket], but contained within this 0D layout that also
    /// contains the necessary information to send information outbound
    pub data: OutboundItem,
    /// The local port form which the data exits from, coupled with the entry port of the adjacent network node
    pub port_mapping: (u16, u16)
}

/// This is the structure passed directly to the outbound sender.
///
/// This is for data that only needs multiple packets, but less than
/// MAX_PACKETS_PER_WAVE number of packets.
pub struct PacketLayout1D {
    /// An array of 0-D packets
    pub data: Vec<PacketLayout0D>
}

/// This is the structure passed directly to the outbound sender.
///
/// This is for data that only needs 1 packet. The amplitudal sigma is zero
pub struct PacketLayout2D {
    /// An array of 1-D waveforms
    pub data: Vec<Vec<PacketLayout0D>>
}

/// This creates the valid header and payload combo, however, it only needs valid port information and an IP before it can be sent to
/// the underlying network stream.
///
/// This panics if the payload is larger than [MAX_PAYLOAD_SIZE]
pub(crate) fn create_packet_with_cfg<T: AsRef<[u8]>>(payload: &T, cfg: &BaseHeaderConfig, pid: f64, wid: f64) -> OutboundItem {
    let payload = payload.as_ref();

    assert!(payload.len() > MAX_PAYLOAD_SIZE, "Oversized payloads not accepted");

    let header = ProcessedPacketHeader::craft(cfg.cid_original,
                                              cfg.nid_original,
                                              cfg.cid_needed_to_undrill,
                                              cfg.drill_version_needed_to_undrill,
                                              cfg.security_level_drilled,
                                              cfg.timestamp,
                                              cfg.current_packet_hop_state,
                                              cfg.next_hop_state,
                                              cfg.endpoint_destination_type,
                                              cfg.hops_remaining,
                                              cfg.command_flag,
                                              cfg.packet_type,
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

/// Sometimes, a series of waves must be created, but no encryption is necessary (e.g., during registration phase).
/// Data is chunked, and then this uses zero for the WID and the sequential order for the PID
pub(crate) fn generate_raw_layout_sequential<T: AsRef<[u8]>>(data: &T, cfg: &BaseHeaderConfig, local_port: u16, remote_port: u16) -> Vec<PacketLayout0D> {
    let data = data.as_ref();
    let bytes_len = data.len();

    if bytes_len > MAX_PAYLOAD_SIZE {
        let num_waves = bytes_len.div_ceil(&MAX_PAYLOAD_SIZE);
        let mut output = Vec::with_capacity(num_waves);
        for (idx, bytes) in data.chunks(MAX_PAYLOAD_SIZE).enumerate() {
            (&mut output).push(PacketLayout0D { data: create_packet_with_cfg(bytes, cfg, idx as f64, 0.0), port_mapping: (local_port, remote_port) })
        }

        output
    } else {
        let mut output = Vec::with_capacity(1);
        output.push(PacketLayout0D { data: create_packet_with_cfg(data, cfg, 0.0, 0.0), port_mapping: (local_port, remote_port) });
        output
    }
}

/// `offset` is the starting point of the `port_mapping` vector. This is only really useful for 2D PacketLayout's
/// `count` is the number of pairs from the offset you wish to use for computing the amplitudal sigma
/// `port_mapping` obtained by the drill
///
/// Panics if offset + count is larger than the vector length
fn calculate_amplitudal_sigma(offset: usize, count: usize, port_mapping: &Vec<(u16, u16)>) -> usize {
    assert!(offset + count > port_mapping.len());
    let mut sigma = 0;
    for idx in offset..(offset + count) {
        let val = port_mapping[idx];
        sigma += val.1 - val.0;
    }

    sigma as usize
}

/// The layout's constraints change semi-actively as per dependence upon the drill
pub fn determine_layout<Drx: DrillType>(data_len: usize, drill: &Drill<Drx>, security_level: SecurityLevel) -> u8 {
    let encrypted_bytes_len = security_level.get_expected_encrypted_len(data_len);
    let packets_needed = encrypted_bytes_len.div_ceil(&MAX_PAYLOAD_SIZE);
    let max_packets_per_wave = drill.get_port_mapping().len(); // the max size/(number of packets) of each wave is equal to the length of the port_mappings vector

    if packets_needed == 1 {
        0
    } else if packets_needed > 1 && packets_needed < max_packets_per_wave {
        1
    } else {
        2
    }
}

impl PacketLayout0D {
    /// Creates a new layout. This automatically splits the data into chunks, encrypts each chunk, determines the number of waves, and constructs the packet headers
    /// This is for "small-sized" data (e.g., signals)
    ///
    /// Panics if the input's encrypted length is larger than the maximum size of a single packet's payload
    pub fn new<'a, Drx: DrillType + 'a, B: ByteSlice + 'a>(unencrypted_bytes: &B, drill: &Drill<Drx>, security_level: SecurityLevel, cfg: &BaseHeaderConfig, wid: f64, pid: f64, port_local: u16, port_remote: u16) -> Result<Self, CryptError<String>> {
        assert!(security_level.get_expected_encrypted_len(unencrypted_bytes.len()) < MAX_PAYLOAD_SIZE);

        match drill.encrypt_to_vec(unencrypted_bytes.as_bytes(), 0, security_level) {
            Ok(encrypted_bytes) => {
                Ok(PacketLayout0D { data: create_packet_with_cfg(&encrypted_bytes, cfg, pid, wid), port_mapping: (port_local, port_remote) })
            }

            Err(err) => {
                Err(err)
            }
        }
    }

    /// Calculates the amplitudal sigma given an input of data
    fn calculate_amplitudal_sigma(_: &Vec<(u16, u16)>) -> usize {
        unimplemented!()
    }
}

impl PacketLayout1D {
    /// Packet layout 1D. This is for "medium-sized" data. The PID is nonzero, whereas the WID is zero since there is only one wave
    pub fn new<'a, Drx: DrillType + 'a, B: ByteSlice + 'a>(unencrypted_bytes: &B, drill: &Drill<Drx>, security_level: SecurityLevel, cfg: &BaseHeaderConfig, port_start: u16) -> Result<Self, CryptError<String>> {
        let encrypted_bytes_len = security_level.get_expected_encrypted_len(unencrypted_bytes.len());
        let packets_needed = encrypted_bytes_len.div_ceil(&MAX_PAYLOAD_SIZE);
        let port_mapping = drill.get_port_mapping();
        let max_packets_per_wave = port_mapping.len(); // the max size of each wave is equal to the length of the port_mappings vector
        assert!(packets_needed > 1 && packets_needed < max_packets_per_wave); // if only 1 packet is needed, call instead PacketLayout0D::new(...)



        let amplitudal_sigma = calculate_amplitudal_sigma(0, packets_needed, port_mapping);

        let mut data = Vec::with_capacity(packets_needed);
        let bytes = unencrypted_bytes.as_bytes();
        for packet_idx in 0..packets_needed {
            let pid = drill.get_pid(packet_idx);
            let start_idx = packet_idx*MAX_PAYLOAD_SIZE;
            let end_idx = {
                if start_idx + MAX_PAYLOAD_SIZE < encrypted_bytes_len {
                    start_idx + MAX_PAYLOAD_SIZE
                } else {
                    encrypted_bytes_len
                }
            };
            match drill.encrypt_to_vec(&bytes[start_idx..end_idx], amplitudal_sigma, security_level) {
                Ok(encrypted_bytes) => {
                    let (port_local, port_remote) = port_mapping[packet_idx];
                    data.push(PacketLayout0D { data: create_packet_with_cfg(&encrypted_bytes, cfg, pid, 0 as f64), port_mapping: (port_local + port_start, port_remote + port_start) });
                },
                Err(err) => return Err(err)
            }
        }

        Ok(Self {data})
    }
}

impl PacketLayout2D {
    /// Packet layout 2D. This is for "large-sized" and effectively infinitely-long data. While each individual 1D wave has a variable upper bound, this is not the case
    /// for 2D packet layouts: They can be comprised with an arbitrarily numerous quantity of 1D waves
    pub fn new<'a, Drx: DrillType + 'a, B: ByteSlice + 'a>(unencrypted_bytes: &B, drill: &Drill<Drx>, security_level: SecurityLevel, cfg: &BaseHeaderConfig, port_start: u16) -> Result<Self, CryptError<String>> {
        let encrypted_bytes_len = security_level.get_expected_encrypted_len(unencrypted_bytes.len());
        let packets_needed = encrypted_bytes_len.div_ceil(&MAX_PAYLOAD_SIZE);
        let port_mapping = drill.get_port_mapping();
        let max_packets_per_wave = port_mapping.len(); // the max size of each wave is equal to the length of the port_mappings vector
        debug_assert!(packets_needed >= max_packets_per_wave); // This assertion is only for the debug stage to help ensure the proper logic is created

        let waves_needed = packets_needed.div_ceil(&max_packets_per_wave);
        let packets_in_last_wave = packets_needed % max_packets_per_wave; // the remainder is what we're after here

        let mut data = Vec::with_capacity(waves_needed);
        let bytes = unencrypted_bytes.as_bytes();

        for wave_idx in 0..waves_needed {
            let (packets_in_wave, amplitudal_sigma) = {
                if wave_idx != waves_needed - 1 {
                    (max_packets_per_wave, calculate_amplitudal_sigma(0, port_mapping.len(), port_mapping))
                } else {
                    (packets_in_last_wave, calculate_amplitudal_sigma(0, packets_in_last_wave, port_mapping))
                }
            };

            let mut wave_data = Vec::with_capacity(packets_in_wave);
            let wid = drill.get_wid(wave_idx);

            for packet_idx in 0..packets_in_wave {
                let pid = drill.get_pid(packet_idx);

                let start_idx = packet_idx * MAX_PAYLOAD_SIZE;
                let end_idx = {
                    if start_idx + MAX_PAYLOAD_SIZE < encrypted_bytes_len {
                        start_idx + MAX_PAYLOAD_SIZE
                    } else {
                        encrypted_bytes_len
                    }
                };

                match drill.encrypt_to_vec(&bytes[start_idx..end_idx], amplitudal_sigma, security_level) {
                    Ok(encrypted_bytes) => {
                        let (port_local, port_remote) = port_mapping[packet_idx];
                        wave_data.push(PacketLayout0D { data: create_packet_with_cfg(&encrypted_bytes, cfg, pid, wid), port_mapping: (port_local + port_start, port_remote + port_start) })
                    },

                    Err(err) => return Err(err)
                }
            }
            data.push(wave_data);
        }

        Ok(Self { data })
    }
}

/// This should be determined by pretty the data within the [Drill] file
pub struct PortMapping {
    outbound_ports: Vec<u16>,
    remote_recv_ports: Vec<u16>,
}