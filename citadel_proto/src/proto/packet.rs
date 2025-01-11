//! # Citadel Protocol Packet Structure
//!
//! This module defines the core packet structure and handling for the Citadel Protocol.
//! It implements the Hypernode Data Protocol (HDP) packet format, which provides secure
//! and efficient data transmission between nodes.
//!
//! ## Features
//!
//! * Packet header definition and handling
//! * Command type classification (primary and auxiliary)
//! * Packet size management
//! * Buffer trait implementation for different types
//! * Zero-copy header parsing
//! * Socket address tracking
//! * Packet decomposition and composition
//!
//! ## Important Notes
//!
//! * Headers are fixed-size and aligned
//! * Commands are hierarchically organized
//! * Supports both BytesMut and Vec<u8> buffers
//! * Implements zero-copy parsing for efficiency
//! * Maintains packet integrity checks
//!
//! ## Related Components
//!
//! * `packet_processor`: Processes different packet types
//! * `packet_crafter`: Creates protocol packets
//! * `validation`: Validates packet structure
//! * `state_container`: Manages packet state
//! * `session`: Handles packet sessions
//!

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::proto::misc::dual_cell::DualCell;
use byteorder::WriteBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use citadel_io as rand;
use citadel_io::RngCore;
use citadel_types::crypto::HeaderObfuscatorSettings;
use rand::Rng;
use rand::ThreadRng;
use sha3::Digest;
use std::net::SocketAddr;
use std::num::NonZero;
use zerocopy::byteorder::big_endian::{I64, U128, U32, U64};
use zerocopy::BigEndian;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref, Unaligned};

pub(crate) mod packet_flags {
    pub(crate) mod cmd {
        pub(crate) mod primary {
            pub(crate) const KEEP_ALIVE: u8 = 0;
            /// To save bandwidth, acks are only sent for groups, not necessarily singular packets (unless n=1 in the group)
            pub(crate) const DO_CONNECT: u8 = 1;
            /// Each scrambled-group gets one of these (Groups are scrambled, by default)
            pub(crate) const GROUP_PACKET: u8 = 2;
            pub(crate) const DO_REGISTER: u8 = 3;
            pub(crate) const DO_DISCONNECT: u8 = 4;
            pub(crate) const DO_DEREGISTER: u8 = 5;
            pub(crate) const DO_PRE_CONNECT: u8 = 6;
            pub(crate) const PEER_CMD: u8 = 7;
            pub(crate) const FILE: u8 = 8;
            pub(crate) const UDP: u8 = 9;
            pub(crate) const HOLE_PUNCH: u8 = 10;
        }

        pub(crate) mod aux {
            pub(crate) mod group {
                /// The header packet in a group, sent prior to transmission of payload, where n = 0 of sequence
                pub(crate) const GROUP_HEADER: u8 = 0;
                /// Sent back after a GROUP_HEADER is received, signalling Alice that it is either ready or not to receive information
                pub(crate) const GROUP_HEADER_ACK: u8 = 1;
                /// The payload packet in a group (the "bulk" of the data)
                pub(crate) const GROUP_PAYLOAD: u8 = 2;
                /// Bob sends this to Alice once he reconstructs a wave. This allows alice to free memory on her side
                pub(crate) const WAVE_ACK: u8 = 3;
            }

            pub(crate) mod do_connect {
                pub(crate) const STAGE0: u8 = 0;
                pub(crate) const STAGE1: u8 = 1;
                pub(crate) const SUCCESS: u8 = 3;
                pub(crate) const FAILURE: u8 = 4;
                pub(crate) const SUCCESS_ACK: u8 = 5;
            }

            pub(crate) mod do_register {
                pub(crate) const STAGE0: u8 = 0;
                pub(crate) const STAGE1: u8 = 1;
                pub(crate) const STAGE2: u8 = 2;
                pub(crate) const SUCCESS: u8 = 5;
                pub(crate) const FAILURE: u8 = 6;
            }

            pub(crate) mod do_disconnect {
                /// Alice sends a STAGE0 packet to Bob
                /// to request a safe disconnect
                pub(crate) const STAGE0: u8 = 0;
                /// Bob sends a packet back to Alice to okay to D/C
                pub(crate) const FINAL: u8 = 1;
            }

            pub(crate) mod do_deregister {
                /// request
                pub(crate) const STAGE0: u8 = 0;
                pub(crate) const SUCCESS: u8 = 3;
                pub(crate) const FAILURE: u8 = 4;
            }

            pub(crate) mod do_preconnect {
                pub(crate) const SYN: u8 = 0;
                pub(crate) const SYN_ACK: u8 = 1;
                // Alice sends this to Bob
                pub(crate) const STAGE0: u8 = 2;
                // alice sends this to bob when the firewall is successfully configured
                pub(crate) const SUCCESS: u8 = 6;
                pub(crate) const FAILURE: u8 = 7;
                pub(crate) const BEGIN_CONNECT: u8 = 8;
                pub(crate) const HALT: u8 = 10;
            }

            /*
               Unlike all other primary commands, peer commands are more poll-like than process-oriented. That is,
               instead of requiring a stateful measure to proceed between stages, these peer commands are meant to
               poll the central servers fast. These commands all require that the session to the HyperLAN server
               is connected
            */

            pub(crate) mod peer_cmd {
                // A signal that has the command details in its payload
                pub(crate) const SIGNAL: u8 = 0;
                // Channels bypass the normal communication method between HyperLAN clients and HyperLAN servers.
                // They allow TURN-like communication WITHOUT encryption/decryption at the HyperLAN server. Instead,
                // channels encrypt/decrypt at their endpoints
                pub(crate) const CHANNEL: u8 = 1;
                pub(crate) const GROUP_BROADCAST: u8 = 2;
            }

            pub(crate) mod file {
                pub(crate) const FILE_HEADER: u8 = 0;
                pub(crate) const FILE_HEADER_ACK: u8 = 1;
                pub(crate) const REVFS_PULL: u8 = 2;
                pub(crate) const REVFS_DELETE: u8 = 3;
                pub(crate) const REVFS_ACK: u8 = 4;
                pub(crate) const REVFS_PULL_ACK: u8 = 5;
                pub(crate) const FILE_ERROR: u8 = 6;
            }

            pub(crate) mod udp {
                pub(crate) const STREAM: u8 = 0;
                pub(crate) const KEEP_ALIVE: u8 = 1;
                pub(crate) const HOLE_PUNCH: u8 = 2;
            }
        }
    }

    pub(crate) mod payload_identifiers {
        pub(crate) mod do_preconnect {
            pub(crate) const TCP_ONLY: u8 = 1;
        }
    }
}

pub(crate) mod packet_sizes {
    use crate::constants::HDP_HEADER_BYTE_LEN;

    /// Group packets
    pub(crate) const GROUP_HEADER_BASE_LEN: usize = HDP_HEADER_BYTE_LEN + 1;
    pub(crate) const GROUP_HEADER_ACK_LEN: usize = HDP_HEADER_BYTE_LEN + 1 + 1 + 4 + 4;
}

#[derive(Debug, FromZeroes, AsBytes, FromBytes, Unaligned, Clone)]
#[repr(C)]
/// The header for each [HdpPacket]
pub struct HdpHeader {
    /// The command expected to be executed on this end
    pub cmd_primary: u8,
    /// Command parameters, not always needed
    pub cmd_aux: u8,
    // This tells the encryption protocol what algorithm to use to decrypt the payload
    pub algorithm: u8,
    /// A value [0,4]
    pub security_level: u8,
    pub protocol_version: U32,
    /// Some commands require arguments; the u128 can hold 16 bytes
    pub context_info: U128,
    /// A unique ID given to a subset of a singular object
    pub group: U64,
    /// The wave ID in the sequence
    pub wave_id: U32,
    /// Multiple clients may be connected from the same node. NOTE: This can also be equal to the ticket id
    pub session_cid: U64,
    /// The entropy_bank version applied to encrypt the data
    pub entropy_bank_version: U32,
    /// Before a packet is sent outbound, the local time is placed into the packet header
    pub timestamp: I64,
    /// The target_cid (0 if hyperLAN server)
    pub target_cid: U64,
}

impl AsRef<[u8]> for HdpHeader {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HdpHeader {
    /// Inscribes the header onto the packet
    pub fn inscribe_into<B: BufMut>(&self, mut writer: B) {
        writer.put_slice(self.as_bytes())
    }

    /// Creates a packet from self
    pub fn as_packet(&self) -> BytesMut {
        BytesMut::from(self.as_bytes())
    }
}

/// The HdpPacket structure
pub struct HdpPacket<B: HdpBuffer = BytesMut> {
    packet: B,
    remote_peer: SocketAddr,
    local_port: u16,
}

pub type ParsedPacket<'a> = (Ref<&'a [u8], HdpHeader>, &'a [u8]);

impl<B: HdpBuffer> HdpPacket<B> {
    /// When a packet comes inbound, this should be used to wrap the packet
    pub fn new_recv(packet: B, remote_peer: SocketAddr, local_port: u16) -> Self {
        Self {
            packet,
            remote_peer,
            local_port,
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.packet.as_ref()
    }

    /// Parses the zerocopy header
    pub fn parse(&self) -> Option<ParsedPacket> {
        Ref::new_from_prefix(self.packet.as_ref())
    }

    /// Creates a packet out of the inner device
    pub fn into_packet(self) -> B {
        self.packet
    }

    /// Returns the length of the packet + header
    pub fn get_length(&self) -> usize {
        self.packet.len()
    }

    /// Splits the header's bytes and the header's in Bytes/Mut form
    pub fn decompose(mut self) -> (B::Immutable, B, SocketAddr, u16) {
        let header_bytes = self.packet.split_to(HDP_HEADER_BYTE_LEN).to_immutable();
        let payload_bytes = self.packet;
        let remote_peer = self.remote_peer;
        let local_port = self.local_port;

        (header_bytes, payload_bytes, remote_peer, local_port)
    }
}

/// Provides random obfuscation to the header of a packet at the start
/// of each session using a key. Helps render deep packet inspection more challenging.
///
/// This was inspired by using XOR-mapped addresses in NAT-traversal packets
/// to help fool firewalls from extracting network addresses and interfering with connections.
///
/// As such, the key should not be a real secret nor derived from a secret, but rather,
/// something that can be transferred in the plain and appear pseudorandom to deep packet inspectors.
///
/// For any given pair of two connnected nodes, one will have to take the
/// "server" role, and the other will take the "client" role.
///
/// If the "server" has a pre-shared key, it will use that key to obfuscate the header.
/// This implies the client must have a matching key.
///
/// If the client enabled the header obfuscator without a pre-shared key, the client
/// will generate a random "first packet" that the server will read, interpret, then
/// use for the remainder of the session.
///
/// If the client disables the header obfuscator, the server will also not obfuscate the contents
/// of the packet (unless the server has a pre-shared key set).
///
/// Valid combinations: (server = PSK, client = PSK), (server = enabled w/no PSK or off, client = enabled w/no PSK or off)
/// Invalid combinations: (server = PSK, client = off), (server = off, client = PSK)
///
/// For invalid packet inputs, the obfuscator will fail silently to not interrupt network traffic.
/// Packets that are too small will be ignored.
/// Packets that arrive with an invalid key will be ignored
///
/// The obfuscator will load the key from the first packet and then store it for the remainder of the session. If there
/// is a pre-existing key, the obfuscator will compare keys, and error if mismatching.
#[derive(Clone)]
pub struct HeaderObfuscator {
    inner: DualCell<Option<NonZero<u128>>>,
    pub first_packet: Option<BytesMut>,
    expected_key: Option<NonZero<u128>>,
    disabled: DualCell<bool>,
    client_intends_disable: DualCell<bool>,
}

const DISABLED_KEY: u128 = u128::MAX;

impl HeaderObfuscator {
    pub fn new(is_server: bool, header_obfuscator_settings: HeaderObfuscatorSettings) -> Self {
        if is_server {
            Self::new_server(header_obfuscator_settings)
        } else {
            Self::new_client(header_obfuscator_settings)
        }
    }

    /// Returns Ok(true) if the packet can be processed by the downstream application
    /// Returns Ok(false) if the packet is either frivolous, invalid, or an initial handshake packet
    pub fn on_packet_received(&self, packet: &mut BytesMut) -> Result<bool, NetworkError> {
        if self.is_disabled() {
            return Ok(true);
        } // disabled

        if let Some(val) = self.load() {
            if packet.len() < HDP_HEADER_BYTE_LEN {
                log::warn!(target: "citadel", "[Header Obfuscator] Packet too small: {}", packet.len());
                return Ok(false);
            }

            log::trace!(target: "citadel", "[Header Obfuscator] Applying inbound cipher w/key {val}");
            apply_cipher(val, true, packet);
            Ok(true)
        } else if packet.len() >= 16 {
            // We are only interested in taking the first 16 bytes
            let key = packet.get_u128();

            if key == 0 {
                log::error!(target: "citadel", "[Header Obfuscator] Invalid first packet key == 0");
                return Err(NetworkError::msg("Invalid first packet key"));
            }

            if let Some(expected_key) = self.expected_key {
                if key != expected_key.get() {
                    log::error!(target: "citadel", "[Header Obfuscator] Invalid first packet key {key} != {expected_key}");
                    return Err(NetworkError::msg("Invalid first packet key"));
                }
            }

            if key == DISABLED_KEY {
                log::trace!(target: "citadel", "[Header Obfuscator] Disabling obfuscator at client's request");
                self.disabled.set(true);
                self.client_intends_disable.set(true);
                return Ok(false);
            }

            self.store(key);
            log::trace!(target: "citadel", "[Header Obfuscator] initial packet set to {key}");
            Ok(false)
        } else {
            log::warn!(target: "citadel", "[Header Obfuscator] Packet too small (skipping): {}", packet.len());
            Ok(false)
        }
    }

    /// This will only obfuscate packets that are at least HDP_HEADER_BYTE_LEN
    pub fn prepare_outbound(&self, mut packet: BytesMut) -> Bytes {
        if self.client_intends_disable.get() && self.disabled.get() {
            return packet.freeze();
        }

        if let Some(key) = self.load() {
            if packet.len() >= HDP_HEADER_BYTE_LEN {
                log::trace!(target: "citadel", "[Header Obfuscator] Applying outbound cipher w/key {key}");
                apply_cipher(key, false, &mut packet);

                if self.client_intends_disable.get() {
                    // Prevent further use of the obfuscator
                    self.disabled.set(true);
                }
            }
        }

        packet.freeze()
    }

    /// Returns to the client an instance of self coupled with the required init packet
    pub fn new_client(header_obfuscator_settings: HeaderObfuscatorSettings) -> Self {
        let key = match header_obfuscator_settings {
            HeaderObfuscatorSettings::Enabled => rand::random::<u128>(),
            HeaderObfuscatorSettings::Disabled => {
                let mut disabled_packet = BytesMut::with_capacity(16);
                disabled_packet.put_u128(DISABLED_KEY);
                return Self {
                    inner: None.into(),
                    first_packet: Some(disabled_packet),
                    expected_key: None,
                    disabled: true.into(),
                    client_intends_disable: false.into(),
                };
            }
            HeaderObfuscatorSettings::EnabledWithKey(key) => key,
        };

        let key = hash_u128(key);

        let mut rng = ThreadRng::default();
        let bytes_to_add = rng.gen_range(0..(HDP_HEADER_BYTE_LEN - 17));
        let mut packet = vec![0; 16 + bytes_to_add];
        let tmp = &mut packet[..];
        let mut tmp = tmp.writer();
        tmp.write_u128::<BigEndian>(key).expect("Should not fail");

        rng.fill_bytes(&mut packet[16..]);
        let first_packet = Some(BytesMut::from(&packet[..]));
        Self {
            inner: DualCell::from(Some(NonZero::new(key).expect("Hashed key cannot be zero"))),
            first_packet,
            expected_key: None,
            disabled: false.into(),
            client_intends_disable: false.into(),
        }
    }

    pub fn new_server(header_obfuscator_settings: HeaderObfuscatorSettings) -> Self {
        let (inner, expected_key) = match header_obfuscator_settings {
            HeaderObfuscatorSettings::Enabled => (DualCell::from(None), None), // Wait for client to set key value
            HeaderObfuscatorSettings::Disabled => (DualCell::from(None), None), // No obfuscation; up to the client to enable it
            HeaderObfuscatorSettings::EnabledWithKey(key) => {
                // Obfuscation is enabled with a pre-shared key
                let key = NonZero::new(hash_u128(key)).expect("Hashed key cannot be zero");
                (DualCell::from(Some(key)), Some(key))
            }
        };

        Self {
            inner,
            first_packet: None,
            expected_key,
            disabled: false.into(), // Let the client enable or disable
            client_intends_disable: false.into(), // Let the client enable or disable
        }
    }

    fn store(&self, key: u128) {
        let key = NonZero::new(key).expect("Input key cannot be zero");
        self.inner.set(Some(key));
    }

    fn load(&self) -> Option<u128> {
        Some(self.inner.get()?.get())
    }

    fn is_disabled(&self) -> bool {
        self.disabled.get()
    }
}

fn hash_u128(key: u128) -> u128 {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(key.to_be_bytes());
    let out: [u8; 32] = hasher.finalize().into();
    let slice: [u8; 16] = out[0..16].try_into().unwrap();
    u128::from_be_bytes(slice)
}

/// # Safety
/// This is NOT a cryptographically-secure cipher since its inverse is relatively trivial:
///
/// C' = ((C + A) XOR B) mod 2^8
/// C = ((C' XOR B) - A) mod 2^8
/// The purpose of this is to obfuscate the header to make deep packet inspection
/// more challenging while providing minimal overhead. As such, the inputs should
/// be data that is acceptable to be plaintext, not ciphertext.
///
/// # Panics
///  If packet is not of proper length
#[inline]
fn apply_cipher(val: u128, inverse: bool, packet: &mut BytesMut) {
    let bytes = val.to_be_bytes();
    let (bytes0, bytes1) = bytes.split_at(8);
    let packet_len = packet.len().min(HDP_HEADER_BYTE_LEN);
    let packet = &mut packet[..packet_len];
    bytes0
        .iter()
        .zip(bytes1.iter())
        .cycle()
        .zip(packet.iter_mut())
        .for_each(|((a, b), c)| cipher_inner(*a, *b, c, inverse))
}

#[inline]
fn cipher_inner(a: u8, b: u8, c: &mut u8, inverse: bool) {
    if inverse {
        *c = (*c ^ b).wrapping_sub(a);
    } else {
        *c = c.wrapping_add(a) ^ b;
    }
}

pub trait HdpBuffer: BufMut + AsRef<[u8]> + AsMut<[u8]> {
    type Immutable;
    fn len(&self) -> usize;
    fn split_to(&mut self, idx: usize) -> Self;
    fn to_immutable(self) -> Self::Immutable;
}

impl HdpBuffer for BytesMut {
    type Immutable = Bytes;

    fn len(&self) -> usize {
        self.len()
    }

    fn split_to(&mut self, idx: usize) -> Self {
        self.split_to(idx)
    }

    fn to_immutable(self) -> Self::Immutable {
        self.freeze()
    }
}

impl HdpBuffer for Vec<u8> {
    type Immutable = Vec<u8>;

    fn len(&self) -> usize {
        self.len()
    }

    fn split_to(&mut self, idx: usize) -> Self {
        let tail = self[..idx].to_vec();
        self.copy_within(idx.., 0);
        self.truncate(self.len() - idx);
        tail // now, tail is the head
    }

    fn to_immutable(self) -> Self::Immutable {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use citadel_types::crypto::HeaderObfuscatorSettings;

    #[test]
    fn test_header_obfuscator_client_server_interaction() {
        // Test client initialization
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Enabled);
        assert!(
            client.first_packet.is_some(),
            "Client should have initial packet"
        );
        assert!(
            client.expected_key.is_none(),
            "Client should not have expected key initially"
        );

        // Test server initialization
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);
        assert!(
            server.first_packet.is_none(),
            "Server should not have initial packet"
        );
        assert!(
            server.expected_key.is_none(),
            "Server should not have expected key initially"
        );
    }

    #[test]
    fn test_header_obfuscator_key_exchange() {
        // Create client and server
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Enabled);
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);

        // Get first packet from client
        let mut first_packet = client.first_packet.as_ref().unwrap().clone();

        // Server should process first packet successfully
        assert!(server.on_packet_received(&mut first_packet).is_ok());

        // Server should now have the same key as client
        assert_eq!(server.load(), client.load());
        assert!(server.load().is_some(), "Both should have non-None key");

        // Create and process a test packet
        let mut test_packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        test_packet.resize(HDP_HEADER_BYTE_LEN, 1); // Fill with 1's

        // Process packet through client and server
        let client_processed = client.prepare_outbound(test_packet.clone());
        let mut server_packet = BytesMut::from(&client_processed[..]);

        // Server should process the packet successfully
        assert!(server.on_packet_received(&mut server_packet).is_ok());
    }

    #[test]
    fn test_header_obfuscator_disabled() {
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Disabled);
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Disabled);

        // Both should have no key and no first packet
        assert!(client.load().is_none());
        assert!(server.load().is_none());
        assert!(client.first_packet.is_some()); // Contains to null packet designed for disabling use
        assert!(server.first_packet.is_none());
    }

    #[test]
    fn test_header_obfuscator_small_packet_ignores() {
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(12345));

        // Test packet smaller than 16 bytes
        let mut small_packet = BytesMut::with_capacity(16);
        small_packet.resize(15, 1);
        let initial_small_packet = small_packet.clone();
        assert!(
            server.on_packet_received(&mut small_packet).is_ok(),
            "Packets that are smaller than 16 bytes will just be skipped"
        );
        assert_eq!(
            initial_small_packet, small_packet,
            "Packets that are smaller than 16 bytes should not be modified"
        );

        // Test empty packet
        let mut empty_packet = BytesMut::new();
        let initial_empty_packet = empty_packet.clone();
        assert!(
            server.on_packet_received(&mut empty_packet).is_ok(),
            "Empty packets should be skipped"
        );
        assert_eq!(
            initial_empty_packet, empty_packet,
            "Empty packets should not be modified"
        );
    }

    #[test]
    fn test_header_obfuscator_invalid_keys() {
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(12345));

        // Test packet with zero key
        let mut zero_key_packet = BytesMut::with_capacity(16);
        zero_key_packet.put_u128(0);
        assert_eq!(zero_key_packet.len(), 16);
        assert!(
            server.on_packet_received(&mut zero_key_packet).is_ok(),
            "Should silently ignore packet with zero key"
        );

        // Test packet with invalid key
        let mut invalid_key_packet = BytesMut::with_capacity(16);
        invalid_key_packet.put_u128(54321); // Different from server's key
        assert!(
            server.on_packet_received(&mut invalid_key_packet).is_ok(),
            "Should ignore packet with mismatched key"
        );
    }

    #[test]
    fn test_header_obfuscator_invalid_keys_no_preset_server_value() {
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);

        // Test packet with zero key
        let mut zero_key_packet = BytesMut::with_capacity(16);
        zero_key_packet.put_u128(0);
        assert!(
            server.on_packet_received(&mut zero_key_packet).is_err(),
            "Should error on packet with zero key"
        );
        assert!(server.load().is_none(), "Server should have no key until the client sends a valid key since the server has no initial key");

        let mut good_first_packet = BytesMut::with_capacity(16);
        good_first_packet.put_u128(12345);
        assert!(
            server.on_packet_received(&mut good_first_packet).is_ok(),
            "Should accept packet with valid key"
        );

        // Test packet with invalid key
        let mut invalid_key_packet = BytesMut::with_capacity(16);
        invalid_key_packet.put_u128(
            server
                .load()
                .expect("Server should have key")
                .wrapping_add(1),
        ); // Different from server's key
        assert!(
            server.on_packet_received(&mut invalid_key_packet).is_ok(),
            "Should ignore packet with mismatched key"
        );
    }

    #[test]
    fn test_header_obfuscator_disabled_behavior() {
        let disabled_server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Disabled);
        let disabled_client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Disabled);

        // Create test packets
        let mut small_packet = BytesMut::with_capacity(8);
        small_packet.resize(8, 1);
        let initial_small = small_packet.clone();

        let mut full_packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        full_packet.resize(HDP_HEADER_BYTE_LEN, 2);
        let initial_full = full_packet.clone();

        // Test that disabled obfuscator doesn't modify any packets
        assert!(disabled_server
            .on_packet_received(&mut small_packet)
            .is_ok());
        assert!(disabled_client.on_packet_received(&mut full_packet).is_ok());
        assert_eq!(
            initial_small, small_packet,
            "Disabled obfuscator should not modify small packets"
        );
        assert_eq!(
            initial_full, full_packet,
            "Disabled obfuscator should not modify full packets"
        );
    }

    #[test]
    fn test_header_obfuscator_key_exchange_flow() {
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Enabled);
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);

        // Get first packet from client
        let mut first_packet = client.first_packet.as_ref().unwrap().clone();

        // Server should process first packet successfully
        assert!(server.on_packet_received(&mut first_packet).is_ok());
        assert_ne!(
            first_packet,
            client.first_packet.as_ref().unwrap().clone(),
            "First packet should be modified by server"
        );

        // Both should now have same key
        assert_eq!(server.load(), client.load());
        assert!(server.load().is_some(), "Both should have non-None key");

        // Create and process a test packet
        let mut test_packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        test_packet.resize(HDP_HEADER_BYTE_LEN, 3);
        let initial_test = test_packet.clone();

        // Process packet through client and server
        let client_processed = client.prepare_outbound(test_packet.clone());
        let mut server_packet = BytesMut::from(&client_processed[..]);

        // Server should process the packet successfully
        assert!(server.on_packet_received(&mut server_packet).is_ok());
        assert_eq!(
            server_packet, initial_test,
            "Server should decrypt to original packet"
        );

        // Server -> Client
        let server_processed = server.prepare_outbound(test_packet.clone());
        let mut client_packet = BytesMut::from(&server_processed[..]);

        // Client should process the packet successfully
        assert!(client.on_packet_received(&mut client_packet).is_ok());
        assert_eq!(
            client_packet, initial_test,
            "Client should decrypt to original packet"
        );
    }

    #[test]
    fn test_header_obfuscator_preshared_key() {
        let psk = 12345u128;
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::EnabledWithKey(psk));
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(psk));

        // Both should have the same hashed key
        assert_eq!(client.load(), server.load());
        assert!(client.load().is_some());

        // Create and process a test packet
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        packet.resize(HDP_HEADER_BYTE_LEN, 1); // Fill with 1's

        // Process packet through client and server
        let client_processed = client.prepare_outbound(packet.clone());
        let mut server_packet = BytesMut::from(&client_processed[..]);

        // Server should process the packet successfully
        assert!(server.on_packet_received(&mut server_packet).is_ok());
    }

    #[test]
    fn test_header_obfuscator_mismatched_psk() {
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::EnabledWithKey(12345));
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(54321));

        // Create a test packet
        let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN);
        packet.resize(HDP_HEADER_BYTE_LEN, 0);

        // Packets should be processed differently due to different keys
        let client_processed = client.prepare_outbound(packet.clone());
        let server_processed = server.prepare_outbound(packet.clone());
        assert_ne!(client_processed[..], server_processed[..]);
    }

    #[test]
    fn test_header_obfuscator_key_validation() {
        // Test with pre-shared key enabled
        let mut server =
            HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(12345));

        // Test packet with mismatched key (should fail)
        let mut invalid_key_packet = BytesMut::with_capacity(16);
        invalid_key_packet.put_u128(54321); // Different from server's key
        assert!(
            server.on_packet_received(&mut invalid_key_packet).is_ok(),
            "Should silently accept packet with mismatched key"
        );

        // Test packet with valid key but too small (should be ignored)
        let mut small_valid_key = BytesMut::with_capacity(16);
        small_valid_key.put_u128(12345);
        assert!(
            server.on_packet_received(&mut small_valid_key).is_ok(),
            "Should accept packet with valid key even if small"
        );

        // Test with no pre-shared key
        server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);

        // Test packet with any non-zero key (should succeed)
        let mut valid_key_packet = BytesMut::with_capacity(16);
        valid_key_packet.put_u128(54321);
        assert!(
            server.on_packet_received(&mut valid_key_packet).is_ok(),
            "Should accept any non-zero key when no PSK"
        );
    }

    #[test]
    fn test_header_obfuscator_psk_mismatch_modes() {
        // Test client with PSK connecting to server without PSK
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::EnabledWithKey(12345));
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::Enabled);

        // Get first packet from client
        let mut first_packet = client.first_packet.as_ref().unwrap().clone();

        // Server should accept the packet since it has no PSK expectations
        assert!(server.on_packet_received(&mut first_packet).is_ok());
        assert!(server.load().is_some());

        // Test server with PSK receiving from client without PSK
        let client = HeaderObfuscator::new_client(HeaderObfuscatorSettings::Enabled);
        let server = HeaderObfuscator::new_server(HeaderObfuscatorSettings::EnabledWithKey(12345));

        // Get first packet from client
        let mut first_packet = client.first_packet.as_ref().unwrap().clone();

        // Server should silently ignore the packet since it doesn't match PSK
        assert!(server.on_packet_received(&mut first_packet).is_ok());
        assert_eq!(server.load().unwrap(), hash_u128(12345));
    }
}
