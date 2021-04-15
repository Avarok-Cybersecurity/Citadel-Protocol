use std::io;

use byteorder::{NetworkEndian, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut, Buf};
use zerocopy::{AsBytes, FromBytes, I64, LayoutVerified, U32, U64, Unaligned};

use crate::constants::HDP_HEADER_BYTE_LEN;
use std::net::SocketAddr;
use rand::prelude::ThreadRng;
use rand::{RngCore, Rng};
use crate::functional::PairMap;
use std::io::Write;

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
            pub(crate) const DO_DRILL_UPDATE: u8 = 5;
            pub(crate) const DO_DEREGISTER: u8 = 6;
            pub(crate) const DO_PRE_CONNECT: u8 = 7;
            pub(crate) const PEER_CMD: u8 = 8;
            pub(crate) const FILE: u8 = 9;
        }

        pub(crate) mod aux {
            pub(crate) mod group {
                /// The header packet in a group, sent prior to transmission of payload, where n = 0 of sequence
                pub(crate) const GROUP_HEADER: u8 = 0;
                /// Sent back after a GROUP_HEADER is received, signalling Alice that it is either ready or not to receive information
                pub(crate) const GROUP_HEADER_ACK: u8 = 1;
                /// The payload packet in a group (the "bulk" of the data)
                pub(crate) const GROUP_PAYLOAD: u8 = 2;
                /// This is sent after each wave is dispatched
                pub(crate) const GROUP_WINDOW_TAIL: u8 = 3;
                /// For requesting a re-transmission
                pub(crate) const WAVE_DO_RETRANSMISSION: u8 = 4;
                /// Bob sends this to Alice once he reconstructs a wave. This allows alice to free memory on her side
                pub(crate) const WAVE_ACK: u8 = 5;
            }

            pub(crate) mod do_connect {
                pub(crate) const STAGE0: u8 = 0;
                pub(crate) const STAGE1: u8 = 1;
                pub(crate) const SUCCESS: u8 = 3;
                pub(crate) const FAILURE: u8 = 4;
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

            pub(crate) mod do_drill_update {
                pub(crate) const STAGE0: u8 = 0;
                pub(crate) const STAGE1: u8 = 1;

                pub(crate) const TRUNCATE: u8 = 2;
                pub(crate) const TRUNCATE_ACK: u8 = 3;
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
                // bob sends this to alice
                pub(crate) const STAGE1: u8 = 3;
                pub(crate) const STAGE_TRY_NEXT: u8 = 4;
                pub(crate) const STAGE_TRY_NEXT_ACK: u8 = 5;
                // alice sends this to bob when the firewall is successfully configured
                pub(crate) const SUCCESS: u8 = 6;
                pub(crate) const FAILURE: u8 = 7;
                pub(crate) const BEGIN_CONNECT: u8 = 8;
                // Bob sends this to Alice when he's finished the hole-punching process
                pub(crate) const RECEIVER_FINISHED_HOLE_PUNCH: u8 = 9;
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
    /// + 16 bytes for an 8-byte, 4-byte security parameter, and the end of the window
    pub(crate) const GROUP_WINDOW_TAIL_LEN: usize = HDP_HEADER_BYTE_LEN + 4;

    pub(crate) mod do_drill_update {
        use crate::constants::HDP_HEADER_BYTE_LEN;

        pub(crate) const STAGE1: usize = HDP_HEADER_BYTE_LEN + HDP_HEADER_BYTE_LEN;
    }

    pub(crate) mod do_preconnect {
        use crate::constants::HDP_HEADER_BYTE_LEN;

        pub(crate) const STAGE_TRY_NEXT: usize = HDP_HEADER_BYTE_LEN + 1;
        // +8 for the i64 sync_time
        pub(crate) const STAGE_TRY_NEXT_ACK: usize = HDP_HEADER_BYTE_LEN + 8;
        pub(crate) const STAGE_SUCCESS_ACK: usize = HDP_HEADER_BYTE_LEN;
    }
}

#[derive(Debug, AsBytes, FromBytes, Unaligned, Clone)]
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
    /// Some commands require arguments; the u64 can hold 8 bytes. The type is w.r.t the context
    pub context_info: U64<NetworkEndian>,
    /// A unique ID given to a subset of a singular object
    pub group: U64<NetworkEndian>,
    /// The wave ID in the sequence
    pub wave_id: U32<NetworkEndian>,
    /// Multiple clients may be connected from the same node. NOTE: This can also be equal to the ticket id
    pub session_cid: U64<NetworkEndian>,
    /// The drill version applied to encrypt the data
    pub drill_version: U32<NetworkEndian>,
    /// Before a packet is sent outbound, the local time is placed into the packet header
    pub timestamp: I64<NetworkEndian>,
    /// The target_cid (0 if hyperLAN server)
    pub target_cid: U64<NetworkEndian>
}

impl AsRef<[u8]> for HdpHeader {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HdpHeader {
    /// Inscribes the header onto the packet
    pub fn inscribe_into<B: BufMut>(&self, writer: &mut B) {
        writer.put_u8(self.cmd_primary);
        writer.put_u8(self.cmd_aux);
        writer.put_u8(self.algorithm);
        writer.put_u8(self.security_level);
        writer.put_u64(self.context_info.get());
        writer.put_u64(self.group.get());
        writer.put_u32(self.wave_id.get());
        writer.put_u64(self.session_cid.get());
        writer.put_u32(self.drill_version.get());
        writer.put_i64(self.timestamp.get());
        writer.put_u64(self.target_cid.get());
    }

    /// similar to inscribe_into, except is meant for raw mutable buffers
    pub fn inscribe_into_slice(&self, output: &mut [u8]) {
        debug_assert_eq!(output.len(), HDP_HEADER_BYTE_LEN);

        let mut writer = io::Cursor::new(output);
        writer.write_u8(self.cmd_primary).unwrap();
        writer.write_u8(self.cmd_aux).unwrap();
        writer.write_u8(self.algorithm).unwrap();
        writer.write_u8(self.security_level).unwrap();
        writer.write_u64::<NetworkEndian>(self.context_info.get()).unwrap();
        writer.write_u64::<NetworkEndian>(self.group.get()).unwrap();
        writer.write_u32::<NetworkEndian>(self.wave_id.get()).unwrap();
        writer.write_u64::<NetworkEndian>(self.session_cid.get()).unwrap();
        writer.write_u32::<NetworkEndian>(self.drill_version.get()).unwrap();
        writer.write_i64::<NetworkEndian>(self.timestamp.get()).unwrap();
        writer.write_u64::<NetworkEndian>(self.target_cid.get()).unwrap();
    }

    /// Creates a packet from self
    pub fn into_packet(self) -> BytesMut {
        BytesMut::from(self.as_bytes())
    }

    pub fn into_vec(self) -> Vec<u8> {
        Vec::from(self.as_ref())
    }

    pub fn into_packet_mut(self) -> BytesMut {
        BytesMut::from(self.as_bytes())
    }

    /// Useful for FCM relaying
    pub fn concat_with<T: AsRef<[u8]>>(&self, payload: T) -> Vec<u8> {
        let payload = payload.as_ref();
        let mut ret = Vec::<u8>::with_capacity(HDP_HEADER_BYTE_LEN + payload.len());
        self.inscribe_into(&mut ret);
        ret.put(payload);
        ret
    }
}

/// The HdpPacket structure
pub struct HdpPacket<B: HdpBuffer= BytesMut> {
    packet: B,
    remote_peer: SocketAddr,
    local_port: u16
}

impl<B: HdpBuffer> HdpPacket<B> {
    /// When a packet comes inbound, this should be used to wrap the packet
    pub fn new_recv(packet: B, remote_peer: SocketAddr, local_port: u16) -> Self {
        Self { packet, remote_peer, local_port }
    }

    /// Note: make sure the buffer has reserved enough room! And make sure the cursor is at zero! Otherwise, panic!
    /// `payload`: Big Endian order!
    pub fn inscribe<Buf: BufMut, Payload: AsRef<[u8]>>(writer: &mut Buf, header: &HdpHeader, payload: Option<Payload>) -> io::Result<()> {
        header.inscribe_into(writer);

        if let Some(payload) = payload {
            writer.put_slice(payload.as_ref());
        }

        Ok(())
    }

    /// Parses the zerocopy header
    pub fn parse(&self) -> Option<(LayoutVerified<&[u8], HdpHeader>, &[u8])> {
        LayoutVerified::new_from_prefix(self.packet.as_ref())
    }

    /// Parses the zerocopy header
    pub fn parse_mut(&mut self) -> Option<(LayoutVerified<&mut [u8], HdpHeader>, &mut [u8])> {
        LayoutVerified::new_from_prefix(self.packet.as_mut())
    }

    /// Creates a packet out of the inner device
    pub fn into_packet(self) -> B {
        self.packet
    }

    /// Parses the header
    pub fn get_header(&self) -> Option<LayoutVerified<&[u8], HdpHeader>> {
        Some(self.parse()?.0)
    }

    /// Parses the payload
    pub fn get_payload(&self) -> Option<&[u8]> {
        Some(self.parse()?.1)
    }

    /// Parses the header
    pub fn get_header_mut(&mut self) -> Option<LayoutVerified<&mut [u8], HdpHeader>> {
        Some(self.parse_mut()?.0)
    }

    /// Parses the payload
    pub fn get_payload_mut(&mut self) -> Option<&mut [u8]> {
        Some(self.parse_mut()?.1)
    }

    /// returns the remote socket
    pub fn get_remote_socket(&self) -> &SocketAddr {
        &self.remote_peer
    }

    /// Returns the port from which this packet ventured
    pub fn get_remote_port(&self) -> u16 {
        self.remote_peer.port()
    }

    /// Returns the local port of entry
    pub fn get_local_port(&self) -> u16 {
        self.local_port
    }

    /// Determines if the packet's header is valid
    pub fn is_header_valid(&self) -> bool {
        self.get_header().is_some()
    }

    /// Returns the length of the packet + header
    pub fn get_length(&self) -> usize {
        self.packet.len()
    }

    /// Splits the header's bytes and the header's in Bytes/Mut form
    pub fn decompose(mut self) -> (B::Immutable, B, SocketAddr, u16) {
        let header_bytes = self.packet.split_to(HDP_HEADER_BYTE_LEN).freeze();
        let payload_bytes = self.packet;
        let remote_peer = self.remote_peer;
        let local_port = self.local_port;

        (header_bytes, payload_bytes, remote_peer, local_port)
    }
}


#[cfg(feature = "multi-threaded")]
#[derive(Clone)]
pub struct HeaderObfuscator {
    inner: std::sync::Arc<atomic::Atomic<Option<u128>>>
}

#[cfg(not(feature = "multi-threaded"))]
#[derive(Clone)]
pub struct HeaderObfuscator {
    inner: std::rc::Rc<std::cell::Cell<Option<u128>>>
}

impl HeaderObfuscator {
    pub fn new(is_server: bool) -> (Self, Option<BytesMut>) {
        if is_server {
            (Self::new_server(), None)
        } else {
            Self::new_client()
                .map_right(Some)
        }
    }

    pub fn on_packet_received(&self, packet: &mut BytesMut) -> Option<()> {
        //log::info!("[Header-scrambler] RECV {:?}", &packet[..]);
        if let Some(val) = self.load() {
            //log::info!("[Header-scrambler] received ordinary packet");
            apply_cipher(val, true, packet);
            Some(())
        } else {
            if packet.len() >= 16 && packet.len() < HDP_HEADER_BYTE_LEN {
                //log::info!("[Header-Scrambler] Loading first-time packet {:?}", &packet[..]);
                // we are only interested in taking the first 16 bytes
                let val0 = packet.get_u64();
                let val1 = packet.get_u64();
                self.store(val0, val1);
                log::info!("[Header obfuscator] initial packet set");
            } else {
                log::error!("Discarding invalid packet (LEN: {})", packet.len());
            }

            None
        }
    }

    /// This will only obfuscate packets that are at least HDP_HEADER_BYTE_LEN
    pub fn prepare_outbound(&self, mut packet: BytesMut) -> Bytes {
        if packet.len() >= HDP_HEADER_BYTE_LEN {
            //log::info!("[Header-scrambler] Before: {:?}", &packet[..]);
            // it is assumed that the value is already loaded
            let val = self.load().unwrap();
            apply_cipher(val, false, &mut packet);
            //log::info!("[Header-scrambler] After: {:?}", &packet[..]);
        }

        packet.freeze()
    }

    /// Returns to the client an instance of self coupled with the required init packet
    pub fn new_client() -> (Self, BytesMut) {
        let mut rng = ThreadRng::default();
        let mut fill0 = [0u8; 8];
        let mut fill1 = [0u8; 8];

        rng.fill(&mut fill0);
        rng.fill(&mut fill1);

        let val0 = u64::from_be_bytes(fill0);
        let val1 = u64::from_be_bytes(fill1);
        //log::info!("[header-scrambler] {} -> {:?} | {} -> {:?}", val0, &fill0, val1, &fill1);
        // we have 16 bytes used. Now, choose a random number of bytes between 0 and HDP_HEADER_BYTE_LEN - 16 to fill
        let bytes_to_add = rng.gen_range(0, HDP_HEADER_BYTE_LEN - 17);
        let mut packet = vec![0; 16 + bytes_to_add];
        let tmp = &mut packet[..];
        let mut tmp = tmp.writer();
        tmp.write_all(&fill0 as &[u8]).unwrap();
        tmp.write_all(&fill1 as &[u8]).unwrap();

        rng.fill_bytes(&mut packet[16..]);
        //log::info!("[Header-scrambler] Prepared packet: {:?}", &packet[..]);
        let packet = BytesMut::from(&packet[..]);
        let this = Self::new_from_u64s(val0, val1);
        (this, packet)
    }

    pub fn new_server() -> Self {
        Self::from(None)
    }

    fn store(&self, val0: u64, val1: u64) {
        #[cfg(feature = "multi-threaded")]
            {
                self.inner.store(Some(u64s_to_u128(val0, val1)), atomic::Ordering::Acquire);
            }
        #[cfg(not(feature = "multi-threaded"))]
            {
                self.inner.set(Some(u64s_to_u128(val0, val1)))
            }
    }

    fn new_from_u64s(val0: u64, val1: u64) -> Self {
        Self::from(Some(u64s_to_u128(val0, val1)))
    }

    fn load(&self) -> Option<u128> {
        #[cfg(feature = "multi-threaded")]
            {
                self.inner.load(atomic::Ordering::Acquire)
            }
        #[cfg(not(feature = "multi-threaded"))]
            {
                self.inner.get()
            }
    }
}

fn u64s_to_u128(val0: u64, val1: u64) -> u128 {
    let mut ret = [0u8; 16];
    let val0_bytes = val0.to_be_bytes();
    let val1_bytes = val1.to_be_bytes();
    for x in 0..8 {
        ret[x] = val0_bytes[x];
        ret[x + 8] = val1_bytes[x];
    }

    u128::from_be_bytes(ret)
}

/// panics if packet is not of proper length
#[inline]
fn apply_cipher(val: u128, inverse: bool, packet: &mut BytesMut) {
    let ref bytes = val.to_be_bytes();
    let (bytes0, bytes1) = bytes.split_at(8);
    let packet = &mut packet[..HDP_HEADER_BYTE_LEN];
    bytes0.iter().zip(bytes1.iter())
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

impl From<Option<u128>> for HeaderObfuscator {
    fn from(inner: Option<u128>) -> Self {
        #[cfg(feature = "multi-threaded")]
        {
            Self { inner: std::sync::Arc::new(atomic::Atomic::new(inner)) }
        }
        #[cfg(not(feature = "multi-threaded"))]
            {
                Self { inner: std::rc::Rc::new(std::cell::Cell::new(inner)) }
            }
    }
}

pub trait HdpBuffer: BufMut + AsRef<[u8]> + AsMut<[u8]> {
    type Immutable;
    fn len(&self) -> usize;
    fn split_to(&mut self, idx: usize) -> Self;
    fn freeze(self) -> Self::Immutable;
}

impl HdpBuffer for BytesMut {
    type Immutable = Bytes;

    fn len(&self) -> usize {
        self.len()
    }

    fn split_to(&mut self, idx: usize) -> Self {
        self.split_to(idx)
    }

    fn freeze(self) -> Self::Immutable {
        self.freeze()
    }
}

impl HdpBuffer for Vec<u8> {
    type Immutable = Self;

    fn len(&self) -> usize {
        self.len()
    }

    // return [0, idx), leave self with [idx, len)
    fn split_to(&mut self, idx: usize) -> Self {
        let mut tail = self.split_off(idx);
        // swap head into tail
        std::mem::swap(self, &mut tail);
        tail // now, tail is the head
    }

    fn freeze(self) -> Self::Immutable {
        self
    }
}