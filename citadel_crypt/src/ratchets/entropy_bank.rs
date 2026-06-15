//! Entropy Bank: Dynamic Cryptographic State Management
//!
//! This module implements a secure entropy bank system that provides dynamic,
//! evolving cryptographic states for packet protection and nonce generation.
//! It ensures replay attack prevention and maintains secure packet ordering.
//!
//! # Features
//!
//! - Dynamic nonce generation and management
//! - Packet encryption and decryption
//! - Replay attack prevention
//! - Ordered packet delivery enforcement
//! - Random scrambling of ciphertext bytes
//! - Post-quantum cryptography support
//! - Transient counter management
//!
//! # Important Notes
//!
//! - Nonce reuse is prevented by design
//! - Ordered packet delivery is mandatory
//! - Port mappings are randomized for security
//! - Thread-safe transient counter handling
//! - Serialization support for persistence
//!
//! # Related Components
//!
//! - [`citadel_pqcrypto::PostQuantumContainer`] - Post-quantum crypto operations
//! - [`crate::misc::CryptError`] - Error handling
//! - [`crate::misc::create_port_mapping`] - Port scrambling

use crate::misc::{create_port_mapping, CryptError};
use byteorder::{BigEndian, ByteOrder};
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ratchets::message_chain::SymmetricChain;
use citadel_pqcrypto::{EncryptionAlgorithmExt, PQNode, PostQuantumContainer};
use rand::prelude::ThreadRng;

pub const DRILL_RANGE: usize = 14;
pub const BYTES_PER_STORE: usize = LARGEST_NONCE_LEN;

/// The default endianness for byte storage
pub type DrillEndian = BigEndian;

impl EntropyBank {
    /// Creates a new entropy_bank
    pub fn new(
        cid: u64,
        version: u32,
        algorithm: EncryptionAlgorithm,
    ) -> Result<Self, CryptError<String>> {
        Self::generate_random_array().map(|bytes| {
            let port_mappings = create_port_mapping();
            let transient_counter = Default::default();
            EntropyBank {
                algorithm,
                version,
                cid,
                entropy: bytes.into(),
                scramble_mappings: port_mappings.into(),
                transient_counter,
                pipelined: false,
                pipelined_chains: citadel_io::Mutex::new(None),
            }
        })
    }

    /// Set the pipelined-PFS routing flag (called at ratchet construction from the negotiated
    /// `SecrecyMode`). When true, [`Self::protect_packet`] / [`Self::validate_packet_in_place_split`]
    /// use the forward-secure symmetric chain instead of the fixed per-version key.
    pub(crate) fn set_pipelined(&mut self, pipelined: bool) {
        // MlKemHybrid is already a per-message-asymmetric AEAD (KEM-OTP + signature per message) and is
        // not supported by the per-message symmetric-key path — it provides its own per-message forward
        // secrecy, so `Perfect` falls back to its native path (design §5a). Only the plain symmetric
        // ciphers (AES/ChaCha/Ascon) use the chain.
        self.pipelined = pipelined && !matches!(self.algorithm, EncryptionAlgorithm::MlKemHybrid);
    }

    /// For generating a random nonce, independent to any entropy_bank
    pub fn generate_public_nonce(
        enx_algorithm: EncryptionAlgorithm,
    ) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let mut base: ArrayVec<u8, LARGEST_NONCE_LEN> = Default::default();
        let mut rng = ThreadRng::default();
        let amt = enx_algorithm.nonce_len();
        for _ in 0..amt {
            base.push(rng.gen())
        }
        base
    }

    #[inline]
    // the nonce_version should come from either the transient counter, or,
    // the appended u32 at the end of each packet
    fn get_nonce(&self, nonce_version: u64) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        // Per-message nonce KDF as a BLAKE3 keyed-hash PRF: the 32-byte secret `entropy` is the key
        // and the packet's `nonce_version` is the input. This is a SIMD-accelerated drop-in for the
        // previous `SHA3-256(entropy || nonce_version)` construction (a Keccak permutation per
        // packet was a measured hot spot). Security is preserved:
        //   * Uniqueness — `nonce_version` is unique per packet (transient counter / packet trailer),
        //     and a keyed PRF is deterministic + collision-resistant in its input, so each packet
        //     gets a distinct nonce (no AEAD nonce reuse).
        //   * Unpredictability — the key (`entropy`) is secret, so outputs are PRF-indistinguishable.
        // BLAKE3's keyed mode is purpose-built for keyed derivation (unlike a bare hash of a secret
        // prefix). NIST SHA3 is retained for ratchet key-evolution and the post-quantum layer — only
        // this nonce KDF changes. WIRE-BREAKING: PROTOCOL_VERSION is bumped so a peer on the old
        // derivation cannot interoperate (and thus cannot mis-derive a colliding nonce).
        let hash = blake3::keyed_hash(&self.entropy, &nonce_version.to_be_bytes());
        let out: [u8; LARGEST_NONCE_LEN] = *hash.as_bytes();
        out.into()
    }

    /// Returns the ciphertext
    pub fn encrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_enx_vec(input, move |input, nonce| {
            quantum_container
                .encrypt(input, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Returns the plaintext if successful
    pub fn decrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_dex_vec(input, move |input, nonce| {
            quantum_container
                .decrypt(input, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Protects an already constructed packet in-place. This guarantees that replay attacks cannot happen
    /// Ordered delivery of packets is mandatory
    pub fn protect_packet<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header_len_bytes: usize,
        full_packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        if self.pipelined {
            return self.protect_packet_in_place_pipelined(
                quantum_container,
                header_len_bytes,
                full_packet,
            );
        }
        self.wrap_with_unique_nonce_enx(full_packet, move |full_packet, nonce| {
            quantum_container
                .protect_packet_in_place(header_len_bytes, full_packet, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Unlike `protect_packet`, the returned object does NOT contain the header. The returned Bytes only contains the ciphertext
    pub fn validate_packet_in_place_split<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header: H,
        payload: &mut T,
    ) -> Result<(), CryptError<String>> {
        if self.pipelined {
            return self.validate_packet_in_place_split_pipelined(
                quantum_container,
                header,
                payload,
            );
        }
        let header = header.as_ref();
        self.wrap_with_unique_nonce_dex(payload, move |payload, nonce| {
            quantum_container
                .validate_packet_in_place(header, payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Lazily seed the per-direction forward-secure chains for the pipelined-PFS path. The seed root is
    /// `BLAKE3(KEM shared secret)` — identical on both endpoints for this version, fresh on every KEM
    /// rekey — domain-separated by a direction label chosen from this node's [`PQNode`] role so that
    /// one node's *send* chain equals the peer's *recv* chain. Idempotent (seeds once per bank).
    fn ensure_pipelined_chains_seeded(
        &self,
        quantum_container: &PostQuantumContainer,
    ) -> Result<(), CryptError<String>> {
        let mut guard = self.pipelined_chains.lock();
        if guard.is_some() {
            return Ok(());
        }
        let shared_secret = quantum_container
            .get_shared_secret()
            .map_err(|err| CryptError::Encrypt(err.to_string()))?;
        // Compress the variable-length KEM secret to a 32-byte root; zeroize the transient copy.
        let root = Zeroizing::new(*blake3::hash(&shared_secret[..]).as_bytes());
        // Direction labels (not send/recv roles) so Alice's send chain == Bob's recv chain.
        let (send_label, recv_label): (&[u8], &[u8]) = match quantum_container.node() {
            PQNode::Alice => (b"a2b", b"b2a"),
            PQNode::Bob => (b"b2a", b"a2b"),
        };
        *guard = Some(DirectionChains {
            send: SymmetricChain::new(&root, send_label),
            recv: SymmetricChain::new(&root, recv_label),
        });
        Ok(())
    }

    /// Pipelined-PFS counterpart to [`Self::protect_packet`]: each message gets a distinct
    /// forward-secure key `MK_i` from this node's local send chain (no per-message KEM round-trip), and
    /// the sequential chain index `i` is appended as the 8-byte trailer (replacing the random
    /// transient-id; the nonce stays `BLAKE3(entropy, i)`, safe since `MK_i` is unique per message).
    /// See `docs/pfs-symmetric-ratchet-design.md`.
    pub fn protect_packet_in_place_pipelined<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header_len_bytes: usize,
        full_packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.ensure_pipelined_chains_seeded(quantum_container)?;
        // The chain lock is held across the seal: the send chain MUST advance atomically per message
        // (sequential index), so concurrent sends on one bank are serialized — required for correctness.
        let mut guard = self.pipelined_chains.lock();
        let chains = guard
            .as_mut()
            .ok_or_else(|| CryptError::Encrypt("pipelined chains unseeded".to_string()))?;
        let (index, message_key) = chains.send.next_send_key();
        let nonce = self.get_nonce(index);
        quantum_container
            .protect_packet_in_place_with_key(
                header_len_bytes,
                full_packet,
                &nonce,
                &message_key[..],
            )
            .map_err(|err| CryptError::Encrypt(err.to_string()))?;
        full_packet
            .extend_from_slice(&index.to_be_bytes())
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Pipelined-PFS counterpart to [`Self::validate_packet_in_place_split`]: reads the 8-byte chain
    /// index trailer, derives `MK_i` from this node's recv chain (tolerating out-of-order delivery up
    /// to [`PIPELINED_MAX_SKIP`] via the chain's skipped-key cache), and opens under `MK_i`.
    pub fn validate_packet_in_place_split_pipelined<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header: H,
        payload: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.ensure_pipelined_chains_seeded(quantum_container)?;
        // Read + strip the trailing 8-byte chain index.
        let starting_pos = payload.len().checked_sub(8).ok_or_else(|| {
            CryptError::Decrypt("packet too small for pipelined chain index".to_string())
        })?;
        let index = BigEndian::read_u64(&payload.as_ref()[starting_pos..]);
        payload.truncate(starting_pos);

        let message_key = {
            let mut guard = self.pipelined_chains.lock();
            let chains = guard
                .as_mut()
                .ok_or_else(|| CryptError::Decrypt("pipelined chains unseeded".to_string()))?;
            chains
                .recv
                .recv_key(index, PIPELINED_MAX_SKIP)
                .map_err(|err| CryptError::Decrypt(err.to_string()))?
        };
        let nonce = self.get_nonce(index);
        quantum_container
            .validate_packet_in_place_with_key(header, payload, &nonce, &message_key[..])
            .map_err(|err| CryptError::Decrypt(err.to_string()))
    }

    /// In-place equivalent of [`Self::encrypt`] (no header AAD, no anti-replay PID): encrypts `buf`
    /// in place, appends the AEAD tag, and appends the 8-byte nonce transient-id trailer. Avoids
    /// the fresh `Vec` allocation `encrypt` performs — used by the scramble/group wave path.
    pub fn encrypt_in_place<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        buf: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.wrap_with_unique_nonce_enx(buf, move |buf, nonce| {
            quantum_container
                .encrypt_in_place(buf, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// In-place equivalent of [`Self::decrypt`], matching [`Self::encrypt_in_place`] / `encrypt`:
    /// reads + removes the nonce transient-id trailer, then decrypts `buf` in place (removing the
    /// AEAD tag). Avoids the fresh `Vec` allocation `decrypt` performs.
    pub fn decrypt_in_place<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        buf: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.wrap_with_unique_nonce_dex(buf, move |buf, nonce| {
            quantum_container
                .decrypt_in_place(buf, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    fn wrap_with_unique_nonce_enx<T: EzBuffer>(
        &self,
        buf: &mut T,
        function: impl FnOnce(&mut T, &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<(), CryptError>,
    ) -> Result<(), CryptError> {
        let transient_id = self.transient_counter.next_id();
        let nonce = &self.get_nonce(transient_id);
        function(buf, nonce)?;
        buf.extend_from_slice(&transient_id.to_be_bytes())
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    fn wrap_with_unique_nonce_dex<T: EzBuffer>(
        &self,
        buf: &mut T,
        function: impl FnOnce(&mut T, &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<(), CryptError>,
    ) -> Result<(), CryptError> {
        let starting_pos = buf.len().saturating_sub(8);
        let transient_id_bytes = &buf.as_ref()[starting_pos..];
        if transient_id_bytes.len() != 8 {
            return Err(CryptError::Decrypt(format!(
                "Bad input size of {} (transient id)",
                buf.as_ref().len()
            )));
        }

        let transient_id = byteorder::BigEndian::read_u64(transient_id_bytes);
        let nonce = &self.get_nonce(transient_id);
        // trim the last 8 bytes
        buf.truncate(starting_pos);
        function(buf, nonce)
    }

    fn wrap_with_unique_nonce_enx_vec<T: AsRef<[u8]>>(
        &self,
        input: T,
        function: impl FnOnce(&[u8], &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<Vec<u8>, CryptError>,
    ) -> Result<Vec<u8>, CryptError> {
        let transient_id = self.transient_counter.next_id();
        let nonce = &self.get_nonce(transient_id);
        let input = input.as_ref();
        let mut out = function(input, nonce)?;
        out.extend_from_slice(&transient_id.to_be_bytes());
        Ok(out)
    }

    fn wrap_with_unique_nonce_dex_vec<T: AsRef<[u8]>>(
        &self,
        input: T,
        function: impl FnOnce(&[u8], &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<Vec<u8>, CryptError>,
    ) -> Result<Vec<u8>, CryptError> {
        let buf = input.as_ref();
        let starting_pos = buf.len().saturating_sub(8);
        let transient_id_bytes = &buf[starting_pos..];
        if transient_id_bytes.len() != 8 {
            return Err(CryptError::Decrypt(format!(
                "Bad input size of {} (transient id)",
                buf.len()
            )));
        }

        let transient_id = byteorder::BigEndian::read_u64(transient_id_bytes);
        let nonce = &self.get_nonce(transient_id);
        // trim the last 8 bytes
        let input = &buf[..starting_pos];
        function(input, nonce)
    }

    pub fn local_encrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        payload: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_enx_vec(payload, move |payload, nonce| {
            // For local_encrypt, always pass the full 32-byte nonce
            // The PostQuantumContainer implementation will handle any necessary slicing
            quantum_container
                .local_encrypt(payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    pub fn local_decrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        payload: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_dex_vec(payload, move |payload, nonce| {
            // For local_decrypt, always pass the full 32-byte nonce
            // The PostQuantumContainer implementation will handle any necessary slicing
            quantum_container
                .local_decrypt(payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Returns the multiport width
    pub fn get_multiport_width(&self) -> usize {
        self.scramble_mappings.len()
    }

    /// Gets the client ID
    pub fn get_cid(&self) -> u64 {
        self.cid
    }

    /// Gets the version of the entropy_bank
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /// Updates the version of the entropy_bank
    pub fn update_version(&mut self, version: u32) -> Result<(), CryptError<String>> {
        self.version = version;
        Ok(())
    }

    /// Downloads the data necessary to create a entropy_bank
    fn generate_random_array() -> Result<[u8; BYTES_PER_STORE], CryptError<String>> {
        let mut bytes: [u8; BYTES_PER_STORE] = [0u8; BYTES_PER_STORE];
        let mut trng = thread_rng();
        trng.fill_bytes(&mut bytes);

        Ok(bytes)
    }

    /// Serializes self to a vector
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, CryptError<String>> {
        bincode::serialize(self).map_err(|err| CryptError::RekeyUpdateError(err.to_string()))
    }

    /// Deserializes self from a set of bytes
    pub fn deserialize_from<T: AsRef<[u8]>>(entropy_bank: T) -> Result<Self, CryptError<String>> {
        bincode::deserialize(entropy_bank.as_ref())
            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))
    }
}

use arrayvec::ArrayVec;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use citadel_types::crypto::EncryptionAlgorithm;
use citadel_types::crypto::LARGEST_NONCE_LEN;
use zeroize::Zeroizing;

/// Forward gap bound for the pipelined-PFS receive chain (Signal-style `MAX_SKIP`). Tied to the
/// protocol's existing in-flight UDP/group window (`docs/pfs-symmetric-ratchet-design.md` §7-3): a
/// receiver will derive at most this many skipped message keys to open an out-of-order packet, so a
/// forged far-future chain index cannot force unbounded key derivation (DoS bound).
pub(crate) const PIPELINED_MAX_SKIP: u64 = 1024;

/// The two per-direction forward-secure chains for the pipelined-PFS path, from *this* node's point of
/// view (send = packets this node protects, recv = packets it validates). Seeded once, lazily, from
/// the version's KEM shared secret; see [`EntropyBank::ensure_pipelined_chains_seeded`].
///
/// SECURITY: this state is intentionally **never serialized** (`#[serde(skip)]` on the owning field).
/// The send chain index is inherently sequential (unlike the random-based nonce counter), so restoring
/// a persisted chain could re-emit a forward-secure `MK_i` — catastrophic. A restored bank therefore
/// has no chain and must rekey to a fresh version (chain @ index 0) before pipelined use
/// (`docs/pfs-symmetric-ratchet-design.md` §5b-3 / §5c-7).
struct DirectionChains {
    send: SymmetricChain,
    recv: SymmetricChain,
}

/// A entropy bank is a fundamental dataset that continually morphs into new future sets
#[derive(Serialize, Deserialize)]
pub struct EntropyBank {
    pub(crate) algorithm: EncryptionAlgorithm,
    pub(crate) version: u32,
    pub(crate) cid: u64,
    pub(crate) entropy: Zeroizing<[u8; BYTES_PER_STORE]>,
    pub(crate) scramble_mappings: Zeroizing<Vec<(u16, u16)>>,
    pub(crate) transient_counter: TransientNonceCounter,
    /// When true (a `SecrecyMode::Perfect` session), [`Self::protect_packet`] /
    /// [`Self::validate_packet_in_place_split`] route through the forward-secure symmetric chain
    /// (per-message key) instead of the fixed per-version key. Set at ratchet construction from the
    /// negotiated mode (both endpoints agree). Persisted (`serde(default)` = false) so a restored bank
    /// keeps routing correctly; the chain state itself is never persisted (see below).
    #[serde(default)]
    pub(crate) pipelined: bool,
    /// Lazily-seeded per-direction forward-secure chains for `SecrecyMode::Perfect` (pipelined).
    /// `None` until the first pipelined protect/validate (when the `PostQuantumContainer` — hence the
    /// KEM shared secret + this node's role — is available). Never persisted (see [`DirectionChains`]).
    #[serde(skip)]
    pipelined_chains: citadel_io::Mutex<Option<DirectionChains>>,
}

/// Per-instance counter used to derive unique AEAD nonces for an [`EntropyBank`].
///
/// Security invariant: a `(key, nonce)` pair must never repeat. The same key can outlive a single
/// process run — most notably the static auxiliary ratchet, whose key is reused across reconnects —
/// and bank state is persisted and cloned via serde. Restoring a *stale* counter value (e.g. after
/// a crash before the next save, from an older serialized snapshot, or from a serde clone) would let
/// a fresh run re-emit nonce-deriving ids already used under that key, which is catastrophic for
/// AES-GCM/ChaCha20-Poly1305.
///
/// To make rollback impossible, the counter is **never restored**: every freshly-constructed *or*
/// deserialized instance starts at an independent random 63-bit base. That gives ~2^63 headroom
/// before wrap and a negligible probability that two instances' incrementing ranges overlap. The
/// value is still written and read as a `u64`, so the serialized byte layout is unchanged (the
/// transmitted id, not this local value, is what the receiver uses to derive the nonce).
#[derive(Debug)]
pub(crate) struct TransientNonceCounter(AtomicU64);

impl TransientNonceCounter {
    fn random_base() -> u64 {
        // Clear the top bit so there are always ~2^63 increments of headroom before wraparound.
        thread_rng().gen::<u64>() >> 1
    }

    /// Atomically returns the next unique nonce id for this instance.
    #[inline]
    pub(crate) fn next_id(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for TransientNonceCounter {
    fn default() -> Self {
        Self(AtomicU64::new(Self::random_base()))
    }
}

impl Serialize for TransientNonceCounter {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Preserve the historical 8-byte (u64) layout for storage/wire compatibility.
        self.0.load(Ordering::Relaxed).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TransientNonceCounter {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Consume the persisted u64 (so the layout is unchanged) but discard it: a restored counter
        // must never be reused. Start from a fresh random base instead.
        let _persisted = u64::deserialize(deserializer)?;
        Ok(Self::default())
    }
}

/// Returns the approximate number of bytes needed to serialize a Drill
pub const fn get_approx_serialized_entropy_bank_len() -> usize {
    4 + 8 + BYTES_PER_STORE + (DRILL_RANGE * 16 * 2)
}

impl Debug for EntropyBank {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        writeln!(
            f,
            "EntropyBank Version: {}\nCID:{}",
            self.get_version(),
            self.get_cid()
        )
    }
}

#[cfg(test)]
mod nonce_counter_tests {
    use super::*;
    use citadel_types::crypto::EncryptionAlgorithm;

    #[test]
    fn counter_is_rerandomized_on_deserialize_not_restored() {
        let bank = EntropyBank::new(1, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        // Advance the live counter as if packets had been encrypted.
        for _ in 0..16 {
            let _ = bank.transient_counter.next_id();
        }
        let bytes = bank.serialize_to_vec().unwrap();

        // Two independent reloads of the SAME persisted bytes must NOT produce the same nonce base.
        // If the persisted counter were restored verbatim, both would start identically — exactly
        // the rollback condition that causes catastrophic AEAD nonce reuse. Re-randomization makes
        // a collision astronomically unlikely (~2^-63).
        let a = EntropyBank::deserialize_from(&bytes).unwrap();
        let b = EntropyBank::deserialize_from(&bytes).unwrap();
        assert_ne!(
            a.transient_counter.next_id(),
            b.transient_counter.next_id(),
            "counter base must be re-randomized per instance, not restored from serialized state"
        );
    }

    #[test]
    fn serialized_layout_roundtrips() {
        // The counter newtype must still occupy its u64 slot so the serialized layout is unchanged.
        let bank = EntropyBank::new(7, 3, EncryptionAlgorithm::AES_GCM_256).unwrap();
        let bytes = bank.serialize_to_vec().unwrap();
        let restored = EntropyBank::deserialize_from(&bytes).unwrap();
        assert_eq!(restored.get_cid(), 7);
        assert_eq!(restored.get_version(), 3);
    }

    // --- BLAKE3 keyed-hash nonce KDF (get_nonce) security properties ---

    #[test]
    fn nonce_is_full_width_and_deterministic() {
        let bank = EntropyBank::new(1, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        let n1 = bank.get_nonce(42);
        let n2 = bank.get_nonce(42);
        // Full BLAKE3 width so every AEAD's nonce_len() prefix is covered.
        assert_eq!(n1.len(), LARGEST_NONCE_LEN);
        // Determinism: both endpoints must derive the same nonce for the same version.
        assert_eq!(n1, n2, "get_nonce must be deterministic in nonce_version");
    }

    #[test]
    fn distinct_versions_yield_distinct_nonces() {
        // Uniqueness is the AEAD-critical property: nonce reuse across packets is catastrophic.
        // Sweep many versions (incl. adjacent + bit-flipped) and assert no collisions.
        let bank = EntropyBank::new(2, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        let mut seen = std::collections::HashSet::new();
        for v in (0u64..4096).chain([u64::MAX, u64::MAX - 1, 1 << 32, 1 << 63]) {
            assert!(
                seen.insert(bank.get_nonce(v).to_vec()),
                "nonce collision at version {v}"
            );
        }
    }

    #[test]
    fn distinct_keys_yield_distinct_nonces() {
        // Two banks (different secret entropy) must not derive the same nonce for the same version —
        // i.e. the entropy genuinely keys the PRF.
        let a = EntropyBank::new(3, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        let b = EntropyBank::new(3, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        assert_ne!(
            a.get_nonce(7),
            b.get_nonce(7),
            "independent entropy must produce independent nonces"
        );
    }
}

#[cfg(test)]
mod pipelined_pfs_tests {
    use super::*;
    use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    use citadel_pqcrypto::PostQuantumContainer;

    // A real ML-KEM exchange so both containers share the same shared secret (the chain seed root) and
    // a working anti-replay pair (alice=tx, bob=rx), mirroring the protocol's sender/receiver split.
    fn pqc_pair() -> (PostQuantumContainer, PostQuantumContainer) {
        let opts = ConstructorOpts::default();
        let mut alice = PostQuantumContainer::new_alice(opts.clone()).unwrap();
        let a2b = alice.generate_alice_to_bob_transfer().unwrap();
        let bob = PostQuantumContainer::new_bob(opts, a2b, &[b"psk"]).unwrap();
        let b2a = bob.generate_bob_to_alice_transfer().unwrap();
        alice.alice_on_receive_ciphertext(b2a, &[b"psk"]).unwrap();
        (alice, bob)
    }

    // Two banks that share the same secret `entropy` (so get_nonce agrees on both ends). Serializing
    // and reloading preserves entropy, re-randomizes only the transient counter, and leaves the
    // (serde-skip) pipelined chains unseeded — exactly the real two-endpoint setup.
    fn twin_banks() -> (EntropyBank, EntropyBank) {
        let alice_bank = EntropyBank::new(1, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
        let bytes = alice_bank.serialize_to_vec().unwrap();
        let bob_bank = EntropyBank::deserialize_from(&bytes).unwrap();
        (alice_bank, bob_bank)
    }

    const HEADER: &[u8] = b"pipelined-pfs-header-0123456789";

    fn protect(bank: &EntropyBank, qc: &PostQuantumContainer, plaintext: &[u8]) -> Vec<u8> {
        let mut packet: Vec<u8> = HEADER.to_vec();
        packet.extend_from_slice(plaintext);
        bank.protect_packet_in_place_pipelined(qc, HEADER.len(), &mut packet)
            .unwrap();
        // Caller gets the payload (everything after the header) for validation.
        packet.split_off(HEADER.len())
    }

    #[test]
    fn pipelined_roundtrip_in_order() {
        let (alice_pqc, bob_pqc) = pqc_pair();
        let (alice_bank, bob_bank) = twin_banks();
        for i in 0..32u32 {
            let plaintext = format!("pipelined bank msg {i}").into_bytes();
            let mut payload = protect(&alice_bank, &alice_pqc, &plaintext);
            assert!(
                payload.len() > plaintext.len(),
                "payload must carry tag + PID + index trailer"
            );
            bob_bank
                .validate_packet_in_place_split_pipelined(&bob_pqc, HEADER, &mut payload)
                .unwrap();
            assert_eq!(payload, plaintext, "round-trip mismatch at {i}");
        }
    }

    #[test]
    fn pipelined_out_of_order_within_window() {
        let (alice_pqc, bob_pqc) = pqc_pair();
        let (alice_bank, bob_bank) = twin_banks();
        let plains: Vec<Vec<u8>> = (0..8u32).map(|i| format!("m{i}").into_bytes()).collect();
        let packets: Vec<Vec<u8>> = plains
            .iter()
            .map(|p| protect(&alice_bank, &alice_pqc, p))
            .collect();
        // Deliver shuffled but within the skip window: the recv chain caches skipped keys.
        for &idx in &[3usize, 1, 0, 2, 7, 5, 4, 6] {
            let mut payload = packets[idx].clone();
            bob_bank
                .validate_packet_in_place_split_pipelined(&bob_pqc, HEADER, &mut payload)
                .unwrap();
            assert_eq!(payload, plains[idx], "out-of-order mismatch at {idx}");
        }
    }

    #[test]
    fn pipelined_replay_is_rejected() {
        let (alice_pqc, bob_pqc) = pqc_pair();
        let (alice_bank, bob_bank) = twin_banks();
        let payload = protect(&alice_bank, &alice_pqc, b"once");

        let mut first = payload.clone();
        bob_bank
            .validate_packet_in_place_split_pipelined(&bob_pqc, HEADER, &mut first)
            .unwrap();
        // Re-delivering the same chain index must fail (index already consumed / replay).
        let mut replay = payload.clone();
        assert!(bob_bank
            .validate_packet_in_place_split_pipelined(&bob_pqc, HEADER, &mut replay)
            .is_err());
    }

    #[test]
    fn pipelined_distinct_keys_per_message() {
        // Forward secrecy at the wire: the SAME plaintext+header under consecutive messages must
        // produce DIFFERENT ciphertext, proving each message used a distinct MK_i (and nonce).
        let (alice_pqc, _bob_pqc) = pqc_pair();
        let (alice_bank, _bob_bank) = twin_banks();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let payload = protect(&alice_bank, &alice_pqc, b"identical-plaintext");
            // Drop the 8-byte index trailer; compare the AEAD ciphertext (binds key + nonce).
            let ciphertext = payload[..payload.len() - 8].to_vec();
            assert!(
                seen.insert(ciphertext),
                "ciphertext repeated -> per-message key/nonce reuse"
            );
        }
    }

    #[test]
    fn pipelined_wrong_direction_fails() {
        // A chain seeded for the wrong direction (e.g. validating with the sender's own bank/role)
        // must not open the packet — direction labels separate the two chains.
        let (alice_pqc, _bob_pqc) = pqc_pair();
        let (alice_bank, _bob_bank) = twin_banks();
        let mut payload = protect(&alice_bank, &alice_pqc, b"directional");
        // alice_bank.recv chain is b2a; the packet was sealed on alice.send (a2b) -> key mismatch.
        assert!(alice_bank
            .validate_packet_in_place_split_pipelined(&alice_pqc, HEADER, &mut payload)
            .is_err());
    }
}
