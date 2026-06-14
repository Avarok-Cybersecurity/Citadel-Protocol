//! Forward-secure symmetric KDF chain — the per-message forward-secrecy primitive for the pipelined
//! PFS mode (`docs/pfs-symmetric-ratchet-design.md`).
//!
//! Each ratchet version + direction owns a chain seeded from that version's KEM shared secret. Message
//! index `i` yields a distinct 32-byte AEAD key `MK_i = KDF(CK_i)`; the chain then advances
//! `CK_{i+1} = KDF(CK_i)` and `CK_i` is overwritten/zeroized. Because the KDF is one-way and past chain
//! keys are destroyed, an attacker who captures the chain state at index `j` can derive `MK_j, MK_{j+1},
//! …` (future, until the next periodic KEM rekey heals) but **cannot** derive any `MK_{<j}` — i.e.
//! forward secrecy is preserved without a per-message network round-trip.
//!
//! The two KDF legs (`MK` vs chain-advance) and the seed use distinct BLAKE3 `derive_key` contexts for
//! domain separation. The receiver tolerates out-of-order delivery via a bounded skipped-key cache
//! (`max_skip`) so a forged far-future index cannot force unbounded key derivation (DoS bound).

use std::collections::HashMap;
use zeroize::Zeroizing;

// Application-unique BLAKE3 derive_key contexts (domain separation). Never reuse across KDF legs.
const SEED_CONTEXT: &str = "avarok.citadel symmetric-ratchet 2025-06 chain seed v1";
const ADVANCE_CONTEXT: &str = "avarok.citadel symmetric-ratchet 2025-06 chain advance v1";
const MSGKEY_CONTEXT: &str = "avarok.citadel symmetric-ratchet 2025-06 message-key v1";

/// A 32-byte per-message AEAD key, zeroized on drop.
pub type MessageKey = Zeroizing<[u8; 32]>;

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The requested index was already consumed and its key (if cached) evicted — it cannot be
    /// re-derived (forward secrecy: past chain keys are destroyed).
    AlreadyConsumed(u64),
    /// The forward gap from the current index exceeds `max_skip`; rejected to bound out-of-order work.
    SkipTooLarge {
        requested: u64,
        current: u64,
        max_skip: u64,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::AlreadyConsumed(i) => {
                write!(f, "message-chain index {i} already consumed (cannot re-derive)")
            }
            ChainError::SkipTooLarge { requested, current, max_skip } => write!(
                f,
                "message-chain skip too large: requested {requested}, current {current}, max_skip {max_skip}"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// A one-directional forward-secure symmetric ratchet chain. A sender uses [`Self::next_send_key`];
/// the matching receiver uses [`Self::recv_key`]. Both sides seed identically from the same root +
/// direction label, so `MK_i` agrees on both ends.
pub struct SymmetricChain {
    /// `CK` at position `next_index`.
    chain_key: Zeroizing<[u8; 32]>,
    /// Next index this chain will produce (sender) / expects in order (receiver).
    next_index: u64,
    /// Receiver-only: message keys derived for indices that arrived out of order, awaiting their
    /// packet. Bounded by `max_skip` per call; callers should also cap total retained entries.
    skipped: HashMap<u64, MessageKey>,
}

impl SymmetricChain {
    /// Seed a chain from a 32-byte `root` (the per-version KEM shared secret), domain-separated by
    /// `direction_label` (e.g. `b"a2b"` / `b"b2a"`) so the two directions never share key material.
    /// Both endpoints compute the same chain for a given direction.
    pub fn new(root: &[u8; 32], direction_label: &[u8]) -> Self {
        // Zeroizing buffer so the transient copy of the secret root is wiped after seeding.
        let mut seed_input: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(32 + direction_label.len()));
        seed_input.extend_from_slice(root);
        seed_input.extend_from_slice(direction_label);
        let ck = blake3::derive_key(SEED_CONTEXT, &seed_input);
        Self {
            chain_key: Zeroizing::new(ck),
            next_index: 0,
            skipped: HashMap::new(),
        }
    }

    #[inline]
    fn message_key(ck: &[u8; 32]) -> MessageKey {
        Zeroizing::new(blake3::derive_key(MSGKEY_CONTEXT, ck))
    }

    #[inline]
    fn advanced(ck: &[u8; 32]) -> [u8; 32] {
        blake3::derive_key(ADVANCE_CONTEXT, ck)
    }

    /// Advance the chain one step in place, zeroizing the consumed chain key, and return the message
    /// key for the index that was current before the step.
    fn step(&mut self) -> MessageKey {
        let mk = Self::message_key(&self.chain_key);
        let next = Self::advanced(&self.chain_key);
        // Reassigning the `Zeroizing` drops (zeroizes) the previous chain key.
        self.chain_key = Zeroizing::new(next);
        self.next_index = self.next_index.wrapping_add(1);
        mk
    }

    /// The next index this chain will emit.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Sender: derive the message key for the next index and advance the chain.
    pub fn next_send_key(&mut self) -> (u64, MessageKey) {
        let idx = self.next_index;
        let mk = self.step();
        (idx, mk)
    }

    /// Receiver: derive (or fetch from the skipped cache) the message key for index `i`. Advances the
    /// chain over any gap, caching the skipped indices' keys. Errors if the forward gap exceeds
    /// `max_skip`, or if `i` was already consumed and is not cached.
    pub fn recv_key(&mut self, i: u64, max_skip: u64) -> Result<MessageKey, ChainError> {
        if let Some(mk) = self.skipped.remove(&i) {
            return Ok(mk);
        }
        if i < self.next_index {
            return Err(ChainError::AlreadyConsumed(i));
        }
        let gap = i - self.next_index;
        if gap > max_skip {
            return Err(ChainError::SkipTooLarge {
                requested: i,
                current: self.next_index,
                max_skip,
            });
        }
        // Advance over the gap [next_index, i), caching each skipped key.
        while self.next_index < i {
            let idx = self.next_index;
            let mk = self.step();
            let _ = self.skipped.insert(idx, mk);
        }
        // next_index == i: produce its key and advance past it.
        Ok(self.step())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A2B: &[u8] = b"a2b";
    const MAX_SKIP: u64 = 1024;

    fn key_bytes(mk: &MessageKey) -> [u8; 32] {
        **mk
    }

    #[test]
    fn sender_receiver_agree_in_order() {
        let root = [7u8; 32];
        let mut send = SymmetricChain::new(&root, A2B);
        let mut recv = SymmetricChain::new(&root, A2B);
        for expected_idx in 0..1000u64 {
            let (idx, smk) = send.next_send_key();
            assert_eq!(idx, expected_idx);
            let rmk = recv.recv_key(idx, MAX_SKIP).unwrap();
            assert_eq!(key_bytes(&smk), key_bytes(&rmk), "key mismatch at {idx}");
        }
    }

    #[test]
    fn all_message_keys_distinct() {
        let root = [9u8; 32];
        let mut send = SymmetricChain::new(&root, A2B);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let (_, mk) = send.next_send_key();
            assert!(seen.insert(key_bytes(&mk)), "duplicate message key");
        }
    }

    #[test]
    fn out_of_order_within_window() {
        let root = [1u8; 32];
        let mut send = SymmetricChain::new(&root, A2B);
        let mut recv = SymmetricChain::new(&root, A2B);
        let sent: Vec<_> = (0..50).map(|_| send.next_send_key()).collect();
        // Deliver receiver keys in a shuffled-ish order (5,4,3,...,0 then 6..49).
        for i in (0..6u64).rev() {
            let rmk = recv.recv_key(i, MAX_SKIP).unwrap();
            assert_eq!(key_bytes(&rmk), key_bytes(&sent[i as usize].1));
        }
        for i in 6..50u64 {
            let rmk = recv.recv_key(i, MAX_SKIP).unwrap();
            assert_eq!(key_bytes(&rmk), key_bytes(&sent[i as usize].1));
        }
    }

    #[test]
    fn consumed_index_cannot_be_rederived() {
        // Forward secrecy at the API surface: once an index is consumed (and not cached), its key is
        // gone — the chain cannot reproduce a past key from a later chain state.
        let root = [3u8; 32];
        let mut recv = SymmetricChain::new(&root, A2B);
        let _ = recv.recv_key(10, MAX_SKIP).unwrap(); // consumes 0..=10 (0..10 cached, 10 returned)
                                                      // index 10 was returned (not cached) -> re-request must fail.
        assert_eq!(
            recv.recv_key(10, MAX_SKIP),
            Err(ChainError::AlreadyConsumed(10))
        );
        // a cached skipped index (say 5) is retrievable exactly once...
        assert!(recv.recv_key(5, MAX_SKIP).is_ok());
        // ...and not twice.
        assert_eq!(
            recv.recv_key(5, MAX_SKIP),
            Err(ChainError::AlreadyConsumed(5))
        );
    }

    #[test]
    fn skip_too_large_is_rejected() {
        let root = [4u8; 32];
        let mut recv = SymmetricChain::new(&root, A2B);
        let err = recv.recv_key(MAX_SKIP + 1, MAX_SKIP).unwrap_err();
        assert!(matches!(err, ChainError::SkipTooLarge { .. }));
        // The chain did not advance on rejection (DoS bound holds).
        assert_eq!(recv.next_index(), 0);
    }

    #[test]
    fn direction_label_separates_chains() {
        let root = [5u8; 32];
        let mut a2b = SymmetricChain::new(&root, b"a2b");
        let mut b2a = SymmetricChain::new(&root, b"b2a");
        assert_ne!(
            key_bytes(&a2b.next_send_key().1),
            key_bytes(&b2a.next_send_key().1)
        );
    }

    #[test]
    fn distinct_roots_give_distinct_keys() {
        let mut c1 = SymmetricChain::new(&[1u8; 32], A2B);
        let mut c2 = SymmetricChain::new(&[2u8; 32], A2B);
        assert_ne!(
            key_bytes(&c1.next_send_key().1),
            key_bytes(&c2.next_send_key().1)
        );
    }
}
