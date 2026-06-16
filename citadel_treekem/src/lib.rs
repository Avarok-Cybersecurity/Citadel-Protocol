//! # citadel_treekem
//!
//! A post-quantum **TreeKEM** Continuous Group Key Agreement (CGKA) for zero-trust Citadel group
//! messaging. Members are leaves of a left-balanced binary ratchet tree of ML-KEM keypairs; each
//! membership change or update re-keys a single root-ward path (O(log n)), and everyone derives the
//! same per-epoch group secret **end-to-end** — the relay server never sees a key or plaintext.
//!
//! Post-quantum throughout: node keypairs are deterministically derived from path secrets via
//! [`citadel_pqcrypto::kem_keypair_from_seed`] (ML-KEM), path secrets are HPKE-sealed with ML-KEM +
//! ChaCha20-Poly1305, and the key schedule uses SHA3/BLAKE3 — reusing Citadel's own crypto abstractions.
//!
//! Status: **M1** — tree + path ratchet + key schedule + `commit`/`process_commit` (the CGKA core).
//! Add/Remove/Welcome (M2), the application-message ratchet bridge (M3), and the hierarchy overlay (M4)
//! land in subsequent milestones.

#![forbid(unsafe_code)]

pub mod application;
pub mod commit;
pub mod crypto;
pub mod group;
pub mod hierarchy;
pub mod keys;
pub mod path;
pub mod schedule;
pub mod tree;
pub mod welcome;

pub use application::AppCiphertext;
pub use commit::{Commit, Proposal};
pub use group::GroupState;
pub use hierarchy::{CommandPath, DheEnvelope, HierarchyScheme, KdfKemTree, ReadPolicy};
pub use keys::KeyPackage;
pub use path::UpdatePath;
pub use tree::{math, node, ratchet_tree};
pub use welcome::Welcome;
