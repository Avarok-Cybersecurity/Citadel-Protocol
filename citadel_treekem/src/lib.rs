//! # citadel_treekem
//!
//! A post-quantum **TreeKEM** Continuous Group Key Agreement (CGKA) for zero-trust Citadel group
//! messaging. Members are leaves of a left-balanced binary ratchet tree of ML-KEM keypairs; each
//! membership change re-keys a single root-ward path (O(log n)) and everyone derives the same
//! per-epoch group secret **end-to-end** — the relay server never sees a key or plaintext.
//!
//! Post-quantum throughout: node keypairs are deterministically derived from path secrets via
//! [`citadel_pqcrypto::kem_keypair_from_seed`] (ML-KEM), path secrets are encapsulated with ML-KEM,
//! and the key schedule uses SHA3/BLAKE3 — reusing Citadel's own crypto abstractions.
//!
//! Status: **M0** — tree math + node model. Path secrets, key schedule, commit/welcome, and the
//! application-message bridge land in subsequent milestones (see the plan).

#![forbid(unsafe_code)]

pub mod tree;

pub use tree::math;
