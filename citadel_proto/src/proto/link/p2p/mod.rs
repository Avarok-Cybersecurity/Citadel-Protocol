//! The P2P establisher: today's attempt split into its three steps (§1.2, §8).
//!
//! - **path** ([`direct`]): the hole punch and the QUIC handshake over it, from the
//!   attempt body of `attempt_simultaneous_hole_punch`;
//! - **seal** ([`wrap`]): the QUIC connection wrapped into the session's framing, bound to
//!   the P2P connection the key exchange made;
//! - **deliver** ([`attach`]): the wrapped route attached to that connection, with the tasks
//!   that carry it and report its end.
//!
//! `handle_p2p_stream` is now `attach(wrap(..))`, so the campaign (`LinkManagerMode::Legacy`)
//! and the manager run one implementation of each step.

#[cfg(not(target_family = "wasm"))]
pub(crate) mod attach;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod direct;
#[cfg(not(target_family = "wasm"))]
mod disconnect_task;
#[cfg(not(target_family = "wasm"))]
mod stream_end;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod turn;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod wrap;
