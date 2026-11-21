//! The SDK side of the negotiation layer (`NEGOTIATION-LAYER.md` §2.1): the ports and adapters
//! around the pure negotiator in `citadel_negotiation` — the in-channel lane a connection's
//! negotiators speak over, the reason a deliberate drop carries, and the key-epoch adapters.

/// C7: negotiation frames bound to their connection.
pub mod bound_frame;
pub(crate) mod driver;
/// C1, C4, C5: the message floor of a negotiated key epoch.
pub mod floor;
mod handle;
/// The `KeyExchange` port: a negotiated key profile as one steered ratchet round.
pub mod key_epoch;
pub mod lane;
pub(crate) mod level_cap;
pub(crate) mod link_refusal;
pub mod reason;
pub(crate) mod refusal;
pub(crate) mod shared;

#[cfg(test)]
mod disconnect_wire_tests;
