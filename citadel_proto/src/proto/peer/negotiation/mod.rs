//! The SDK side of the negotiation layer (`NEGOTIATION-LAYER.md` §2.1): the ports and adapters
//! around the pure negotiator in `citadel_negotiation`.

/// C7: negotiation frames bound to their connection.
pub mod bound_frame;
/// C1, C4, C5: the message floor of a negotiated key epoch.
pub mod floor;
mod handle;
/// The `KeyExchange` port: a negotiated key profile as one steered ratchet round.
pub mod key_epoch;
