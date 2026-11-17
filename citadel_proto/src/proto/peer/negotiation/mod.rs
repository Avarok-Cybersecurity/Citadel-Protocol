//! The SDK side of the negotiation layer (`citadel_negotiation`): the in-channel lane a
//! connection's negotiators speak over, and the reason a deliberate drop carries.

pub(crate) mod driver;
pub mod lane;
pub mod reason;
pub(crate) mod refusal;
pub(crate) mod shared;

#[cfg(test)]
mod disconnect_wire_tests;
