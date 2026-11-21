//! What both ends of a multiplexed connection must agree on before the first subscription.
//!
//! Neither value is negotiated by netbeam itself: the layer that creates the connection knows the
//! peer's protocol version and passes the revision both ends speak, and each caller names the
//! [`Topic`] of the subscriptions it opens.

use serde::{Deserialize, Serialize};

/// How the two ends of a connection pair their subscriptions and time a synchronized start. Both
/// ends name the same revision; there is one, and a later one would be added here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WireRevision {
    /// Every subscription id is proposed by the [`Receiver`](crate::sync::RelativeNodeType) and
    /// acknowledged by the initiator, within a [`Topic`] both sides name, so a call the peer never
    /// matched cannot shift a later pairing. A synchronized start sends a delay relative to
    /// receipt, bounded by the receiver of it.
    Exchanged,
}

/// Which operation a subscription belongs to. A subscription pairs only with the peer's
/// subscription on the same topic, in the order each side opened them.
///
/// Calls that both sides always make in the same order can share [`Topic::GENERAL`]. A call that
/// one side may make while the other moves on (a readiness sync after a local success, a stage
/// that one side skips) needs a topic of its own, or it pairs with whatever the peer opens next.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Topic(u32);

impl Topic {
    /// The topic of [`Subscribable::initiate_subscription`](crate::sync::subscription::Subscribable::initiate_subscription)
    /// on a connection not scoped with `on(topic)`, and of the primitives built on it.
    pub const GENERAL: Topic = Topic(0);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}
