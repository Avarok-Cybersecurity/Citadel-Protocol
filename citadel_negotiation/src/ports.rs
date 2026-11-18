//! The only ways a shell around the core touches the world (§2.2). The core never calls these;
//! a shell turns each [`Command`](crate::Command) into a port call and each result back into an
//! [`Input`](crate::Input). One definition for the SDK adapters and the agent shell.

use crate::frame::Envelope;
use crate::ids::{Cid, ConnectionId, Epoch, Millis, SettingId};
use crate::io::{KeyExchangeOutcome, NegotiationEvent};
use crate::settings::KeyProfile;
use std::future::Future;
use std::pin::Pin;

/// A persisted epoch and the agreed value's bytes.
pub type StoredEpoch = Option<(Epoch, Vec<u8>)>;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Time. The shell reads it and passes it to `step`; it schedules `Input::Tick` at `next_wake`.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Millis;
    fn sleep_until(&self, at: Millis) -> BoxFuture<'static, ()>;
}

/// A frame the lane would not take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendError(pub String);

/// Delivery of one envelope to the peer. `Err` becomes `Input::SendFailed`.
pub trait SignalPort: Send + Sync + 'static {
    fn send(
        &self,
        conn: ConnectionId,
        envelope: Envelope,
    ) -> BoxFuture<'static, Result<(), SendError>>;
}

/// The apply step for the key profile: one steered ratchet round (lane SDK2).
pub trait KeyExchange: Send + Sync + 'static {
    fn apply(
        &self,
        conn: ConnectionId,
        epoch: Epoch,
        profile: KeyProfile,
    ) -> BoxFuture<'static, KeyExchangeOutcome>;
    /// The profile the channel's current ratchet carries (SDK1's getter).
    fn negotiated(&self, conn: ConnectionId) -> Option<KeyProfile>;
}

/// The apply step for a setting applied locally; the result becomes `Input::LocalOutcome`.
pub trait LocalApply<S>: Send + Sync + 'static {
    fn apply(
        &self,
        conn: ConnectionId,
        epoch: Epoch,
        value: S,
    ) -> BoxFuture<'static, Result<(), String>>;
}

/// The last agreed value of a `PERSIST` setting, so a restart cannot reopen a peer below it.
pub trait EpochStore: Send + Sync + 'static {
    fn load(
        &self,
        peer: Cid,
        setting: SettingId,
    ) -> BoxFuture<'static, Result<StoredEpoch, String>>;
    fn save(
        &self,
        peer: Cid,
        setting: SettingId,
        epoch: Epoch,
        value: Vec<u8>,
    ) -> BoxFuture<'static, Result<(), String>>;
}

/// Tells the account's windows (agent) or the kernel (SDK).
pub trait Reporter<S>: Send + Sync + 'static {
    fn report(&self, conn: ConnectionId, event: NegotiationEvent<S>);
}
