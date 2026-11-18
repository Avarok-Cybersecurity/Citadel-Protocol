//! The `KeyExchange` port over a P2P connection's ratchet manager (§2.1, §5).
//!
//! The negotiator (N0) decides; this adapter carries the key profile out. Only the Leader issues
//! `Command::ApplyKeyEpoch` (D2), which becomes one steered round
//! ([`KeyExchange::apply`]). On the other side the round reaches the ratchet manager, which asks
//! the gate installed here; the gate asks the negotiator (`admit_key_round`) and holds a round
//! the negotiator answers with `Wait` until a later step lets it agree, bounded by the apply
//! deadline. A round it builds is reported to the shell as an [`AdmittedRound`], whose outcome
//! ([`KeyEpochPort::round_outcome`]) the shell feeds back as `Input::KeyOutcome`.

use super::floor::Floor;
pub use super::handle::KeyEpochHandle;
use citadel_crypt::ratchets::key_epoch::{EpochRoundGate, GateFuture, KeyEpochTag};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Notify;
use citadel_negotiation::ports::{BoxFuture, KeyExchange};
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{
    ConnectionId, Epoch, KeyExchangeOutcome, NegotiationPolicy, RoundAdmission,
};
use std::sync::Arc;
use std::time::Duration;

/// What the gate asks of the negotiator: `Negotiator::admit_key_round`.
pub trait RoundAdmitter: Send + Sync + 'static {
    fn admit_key_round(&self, epoch: Epoch, profile: &KeyProfile) -> RoundAdmission;
}

/// A steered round this side admitted and is building on top of version `from`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRound {
    pub tag: KeyEpochTag,
    pub from: u32,
}

/// The `KeyExchange` port of one connection.
pub struct KeyEpochPort<R: Ratchet> {
    handle: KeyEpochHandle<R>,
    apply_deadline: Duration,
}

impl<R: Ratchet> KeyEpochPort<R> {
    /// The policy's apply deadline bounds every wait here, so no future outlives the negotiator.
    pub fn new(handle: KeyEpochHandle<R>, policy: &NegotiationPolicy) -> Self {
        Self {
            handle,
            apply_deadline: policy.apply_deadline,
        }
    }

    pub fn handle(&self) -> &KeyEpochHandle<R> {
        &self.handle
    }

    /// Installs the Bob-side check. `stepped` must be notified (`notify_waiters`) after every
    /// step of the negotiator, which is what releases a held round.
    pub fn install_gate(
        &self,
        admitter: Arc<dyn RoundAdmitter>,
        stepped: Arc<Notify>,
    ) -> UnboundedReceiver<AdmittedRound> {
        let (admitted, rounds) = unbounded_channel();
        self.handle.manager.set_epoch_gate(Arc::new(NegotiatorGate {
            admitter,
            stepped,
            admitted,
            hold_bound: self.apply_deadline,
        }));
        rounds
    }

    /// How an admitted round ended, as the Loser feeds it to its negotiator.
    pub fn round_outcome(&self, round: AdmittedRound) -> BoxFuture<'static, KeyExchangeOutcome> {
        let manager = self.handle.manager.clone();
        let bound = self.apply_deadline;
        Box::pin(async move {
            citadel_io::time::timeout(bound, manager.await_epoch_round(round.tag, round.from))
                .await
                .unwrap_or_else(|_| KeyExchangeOutcome::Failed("the key round did not end".into()))
        })
    }

    /// `Command::RaiseFloor { epoch }`: the peer retired everything before `epoch`, so message
    /// frames under older versions or below its level are refused. `false` when the toolset no
    /// longer knows which version carries `epoch`.
    pub fn raise_floor(&self, epoch: Epoch) -> bool {
        let Some((version, tag)) = self.handle.manager.version_of_epoch(epoch) else {
            return false;
        };
        self.handle.floor.raise(Floor {
            version,
            level: tag.profile.level(),
        });
        true
    }

    fn wrong_connection(&self, conn: ConnectionId) -> Option<String> {
        (conn != self.handle.connection)
            .then(|| format!("asked for connection {conn:?}, this port serves another"))
    }
}

impl<R: Ratchet> KeyExchange for KeyEpochPort<R> {
    fn apply(
        &self,
        conn: ConnectionId,
        epoch: Epoch,
        profile: KeyProfile,
    ) -> BoxFuture<'static, KeyExchangeOutcome> {
        if let Some(err) = self.wrong_connection(conn) {
            return Box::pin(async move { KeyExchangeOutcome::Failed(err) });
        }
        let manager = self.handle.manager.clone();
        let tag = KeyEpochTag { epoch, profile };
        let bound = self.apply_deadline;
        Box::pin(async move {
            let round = async {
                match manager.trigger_rekey_with_profile(tag).await {
                    Ok(from) => manager.await_epoch_round(tag, from).await,
                    Err(err) => KeyExchangeOutcome::Failed(err.into_string()),
                }
            };
            citadel_io::time::timeout(bound, round)
                .await
                .unwrap_or_else(|_| KeyExchangeOutcome::Failed("the key round did not end".into()))
        })
    }

    fn negotiated(&self, conn: ConnectionId) -> Option<KeyProfile> {
        self.wrong_connection(conn)
            .is_none()
            .then(|| self.handle.negotiated())?
    }
}

/// The Bob-side check on a steered round, over the negotiator (§5.1).
struct NegotiatorGate {
    admitter: Arc<dyn RoundAdmitter>,
    stepped: Arc<Notify>,
    admitted: UnboundedSender<AdmittedRound>,
    hold_bound: Duration,
}

impl EpochRoundGate for NegotiatorGate {
    fn admit(&self, tag: KeyEpochTag, current_version: u32) -> GateFuture {
        let admitter = self.admitter.clone();
        let stepped = self.stepped.clone();
        let admitted = self.admitted.clone();
        let hold = async move {
            loop {
                // Registered before asking, so a step between the answer and the wait wakes it.
                let next_step = stepped.notified();
                citadel_io::tokio::pin!(next_step);
                next_step.as_mut().enable();
                match admitter.admit_key_round(tag.epoch, &tag.profile) {
                    RoundAdmission::Build => {
                        let round = AdmittedRound {
                            tag,
                            from: current_version,
                        };
                        return admitted.send(round).is_ok();
                    }
                    RoundAdmission::Refuse => return false,
                    RoundAdmission::Wait => next_step.await,
                }
            }
        };
        let bound = self.hold_bound;
        Box::pin(async move {
            citadel_io::time::timeout(bound, hold)
                .await
                .unwrap_or(false)
        })
    }
}
