//! The ratchet manager's half of a negotiated key epoch (§5.1-5.2): the receiving side's gate,
//! the record of which version each epoch built, refusals, and how one round ended.

use super::{AttachedPayload, RekeyMetadata};
use super::{RatchetManager, RatchetManagerSink, RatchetManagerStream, RatchetMessage};
use crate::misc::CryptError;
use crate::ratchets::key_epoch::{EpochRoundGate, KeyEpochTag};
use crate::ratchets::Ratchet;
use citadel_negotiation::{Epoch, KeyExchangeOutcome};
use futures::SinkExt;
use std::sync::Arc;

/// Turns a steered `AliceToBob` into a plain one plus its tag, so one arm handles both.
pub(super) fn split_epoch_round<P>(
    msg: Option<RatchetMessage<P>>,
) -> (Option<RatchetMessage<P>>, Option<KeyEpochTag>) {
    match msg {
        Some(RatchetMessage::EpochAliceToBob {
            payload,
            earliest_ratchet_version,
            latest_ratchet_version,
            metadata,
            epoch,
        }) => (
            Some(RatchetMessage::AliceToBob {
                payload,
                earliest_ratchet_version,
                latest_ratchet_version,
                attached_payload: None,
                metadata,
            }),
            Some(epoch),
        ),
        other => (other, None),
    }
}

impl<S, I, R, P> RatchetManager<S, I, R, P>
where
    S: RatchetManagerSink<P>,
    I: RatchetManagerStream<P>,
    R: Ratchet,
    P: AttachedPayload,
{
    /// Installs the check this side makes before building a steered round. Without one, every
    /// steered round is refused: a round can never build a profile nobody negotiated.
    pub fn set_epoch_gate(&self, gate: Arc<dyn EpochRoundGate>) {
        self.epochs.set_gate(gate);
    }

    /// The epoch toolset version `version` was built for; `None` for a plain version.
    pub fn epoch_of(&self, version: u32) -> Option<KeyEpochTag> {
        self.epochs.built(version)
    }

    /// The newest epoch any version still in the toolset was built for.
    pub fn latest_epoch(&self) -> Option<KeyEpochTag> {
        self.epochs.latest_built()
    }

    /// How the round that builds `tag` on top of version `from` ended, on either side: the
    /// first version after `from` either carries the epoch (`Applied`) or does not, because a
    /// plain rekey took that version (`Superseded`); or the peer refused the round. Resolves
    /// `Failed` if the rekey process ends first. The caller bounds the wait.
    pub async fn await_epoch_round(&self, tag: KeyEpochTag, from: u32) -> KeyExchangeOutcome {
        let mut round_ends = self.epochs.subscribe();
        loop {
            if self.epochs.take_refused(tag.epoch) {
                return KeyExchangeOutcome::Refused(format!("epoch {:?}", tag.epoch));
            }
            let version = from.wrapping_add(1);
            if self.session_crypto_state.latest_usable_version() >= version {
                return match self.epochs.built(version) {
                    Some(built) if built == tag => KeyExchangeOutcome::Applied { version },
                    _ => KeyExchangeOutcome::Superseded { version },
                };
            }
            if round_ends.changed().await.is_err() {
                return KeyExchangeOutcome::Failed("the rekey process ended".into());
            }
        }
    }

    /// Asks the gate; a refusal is answered so the steered side's round ends at once.
    pub(super) async fn admit_epoch_round(
        &self,
        tag: KeyEpochTag,
        metadata: RekeyMetadata,
    ) -> Result<bool, CryptError> {
        let admitted = match self.epochs.gate() {
            Some(gate) => gate.admit(tag, metadata.current_version).await,
            None => false,
        };
        if !admitted {
            log::warn!(target: "citadel", "Client {} refusing a steered round for epoch {:?}", self.cid, tag.epoch);
            self.sender
                .lock()
                .await
                .send(RatchetMessage::EpochRefused {
                    metadata,
                    epoch: tag.epoch,
                })
                .await
                .map_err(|_| citadel_io::error!(citadel_io::ErrorCode::RekeySinkSendError))?;
        }
        Ok(admitted)
    }

    /// The version just committed was built for `tag`.
    pub(super) fn record_built_epoch(&self, tag: KeyEpochTag) {
        let version = self
            .session_crypto_state
            .toolset()
            .read()
            .get_most_recent_ratchet_version();
        self.epochs.record_built(version, tag);
    }

    /// The peer refused our steered round for `epoch`: drop its constructor. `false` for a
    /// refusal of a round this side no longer has.
    pub(super) fn on_epoch_refused(&self, metadata: RekeyMetadata, epoch: Epoch) -> bool {
        let next_version = metadata.next_version;
        let ours = self
            .epochs
            .unstage(next_version)
            .filter(|tag| tag.epoch == epoch);
        if ours.is_none() {
            return false;
        }
        let _ = self.constructors.lock().remove(&next_version);
        self.epochs.record_refused(epoch);
        true
    }

    pub(super) fn publish_round_end(&self) {
        let latest = self.session_crypto_state.latest_usable_version();
        let oldest = self
            .session_crypto_state
            .toolset()
            .read()
            .get_oldest_ratchet_version();
        self.epochs.round_ended(latest, oldest);
    }
}
