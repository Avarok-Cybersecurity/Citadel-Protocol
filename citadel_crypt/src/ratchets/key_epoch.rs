//! Key epochs: a negotiated key profile carried by one steered ratchet round.
//!
//! A plain rekey builds the next ratchet from the current one's layers, so it can never change the
//! security level. A key-epoch round builds it from a negotiated [`KeyProfile`] instead: the
//! current layers continue their chains, a raise appends layers whose chains are derived from the
//! current ratchet's meta-chain under a domain-separation tag, and a lower truncates. The round's
//! `AliceToBob` names the epoch and profile, and the receiving side builds it only if its own
//! negotiator agreed to exactly that ([`EpochRoundGate`]). Design: `NEGOTIATION-LAYER.md` §5.

use crate::misc::CryptError;
use citadel_io::tokio::sync::watch;
use citadel_io::Mutex;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::Epoch;
use citadel_pqcrypto::constructor_opts::{ConstructorOpts, RecursiveChain};
use citadel_types::crypto::SecurityLevel;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The domain-separation tag for the chains of layers a raised profile adds.
const LAYER_TAG: &[u8] = b"citadel-negotiation/layer";

/// The most layers a ratchet may carry (`ImpliedSecurityLevel` needs the count below `u8::MAX`).
const MAX_LAYERS: usize = u8::MAX as usize - 1;

/// The epoch a steered round builds and the profile it builds it with.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpochTag {
    pub epoch: Epoch,
    pub profile: KeyProfile,
}

pub type GateFuture = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;

/// The receiving side's check on a steered round (§5.1): resolves `true` only if this side agreed
/// to build exactly `tag` on top of `current_version`. A gate may hold the round until its
/// negotiator has seen the frame that makes it agree; it must resolve within a bound of its own.
pub trait EpochRoundGate: Send + Sync + 'static {
    fn admit(&self, tag: KeyEpochTag, current_version: u32) -> GateFuture;
}

/// The key profile a ratchet carries: its layer count is the level, and the newest layer's
/// parameters are the ones the last raise chose (for a ratchet never raised, the session's).
pub fn profile_of<R: crate::ratchets::Ratchet>(ratchet: &R) -> Result<KeyProfile, CryptError> {
    let layers = ratchet.message_ratchet_count();
    let top = layers
        .checked_sub(1)
        .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::NoMessageRatchets))?;
    let (pqc, _) = ratchet.get_message_pqc_and_entropy_bank_at_layer(Some(top))?;
    let level = u8::try_from(top)
        .map_err(|_| citadel_io::error!(citadel_io::ErrorCode::KeyEpochLayerCount, layers))?;
    Ok(KeyProfile::new(SecurityLevel::from(level), pqc.params))
}

/// The next layers' constructor options for `profile`, given `base`: the options a plain rekey
/// would use (one per current layer, each continuing its own chain). Pure: both ends compute the
/// same result from the same ratchet.
pub fn opts_for_profile(
    mut base: Vec<ConstructorOpts>,
    profile: &KeyProfile,
) -> Result<Vec<ConstructorOpts>, CryptError> {
    let layers = profile.level().value() as usize + 1;
    if layers > MAX_LAYERS {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::KeyEpochLayerCount,
            layers
        ));
    }
    if layers <= base.len() {
        base.truncate(layers);
        return Ok(base);
    }
    let meta_chain = base
        .first()
        .and_then(|opts| opts.chain.as_ref())
        .map(|chain| chain.chain)
        .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::KeyEpochChainMissing))?;
    for index in base.len()..layers {
        let chain = RecursiveChain::new(
            derive(b"chain", &meta_chain, index),
            derive(b"alice", &meta_chain, index),
            derive(b"bob", &meta_chain, index),
            false,
        )
        .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::KeyEpochChainMissing))?;
        base.push(ConstructorOpts::new_ratcheted(
            Some(profile.params()),
            chain,
        ));
    }
    Ok(base)
}

fn derive(role: &[u8], meta_chain: &[u8; 32], index: usize) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    hasher.update(LAYER_TAG);
    hasher.update(role);
    hasher.update(meta_chain);
    hasher.update((index as u64).to_be_bytes());
    hasher.finalize().into()
}

/// What one ratchet manager knows about key epochs: which stored constructors are steered, which
/// versions carry an epoch, the gate, and a signal at every round end.
pub(crate) struct EpochLedger {
    /// The tag of each steered Alice constructor this side stored, by the version it builds.
    staged: Mutex<HashMap<u32, KeyEpochTag>>,
    /// The epoch each committed version was built for. Plain versions are absent.
    built: Mutex<BTreeMap<u32, KeyEpochTag>>,
    /// Epochs the peer refused to build.
    refused: Mutex<Vec<Epoch>>,
    gate: Mutex<Option<Arc<dyn EpochRoundGate>>>,
    /// A steered round wants to start: this side's plain rekeys stand aside until it has.
    priority: AtomicBool,
    /// Bumped at the end of every round, completed or not.
    rounds: watch::Sender<u64>,
}

impl EpochLedger {
    pub(crate) fn new() -> Self {
        Self {
            staged: Mutex::new(HashMap::new()),
            built: Mutex::new(BTreeMap::new()),
            refused: Mutex::new(Vec::new()),
            gate: Mutex::new(None),
            priority: AtomicBool::new(false),
            rounds: watch::channel(0).0,
        }
    }

    pub(crate) fn stage(&self, version: u32, tag: Option<KeyEpochTag>) {
        let mut staged = self.staged.lock();
        match tag {
            Some(tag) => drop(staged.insert(version, tag)),
            None => drop(staged.remove(&version)),
        }
    }

    pub(crate) fn unstage(&self, version: u32) -> Option<KeyEpochTag> {
        self.staged.lock().remove(&version)
    }

    pub(crate) fn record_built(&self, version: u32, tag: KeyEpochTag) {
        let _ = self.built.lock().insert(version, tag);
    }

    pub(crate) fn built(&self, version: u32) -> Option<KeyEpochTag> {
        self.built.lock().get(&version).copied()
    }

    /// The newest epoch any committed version carries.
    pub(crate) fn latest_built(&self) -> Option<KeyEpochTag> {
        self.built.lock().values().next_back().copied()
    }

    /// The version that carries `epoch`, while the toolset still holds it.
    pub(crate) fn version_of(&self, epoch: Epoch) -> Option<(u32, KeyEpochTag)> {
        self.built
            .lock()
            .iter()
            .find(|(_, tag)| tag.epoch == epoch)
            .map(|(version, tag)| (*version, *tag))
    }

    pub(crate) fn record_refused(&self, epoch: Epoch) {
        self.refused.lock().push(epoch);
    }

    pub(crate) fn take_refused(&self, epoch: Epoch) -> bool {
        let mut refused = self.refused.lock();
        let before = refused.len();
        refused.retain(|e| *e != epoch);
        refused.len() != before
    }

    /// Forgets what no longer matters once `completed` is the newest finished version. A version
    /// above it was committed by a round that did not complete; the toolset drops it at the next
    /// commit, so its epoch record goes too.
    pub(crate) fn round_ended(&self, completed: u32, oldest_kept: u32) {
        self.staged.lock().retain(|version, _| *version > completed);
        self.built
            .lock()
            .retain(|version, _| (oldest_kept..=completed).contains(version));
        self.rounds.send_modify(|n| *n = n.wrapping_add(1));
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.rounds.subscribe()
    }

    pub(crate) fn set_gate(&self, gate: Arc<dyn EpochRoundGate>) {
        *self.gate.lock() = Some(gate);
    }

    pub(crate) fn gate(&self) -> Option<Arc<dyn EpochRoundGate>> {
        self.gate.lock().clone()
    }

    pub(crate) fn has_priority(&self) -> bool {
        self.priority.load(Ordering::SeqCst)
    }

    pub(crate) fn claim_priority(self: &Arc<Self>) -> PriorityClaim {
        self.priority.store(true, Ordering::SeqCst);
        PriorityClaim(self.clone())
    }
}

/// Holds this side's plain rekeys back while a steered round waits to start.
pub(crate) struct PriorityClaim(Arc<EpochLedger>);

impl Drop for PriorityClaim {
    fn drop(&mut self) {
        self.0.priority.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::crypto::CryptoParameters;

    fn base(layers: usize) -> Vec<ConstructorOpts> {
        let chain = RecursiveChain::new([7u8; 32], [8u8; 32], [9u8; 32], false).unwrap();
        (0..layers)
            .map(|_| {
                ConstructorOpts::new_ratcheted(Some(CryptoParameters::default()), chain.clone())
            })
            .collect()
    }

    fn profile(level: SecurityLevel) -> KeyProfile {
        KeyProfile::new(level, CryptoParameters::default())
    }

    #[test]
    fn a_raise_appends_derived_layers_and_keeps_the_current_ones() {
        let opts = opts_for_profile(base(2), &profile(SecurityLevel::Extreme)).unwrap();
        assert_eq!(opts.len(), 5);
        let chains: Vec<[u8; 32]> = opts
            .iter()
            .map(|o| o.chain.as_ref().unwrap().chain)
            .collect();
        assert_eq!(chains[0], [7u8; 32]);
        assert_eq!(chains[1], [7u8; 32]);
        for (i, chain) in chains.iter().enumerate().skip(2) {
            assert_ne!(*chain, [7u8; 32], "layer {i} must not reuse the meta-chain");
            assert!(chains.iter().filter(|c| *c == chain).count() == 1);
        }
    }

    #[test]
    fn both_ends_derive_the_same_layers() {
        let a = opts_for_profile(base(1), &profile(SecurityLevel::High)).unwrap();
        let b = opts_for_profile(base(1), &profile(SecurityLevel::High)).unwrap();
        let bytes = |opts: &[ConstructorOpts]| -> Vec<[u8; 32]> {
            opts.iter()
                .flat_map(|o| {
                    let c = o.chain.as_ref().unwrap();
                    [c.chain, c.alice, c.bob]
                })
                .collect()
        };
        assert_eq!(bytes(&a), bytes(&b));
    }

    #[test]
    fn a_lower_truncates() {
        let opts = opts_for_profile(base(5), &profile(SecurityLevel::Reinforced)).unwrap();
        assert_eq!(opts.len(), 2);
    }

    #[test]
    fn a_profile_beyond_the_layer_limit_is_refused() {
        let Err(err) = opts_for_profile(base(1), &profile(SecurityLevel::Custom(u8::MAX))) else {
            panic!("a 256-layer profile must be refused");
        };
        assert_eq!(err.code, citadel_io::ErrorCode::KeyEpochLayerCount);
    }

    #[test]
    fn a_raise_without_a_chain_is_refused() {
        let opts = vec![ConstructorOpts::new_init(Some(CryptoParameters::default()))];
        let Err(err) = opts_for_profile(opts, &profile(SecurityLevel::High)) else {
            panic!("a raise without a chain must be refused");
        };
        assert_eq!(err.code, citadel_io::ErrorCode::KeyEpochChainMissing);
    }
}
