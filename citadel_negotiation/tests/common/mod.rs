//! Shared test fixtures: a policy, configs, a three-value ordered test setting, key profiles.
#![allow(dead_code)]

use citadel_negotiation::schedule::{Side, World};
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{
    ApplyPath, NegotiationPolicy, NegotiationState, NegotiatorConfig, PeerSupport, Setting,
    SettingId,
};
use citadel_types::crypto::{
    CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel, SigAlgorithm,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const A: u64 = 1;
pub const B: u64 = 2;

/// Test rationale (PCND): the scheduler jumps each clock straight to the next deadline, so the
/// lengths only need to be non-zero and equal on both sides; three attempts lets the superseded
/// test see a re-issue succeed and an exhausted budget fail.
pub fn policy() -> NegotiationPolicy {
    NegotiationPolicy {
        proposal_deadline: Duration::from_secs(1),
        apply_deadline: Duration::from_secs(1),
        max_apply_attempts: 3,
        udp_retire_grace: None,
    }
}

pub fn config<S: Setting>(
    local: u64,
    initial: S,
    minimum: S,
    support: PeerSupport,
) -> NegotiatorConfig<S> {
    let peer = if local == A { B } else { A };
    NegotiatorConfig {
        local,
        peer,
        initial,
        minimum,
        support,
        policy: policy(),
    }
}

/// A world of A (cid 1, the Leader) and B (cid 2), both in band, minimum = the initial value.
pub fn world<S: Setting>(initial: S, follow_minimum: bool) -> World<S> {
    world_with_minimums(initial.clone(), initial.clone(), initial, follow_minimum)
}

pub fn world_with_minimums<S: Setting>(initial: S, min_a: S, min_b: S, follow: bool) -> World<S> {
    let a = config(A, initial.clone(), min_a, PeerSupport::InBand);
    let b = config(B, initial, min_b, PeerSupport::InBand);
    World::new(a, b, follow)
}

/// Three ordered values, applied locally: the exhaustive test's setting.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tier(pub u8);

impl Setting for Tier {
    const ID: SettingId = SettingId(900);
    const PERSIST: bool = false;
    fn merge(leader: &Self, loser: &Self) -> Self {
        Tier(leader.0.max(loser.0))
    }
    fn is_downgrade(from: &Self, to: &Self) -> Option<bool> {
        Some(to.0 < from.0)
    }
    fn path(_from: &Self, _to: &Self) -> ApplyPath {
        ApplyPath::InBandLocal
    }
    fn is_supported(&self) -> bool {
        self.0 < 3
    }
}

/// The suite these worlds start from; a change of KEM is measured against it.
pub const BASE_PARAMS: CryptoParameters = CryptoParameters::new(
    EncryptionAlgorithm::AES_GCM_256,
    KemAlgorithm::MlKem,
    SigAlgorithm::None,
);

pub fn profile(level: SecurityLevel) -> KeyProfile {
    KeyProfile::new(level, BASE_PARAMS)
}

pub fn states<S: Setting>(world: &World<S>, side: Side) -> Vec<NegotiationState<S>> {
    world
        .party(side)
        .events
        .iter()
        .map(|event| event.state.clone())
        .collect()
}

pub fn applied_count<S: Setting>(world: &World<S>, side: Side) -> usize {
    states(world, side)
        .iter()
        .filter(|s| matches!(s, NegotiationState::Applied { .. }))
        .count()
}

/// Every crypto suite the packed byte can name.
pub fn suites() -> Vec<CryptoParameters> {
    (0..=u8::MAX)
        .filter_map(|byte| CryptoParameters::try_from(byte).ok())
        .collect()
}
