use super::*;
use crate::constants::PROTOCOL_VERSION;
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use citadel_types::proto::{PathClasses, PathRule};
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;
use std::time::Duration;

fn policy() -> PathPolicy {
    let rules = PathKind::ALL
        .into_iter()
        .map(|kind| PathRule {
            kind,
            enabled: true,
            attempt_timeout: Duration::from_secs(9),
            cost_weight: 1,
            classes: PathClasses::ALL,
        })
        .collect();
    PathPolicy::new(rules, PathClasses::NONE).unwrap()
}

const OPEN: PathOffer = PathOffer {
    restrictions: PathRestrictions::NONE,
    turn_ready: true,
};
const DIRECT_OK: PairFeasibility = PairFeasibility {
    direct: true,
    forwarder: None,
};

fn both() -> KexPath {
    KexPath {
        initiator: Some(OPEN),
        responder: Some(OPEN),
        plan: None,
    }
}

#[test]
fn the_server_stamps_a_plan_only_with_both_offers_and_a_policy() {
    let stamped = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK)).unwrap();
    let kinds: Vec<_> = stamped.plan.unwrap().paths.iter().map(|p| p.kind).collect();
    assert_eq!(
        kinds,
        [PathKind::Direct, PathKind::Turn, PathKind::ServerRelay]
    );

    let stage0 = KexPath {
        responder: None,
        ..both()
    };
    let relayed = stamp(Some(&policy()), Some(stage0), || Some(DIRECT_OK)).unwrap();
    assert_eq!(
        relayed.plan, None,
        "Stage0 carries one offer: nothing to stamp"
    );
    assert_eq!(relayed.initiator, Some(OPEN), "the offer is relayed");

    let no_policy = stamp(None, Some(both()), || Some(DIRECT_OK)).unwrap();
    assert_eq!(no_policy.plan, None);
    let target_gone = stamp(Some(&policy()), Some(both()), || None).unwrap();
    assert_eq!(target_gone.plan, None);
    assert_eq!(stamp(Some(&policy()), None, || Some(DIRECT_OK)), None);
}

#[test]
fn a_plan_a_peer_put_in_is_never_relayed() {
    let forged = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK))
        .unwrap()
        .plan;
    let from_peer = KexPath {
        responder: None,
        plan: forged.clone(),
        ..both()
    };
    assert_eq!(
        stamp(Some(&policy()), Some(from_peer.clone()), || Some(DIRECT_OK))
            .unwrap()
            .plan,
        None
    );
    assert_eq!(
        stamp(
            None,
            Some(KexPath {
                plan: forged,
                ..both()
            }),
            || Some(DIRECT_OK)
        )
        .unwrap()
        .plan,
        None
    );
}

#[test]
fn a_relay_only_turn_config_refuses_the_paths_that_reveal_an_address() {
    let relay_only = TurnRelayConfig::new(vec![], TurnPolicy::RelayOnly);
    let offer = local_offer(Some(&relay_only));
    assert!(offer.turn_ready);
    assert!(offer.restrictions.denies(PathKind::Direct));
    assert!(offer.restrictions.denies(PathKind::PeerRelay));
    assert!(!offer.restrictions.denies(PathKind::Turn));
    let fallback = TurnRelayConfig::new(vec![], TurnPolicy::Fallback);
    assert_eq!(local_offer(Some(&fallback)), OPEN);
    assert_eq!(
        local_offer(None),
        PathOffer {
            restrictions: PathRestrictions::NONE,
            turn_ready: false
        }
    );
}

#[test]
fn a_peer_executes_a_stamped_plan_only_from_a_sender_at_the_version() {
    let stamped = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK));
    let current = Some(*PROTOCOL_VERSION);
    assert!(stamped_plan(stamped.as_ref(), current).is_some());
    let older = Some(Semver::new(0, 12, 1).to_u32().unwrap());
    assert_eq!(stamped_plan(stamped.as_ref(), older), None);
    assert_eq!(stamped_plan(stamped.as_ref(), None), None);
    assert_eq!(stamped_plan(None, current), None);
}

fn kex(path: Option<KexPath>) -> PeerSignal {
    PeerSignal::Kex {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: 1,
            peer_cid: 2,
        },
        kex_payload: KeyExchangeProcess::Stage2(7, None, true),
        sender_protocol_version: Some(*PROTOCOL_VERSION),
        path,
    }
}

fn path_of(signal: PeerSignal) -> Option<KexPath> {
    match signal {
        PeerSignal::Kex { path, .. } => path,
        other => panic!("not a Kex: {other:?}"),
    }
}

/// An older node reads a signal as its own fields followed by bytes it ignores, and sends one
/// that ends before the path: both directions must parse.
#[test]
fn the_path_is_appended_to_the_kex_and_absent_from_an_older_nodes() {
    let stamped = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK));
    let with = kex(stamped.clone()).serialize_to_vector().unwrap();
    let read = PeerSignal::deserialize_from_vector(&with).unwrap();
    assert_eq!(path_of(read), stamped);

    let without = kex(None).serialize_to_vector().unwrap();
    let legacy = &without[..without.len() - 1];
    assert!(
        with.starts_with(legacy),
        "the old encoding, with the path appended"
    );
    let from_older = PeerSignal::deserialize_from_vector(legacy).unwrap();
    assert_eq!(path_of(from_older), None);
}
