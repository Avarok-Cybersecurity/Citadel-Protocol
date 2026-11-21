use super::*;
use crate::constants::PROTOCOL_VERSION;
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use citadel_types::proto::{PathClasses, PathRule};
use citadel_user::serialization::SyncIO;
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
fn a_peer_executes_the_plan_the_server_stamped() {
    let stamped = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK));
    assert!(stamped_plan(stamped.as_ref()).is_some());
    assert_eq!(stamped_plan(None), None);
}

fn kex(path: Option<KexPath>) -> PeerSignal {
    PeerSignal::Kex {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: 1,
            peer_cid: 2,
        },
        kex_payload: KeyExchangeProcess::Stage2(7, None, true),
        sender_protocol_version: *PROTOCOL_VERSION,
        path,
        auth: None,
    }
}

fn path_of(signal: PeerSignal) -> Option<KexPath> {
    match signal {
        PeerSignal::Kex { path, .. } => path,
        other => panic!("not a Kex: {other:?}"),
    }
}

/// The path crosses the wire; the encoding before it (ending before the path and the signature
/// after it) does not parse.
#[test]
fn the_path_crosses_the_wire_and_a_kex_without_it_is_refused() {
    let stamped = stamp(Some(&policy()), Some(both()), || Some(DIRECT_OK));
    let with = kex(stamped.clone()).serialize_to_vector().unwrap();
    let read = PeerSignal::deserialize_from_vector(&with).unwrap();
    assert_eq!(path_of(read), stamped);

    let without = kex(None).serialize_to_vector().unwrap();
    assert!(PeerSignal::deserialize_from_vector(&without).is_ok());
    let older = &without[..without.len() - 2];
    assert!(PeerSignal::deserialize_from_vector(older).is_err());
}

/// A pair the NAT model rules out is stamped infeasible in this build too. Under
/// `localhost-testing` the decision used to read "direct" for every pair, so a test server
/// stamped direct plans for production clients and the TURN-first branches never ran in CI.
#[test]
fn a_pair_of_unpredictable_nats_is_not_direct_in_any_build() {
    let unpredictable = NatType::unidentified(None);
    assert!(!pair_feasibility(&unpredictable, &unpredictable).direct);
    assert!(pair_feasibility(&NatType::offline(), &unpredictable).direct);
}
