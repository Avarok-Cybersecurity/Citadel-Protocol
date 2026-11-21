//! Each §3.1 state, reached by real inputs, and one matching input of every kind.

use citadel_link::{
    Incarnation, LinkCore, LinkInput, LossCause, Millis, PathFailure, PathReport, PathStage,
    RouteId, RouteKind, SealFailure, SealRefusal, SettingId, ShutdownReason, StageFailure,
};
use citadel_types::crypto::SecurityLevel;

use crate::common::{direct_then_relay, nat, other_kem, peer, ALL};

use crate::kinds::StateKind;

/// A Leader of a peer pair in one state, with the attempt and incarnation that state waits on.
pub struct Fixture {
    pub core: LinkCore,
    pub now: Millis,
    pub attempt: u32,
    /// The incarnation the state waits on (Sealing: issued; Reattaching: held; Up: live;
    /// Resealing: next).
    pub inc: Incarnation,
    /// The live incarnation, the one a `LinkLost` names.
    pub live: Incarnation,
}

pub fn report(route: u64) -> PathReport {
    PathReport {
        kind: RouteKind::Direct,
        route: RouteId(route),
        migratable: true,
        extra_stages: vec![],
        reused_socket: false,
        local_nat: nat(),
        peer_nat: Some(nat()),
    }
}

fn first() -> Incarnation {
    Incarnation::first(citadel_link::ConnectionId(7))
}

pub fn fixture(state: StateKind) -> Fixture {
    let mut core = LinkCore::new(peer(1, 2, ALL)).unwrap();
    let now = Millis(0);
    let mut fx = |input: LinkInput| {
        let _ = core.step(now, input);
    };
    let one = first();
    let two = one.next().unwrap();
    let (attempt, inc) = match state {
        StateKind::Dormant => (1, one),
        StateKind::Resolving => {
            fx(LinkInput::Start);
            (1, one)
        }
        StateKind::Opening => {
            fx(LinkInput::Start);
            fx(LinkInput::Met {
                attempt: 1,
                plan: direct_then_relay(),
            });
            (1, one)
        }
        _ => {
            fx(LinkInput::Start);
            fx(LinkInput::Met {
                attempt: 1,
                plan: direct_then_relay(),
            });
            fx(LinkInput::PathOpened {
                attempt: 1,
                report: report(5),
            });
            if state == StateKind::Sealing {
                (1, one)
            } else {
                fx(LinkInput::Sealed { incarnation: one });
                match state {
                    StateKind::Up => (1, one),
                    StateKind::Degraded | StateKind::Reattaching => {
                        fx(LinkInput::LinkLost {
                            incarnation: one,
                            cause: LossCause::Transient,
                        });
                        if state == StateKind::Reattaching {
                            fx(LinkInput::Tick);
                            fx(LinkInput::PathOpened {
                                attempt: 2,
                                report: report(6),
                            });
                            (2, one)
                        } else {
                            (1, one)
                        }
                    }
                    StateKind::Resealing => {
                        fx(LinkInput::SettingsAgreed {
                            epoch: citadel_link::Epoch(1),
                            setting: SettingId::KEY_PROFILE,
                            agreed: other_kem(SecurityLevel::Standard),
                        });
                        (1, two)
                    }
                    StateKind::Closing | StateKind::Closed => {
                        fx(LinkInput::Shutdown {
                            reason: ShutdownReason::Shutdown,
                        });
                        if state == StateKind::Closed {
                            fx(LinkInput::Retired { incarnation: one });
                        }
                        (1, one)
                    }
                    _ => unreachable!(),
                }
            }
        }
    };
    Fixture {
        core,
        now,
        attempt,
        inc,
        live: one,
    }
}

/// One input of every kind, in `INPUTS` order, matching the fixture.
pub fn inputs(fx: &Fixture) -> Vec<LinkInput> {
    let (attempt, inc, live) = (fx.attempt, fx.inc, fx.live);
    let fresh = Incarnation {
        n: inc.n + 1,
        ..inc
    };
    let seal_failed = |failure| LinkInput::SealFailed {
        incarnation: inc,
        failure,
    };
    vec![
        LinkInput::Start,
        LinkInput::Met {
            attempt,
            plan: direct_then_relay(),
        },
        LinkInput::MeetFailed {
            attempt,
            failure: StageFailure::Signalling,
        },
        LinkInput::PathOpened {
            attempt,
            report: report(9),
        },
        LinkInput::PathFailed {
            attempt,
            failure: PathFailure {
                stage: PathStage::Direct,
                failure: StageFailure::PunchFailed,
            },
        },
        LinkInput::Sealed { incarnation: inc },
        seal_failed(SealFailure::Handshake),
        seal_failed(SealFailure::Refused(SealRefusal::BelowPolicy)),
        seal_failed(SealFailure::UnknownSeal),
        LinkInput::Delivered { incarnation: inc },
        LinkInput::LinkLost {
            incarnation: live,
            cause: LossCause::Transient,
        },
        LinkInput::LinkLost {
            incarnation: live,
            cause: LossCause::RouteLost,
        },
        LinkInput::PeerClosing { reason: None },
        LinkInput::NatChanged { local: nat() },
        LinkInput::InterfaceChanged,
        LinkInput::Rebound {
            route: RouteId(5),
            ok: true,
        },
        LinkInput::Suspended,
        LinkInput::Resumed,
        LinkInput::SettingsAgreed {
            epoch: citadel_link::Epoch(2),
            setting: SettingId::KEY_PROFILE,
            agreed: other_kem(SecurityLevel::Standard),
        },
        LinkInput::PeerOffer {
            incarnation: inc,
            report: report(11),
        },
        LinkInput::PeerOffer {
            incarnation: fresh,
            report: report(12),
        },
        LinkInput::PeerReachable,
        LinkInput::ProbeResult { ok: true },
        LinkInput::ProbeResult { ok: false },
        LinkInput::Retired { incarnation: inc },
        LinkInput::Tick,
        LinkInput::Shutdown {
            reason: ShutdownReason::Shutdown,
        },
    ]
}
