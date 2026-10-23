//! Which classes of traffic a peer connection may send on each path.
//!
//! A connection whose server stamped a plan (see `kex_path`) may carry, on each path, only the
//! classes the plan gives that path: an operator can, for example, keep media off the server
//! relay. A connection without a stamped plan (an older peer or server) has every class open on
//! every path, as before path policies. Pure: no I/O.

use citadel_types::proto::{EffectivePlan, PathClass, PathClasses, PathKind};

use super::p2p_path::P2pPath;

/// The classes a connection may carry on each of its paths.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClassGates {
    direct: PathClasses,
    turn: PathClasses,
    server_relay: PathClasses,
}

impl ClassGates {
    /// Every class on every path: a connection without a stamped plan.
    pub const OPEN: ClassGates = ClassGates {
        direct: PathClasses::ALL,
        turn: PathClasses::ALL,
        server_relay: PathClasses::ALL,
    };

    /// The gates of a connection executing `plan`. A path the plan does not include carries
    /// nothing (the connection never takes it).
    pub fn from_plan(plan: &EffectivePlan) -> Self {
        Self {
            direct: plan.classes_on(PathKind::Direct),
            turn: plan.classes_on(PathKind::Turn),
            server_relay: plan.classes_on(PathKind::ServerRelay),
        }
    }

    /// The gates for a connection with `stamped`, or [`Self::OPEN`] without one.
    pub(crate) fn from_stamped(stamped: Option<&EffectivePlan>) -> Self {
        stamped.map(Self::from_plan).unwrap_or(Self::OPEN)
    }

    /// The classes `path` may carry.
    pub fn on(&self, path: P2pPath) -> PathClasses {
        match path {
            P2pPath::Direct => self.direct,
            P2pPath::Turn => self.turn,
            P2pPath::ServerRelay => self.server_relay,
        }
    }

    pub fn permits(&self, path: P2pPath, class: PathClass) -> bool {
        self.on(path).contains(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::PlannedPath;
    use std::time::Duration;

    fn planned(kind: PathKind, classes: PathClasses) -> PlannedPath {
        PlannedPath {
            kind,
            attempt_timeout: Duration::from_secs(5),
            classes,
        }
    }

    #[test]
    fn a_stamped_plan_gates_each_path_by_its_classes() {
        let relay_without_media =
            PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
        let plan = EffectivePlan {
            paths: vec![
                planned(PathKind::Direct, PathClasses::ALL),
                planned(PathKind::ServerRelay, relay_without_media),
            ],
            forwarder: None,
        };
        let gates = ClassGates::from_stamped(Some(&plan));
        assert!(gates.permits(P2pPath::Direct, PathClass::Media));
        assert!(!gates.permits(P2pPath::ServerRelay, PathClass::Media));
        assert!(gates.permits(P2pPath::ServerRelay, PathClass::Msg));
        assert_eq!(gates.on(P2pPath::Turn), PathClasses::NONE, "not planned");
    }

    #[test]
    fn without_a_stamped_plan_every_class_rides_every_path() {
        let gates = ClassGates::from_stamped(None);
        assert_eq!(gates, ClassGates::OPEN);
        for path in [P2pPath::Direct, P2pPath::Turn, P2pPath::ServerRelay] {
            for class in PathClass::ALL {
                assert!(gates.permits(path, class));
            }
        }
    }
}
