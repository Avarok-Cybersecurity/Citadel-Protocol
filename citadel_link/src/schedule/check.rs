//! Running a world to rest, and the invariants every schedule must keep (§11.1).

use super::{Action, Op, Side, World};
use crate::core::LinkCommand;
use crate::event::LinkEvent;
use crate::kind::LinkKind;
use crate::LinkState;

impl World {
    /// Answers every outstanding op (as the network allows) and fires every wake, in a fixed
    /// order, until nothing is left. `Err` when the step budget runs out: a livelock.
    pub fn run_to_quiescence(&mut self, budget: usize) -> Result<(), String> {
        let start = self.steps;
        loop {
            if self.steps - start > budget {
                return Err(format!("no quiescence within {budget} steps"));
            }
            let action = if !self.a.ops.is_empty() {
                Action::Resolve(Side::A, 0, true)
            } else if !self.b.ops.is_empty() {
                Action::Resolve(Side::B, 0, true)
            } else if let Some(side) = self.earliest_wake() {
                Action::Tick(side)
            } else {
                return Ok(());
            };
            self.apply(action);
        }
    }

    /// The side whose wake comes first. A live link's own timers (re-arm, probe) never end, so
    /// they are not waited for: a world whose only wakes are those is at rest.
    pub fn earliest_wake(&self) -> Option<Side> {
        let wake = |side: Side| {
            let core = &self.party(side).core;
            let live = matches!(core.state(), LinkState::Up { .. });
            core.next_wake().filter(|_| !live).map(|at| (at, side))
        };
        let (a, b) = (wake(Side::A), wake(Side::B));
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b).1),
            (a, b) => a.or(b).map(|(_, side)| side),
        }
    }

    /// Per step: an establishment (a `Deliver`, a `Cutover`, an `AttachRoute`, a successful
    /// rebind) reports exactly one attached path outcome in the same step, and nothing else
    /// does; a close is reported once, only on `Closed`; the server is asked again only when
    /// something needed it.
    pub(super) fn check_step(&mut self, side: Side, commands: &[LinkCommand]) {
        let establishes = commands
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    LinkCommand::Deliver { .. }
                        | LinkCommand::Cutover { .. }
                        | LinkCommand::AttachRoute { .. }
                )
            })
            .count();
        let attached: Vec<_> = commands
            .iter()
            .filter_map(|c| match c {
                LinkCommand::Report(LinkEvent::Path(o)) if o.incarnation.is_some() => Some(o),
                _ => None,
            })
            .collect();
        let migrated = attached
            .iter()
            .filter(|o| o.punch == crate::plan::PunchReuse::Migrated)
            .count();
        if attached.len() != establishes + migrated {
            self.violations.push(format!(
                "{side:?}: {} attached outcomes for {establishes} establishments: {commands:?}",
                attached.len()
            ));
        }
        let closes = commands
            .iter()
            .filter(|c| matches!(c, LinkCommand::Report(LinkEvent::Closed(_))))
            .count();
        let closed = matches!(self.state(side), LinkState::Closed { .. });
        let earlier = self
            .party(side)
            .events
            .iter()
            .any(|e| matches!(e, LinkEvent::Closed(_)));
        if closes > 1 || (closes == 1 && (!closed || earlier)) {
            self.violations
                .push(format!("{side:?}: close reported out of turn"));
        }
        let ever_up = self
            .party(side)
            .commands
            .iter()
            .any(|c| matches!(c, LinkCommand::Deliver { .. }));
        let asks_server = commands
            .iter()
            .any(|c| matches!(c, LinkCommand::Rendezvous { .. }));
        if asks_server && ever_up && !self.server_needed {
            self.violations.push(format!(
                "{side:?}: asked the server with nothing needing it"
            ));
        }
    }

    /// At rest: both Up on the same incarnation and settings, or both Closed; nothing
    /// outstanding; every invariant kept on the way.
    pub fn check(&self) -> Result<(), String> {
        if let Some(v) = self.violations.first() {
            return Err(v.clone());
        }
        if !self.a.ops.is_empty() || !self.b.ops.is_empty() {
            return Err("at rest with ops outstanding".into());
        }
        match (self.state(Side::A), self.state(Side::B)) {
            (LinkState::Closed { .. }, LinkState::Closed { .. }) => Ok(()),
            (LinkState::Up { incarnation: a, .. }, LinkState::Up { incarnation: b, .. })
                if a == b =>
            {
                if self.a.core.settings() != self.b.core.settings() {
                    return Err("both up, settings differ".into());
                }
                Ok(())
            }
            (a, b) => Err(format!("at rest: A {a:?} B {b:?}")),
        }
    }

    /// How many path outcomes a side reported, and how many of them attached.
    pub fn outcomes(&self, side: Side) -> (usize, usize) {
        let all: Vec<_> = self
            .party(side)
            .events
            .iter()
            .filter_map(|e| match e {
                LinkEvent::Path(o) => Some(o),
                _ => None,
            })
            .collect();
        let attached = all.iter().filter(|o| o.incarnation.is_some()).count();
        (all.len(), attached)
    }

    /// Commands of one kind a side issued.
    pub fn count(&self, side: Side, pick: impl Fn(&LinkCommand) -> bool) -> usize {
        self.party(side).commands.iter().filter(|c| pick(c)).count()
    }

    pub fn is_peer(&self) -> bool {
        matches!(self.a.core.config().kind, LinkKind::Peer { .. })
    }

    pub fn outstanding(&self, side: Side) -> &[Op] {
        &self.party(side).ops
    }
}
