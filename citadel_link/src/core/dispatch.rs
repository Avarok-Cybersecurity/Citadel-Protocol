//! Routing every input to its handler, and the timed transitions a `Tick` fires.

use super::{LinkCommand, LinkCore, LinkInput, LinkState};
use crate::event::{CloseReason, LossCause};
use crate::kind::Millis;
use crate::path::StageFailure;
use crate::plan::PathTrigger;
use crate::typestate::SealFailure;

impl LinkCore {
    pub(super) fn dispatch(&mut self, now: Millis, input: LinkInput, out: &mut Vec<LinkCommand>) {
        match input {
            LinkInput::Start => self.start(now, out),
            LinkInput::Met { attempt, plan } => self.met(now, attempt, plan, out),
            LinkInput::MeetFailed { attempt, failure } => {
                self.meet_failed(now, attempt, failure, out)
            }
            LinkInput::PathOpened { attempt, report } => {
                self.path_opened(now, attempt, report, out)
            }
            LinkInput::PathFailed { attempt, failure } => {
                self.path_failed(now, attempt, failure.failure, out)
            }
            LinkInput::Sealed { incarnation } => self.sealed(now, incarnation, out),
            LinkInput::SealFailed {
                incarnation,
                failure,
            } => self.seal_failed(now, incarnation, failure, out),
            LinkInput::Delivered { .. } => {}
            LinkInput::LinkLost { incarnation, cause } => self.lost(now, incarnation, cause, out),
            LinkInput::PeerClosing { reason } => self.close(CloseReason::Peer(reason), out),
            LinkInput::NatChanged { local } => {
                self.local_nat = local;
                self.network_changed(now, PathTrigger::NatChanged, LossCause::NatChanged, out)
            }
            LinkInput::InterfaceChanged => self.network_changed(
                now,
                PathTrigger::InterfaceChanged,
                LossCause::InterfaceChanged,
                out,
            ),
            LinkInput::Rebound { route, ok } => self.rebound(now, route, ok, out),
            LinkInput::Suspended => self.suspended(),
            LinkInput::Resumed => self.resumed(out),
            LinkInput::SettingsAgreed {
                epoch,
                setting,
                agreed,
            } => self.settings_agreed(now, epoch, setting, agreed, out),
            LinkInput::PeerOffer {
                incarnation,
                report,
            } => self.peer_offer(now, incarnation, report, out),
            LinkInput::PeerReachable => self.peer_reachable(now),
            LinkInput::ProbeResult { ok } => self.probe_result(now, ok, out),
            LinkInput::Retired { incarnation } => self.retired(incarnation, out),
            LinkInput::Tick => self.tick(now, out),
            LinkInput::Shutdown { reason } => self.close(CloseReason::Local(reason), out),
        }
    }

    /// A deadline or a wait ran out. A tick before the wake is a no-op.
    fn tick(&mut self, now: Millis, out: &mut Vec<LinkCommand>) {
        match self.next_wake() {
            Some(wake) if now >= wake => {}
            _ => return,
        }
        match self.state.clone() {
            LinkState::Resolving { attempt, .. } => {
                self.meet_failed(now, attempt, StageFailure::Timeout, out)
            }
            LinkState::Opening { attempt, .. } => {
                self.path_failed(now, attempt, StageFailure::Timeout, out)
            }
            LinkState::Sealing { incarnation, .. } | LinkState::Reattaching { incarnation, .. } => {
                self.seal_failed(now, incarnation, SealFailure::Timeout, out)
            }
            LinkState::Resealing { next, .. } => {
                self.seal_failed(now, next, SealFailure::Timeout, out)
            }
            LinkState::Degraded { .. } => self.heal_tick(now, out),
            LinkState::Up { .. } => self.up_tick(now, out),
            LinkState::Dormant | LinkState::Closing { .. } | LinkState::Closed { .. } => {}
        }
    }
}

/// The span from `then` to `now` (zero if `now` is earlier).
pub(crate) fn since(now: Millis, then: Millis) -> std::time::Duration {
    std::time::Duration::from_millis(now.0.saturating_sub(then.0))
}
