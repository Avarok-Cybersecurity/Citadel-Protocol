//! Each command of the core, as a port call (§2.3), and each port result, as the core's input.
//! Nothing here decides: a command the shell cannot carry out is answered as the failure of its
//! step, so the core's own rules (heal, fresh seal, close) take it from there.

use citadel_link::{LinkCommand, LinkEstablisher, LinkInput, SealFailure};

use super::links::PortDone;
use super::ports::LinkPorts;
use super::RobustConnectionManager;

pub(super) fn dispatch<E: LinkEstablisher, P: LinkPorts>(
    m: &mut RobustConnectionManager<E, P>,
    command: LinkCommand,
) {
    match command {
        LinkCommand::OpenPath {
            attempt,
            stage,
            trigger,
            reuse,
            deadline,
        } => {
            let (est, target) = (m.est.clone(), m.target.clone());
            let incarnation = m.links.next_incarnation();
            m.pending.push(Box::pin(async move {
                let result = est
                    .open_path(&target, stage, trigger, reuse, incarnation, deadline)
                    .await;
                PortDone::Opened { attempt, result }
            }));
        }
        LinkCommand::Rendezvous { attempt, via, .. } => {
            let ports = m.ports.clone();
            m.pending.push(Box::pin(async move {
                let result = ports.rendezvous(attempt, via).await;
                PortDone::Met { attempt, result }
            }));
        }
        LinkCommand::Seal {
            incarnation,
            params,
            deadline,
        } => {
            m.links.issue(incarnation);
            let Some(link) = m.links.take_opened() else {
                return m.apply(LinkInput::SealFailed {
                    incarnation,
                    failure: SealFailure::PathLost,
                });
            };
            let est = m.est.clone();
            m.pending.push(Box::pin(async move {
                let result = est.seal(link, &params, deadline).await;
                PortDone::Sealed {
                    incarnation,
                    result,
                }
            }));
        }
        LinkCommand::Reattach { incarnation, .. } => {
            // No held seal is kept by this shell yet (the reattach frames are lane L1's):
            // the core seals afresh on the path already open (§3.2).
            m.apply(LinkInput::SealFailed {
                incarnation,
                failure: SealFailure::UnknownSeal,
            });
        }
        LinkCommand::Deliver { incarnation } => {
            if let Some(link) = m.links.sealed.remove(&incarnation) {
                let delivered = m.est.deliver(link, &m.handle);
                m.links.delivered.insert(incarnation, delivered);
                m.apply(LinkInput::Delivered { incarnation });
            }
        }
        LinkCommand::ForkPath { next, .. } => {
            // A second session on the live path is lane L5's reseal; refused, the core keeps
            // the live incarnation (§3.2 Resealing + SealFailed).
            m.apply(LinkInput::SealFailed {
                incarnation: next,
                failure: SealFailure::Handshake,
            });
        }
        LinkCommand::Cutover { .. } => {}
        LinkCommand::Retire {
            incarnation,
            reason,
        } => {
            let Some(link) = m.links.delivered.remove(&incarnation) else {
                return m.apply(LinkInput::Retired { incarnation });
            };
            let est = m.est.clone();
            m.pending.push(Box::pin(async move {
                let undelivered = est.retire(link, reason).await;
                PortDone::Retired {
                    incarnation,
                    undelivered,
                }
            }));
        }
        LinkCommand::ClosePath => m.links.close_undelivered(),
        LinkCommand::FallBackToRelay => m.ports.fall_back_to_relay(),
        LinkCommand::AttachRoute { .. } => {
            // A side attempt opened a route under the live seal: seal it and attach it.
            let Some(link) = m.links.take_opened() else {
                return;
            };
            let est = m.est.clone();
            let params = citadel_link::SealParams {
                settings: m.core.settings(),
            };
            let deadline = m.clock.now();
            m.pending.push(Box::pin(async move {
                let result = est.seal(link, &params, deadline).await;
                PortDone::SideSealed { result }
            }));
        }
        LinkCommand::Rebind { route } => {
            let ports = m.ports.clone();
            m.pending.push(Box::pin(async move {
                let ok = ports.rebind(route).await;
                PortDone::Rebound { route, ok }
            }));
        }
        LinkCommand::Probe => {
            let ports = m.ports.clone();
            m.pending.push(Box::pin(async move {
                let ok = ports.probe().await;
                PortDone::Probed { ok }
            }));
        }
        LinkCommand::Buffer(mode) => m.ports.buffer(mode),
        LinkCommand::Report(event) => m.ports.report(event),
        LinkCommand::ScheduleWake(_) => {}
    }
}

impl<E: LinkEstablisher, P: LinkPorts> RobustConnectionManager<E, P> {
    /// Stores what a port returned and names the core's input for it. A stale result (an
    /// attempt the core already timed out) is dropped with its link: the core ignores its input.
    pub(super) fn absorb(&mut self, done: PortDone<E>) -> Option<LinkInput> {
        match done {
            PortDone::Opened { attempt, result } => Some(match result {
                Ok(link) => {
                    let report = super::report::path_report(&link);
                    self.links.pathed.insert(attempt, link);
                    self.links.last_opened = Some(attempt);
                    LinkInput::PathOpened { attempt, report }
                }
                Err(failure) => LinkInput::PathFailed { attempt, failure },
            }),
            PortDone::Sealed {
                incarnation,
                result,
            } => Some(match result {
                Ok(link) => {
                    self.links.sealed.insert(incarnation, link);
                    LinkInput::Sealed { incarnation }
                }
                Err(failure) => LinkInput::SealFailed {
                    incarnation,
                    failure,
                },
            }),
            PortDone::SideSealed { result } => match result {
                Ok(link) => {
                    // Delivered as a route of the live incarnation; its values end with it.
                    drop(self.est.deliver(link, &self.handle));
                    None
                }
                Err(_) => {
                    let incarnation = self.live_incarnation()?;
                    Some(LinkInput::LinkLost {
                        incarnation,
                        cause: citadel_link::LossCause::RouteLost,
                    })
                }
            },
            PortDone::Retired {
                incarnation,
                mut undelivered,
            } => {
                self.links.undelivered.append(&mut undelivered);
                Some(LinkInput::Retired { incarnation })
            }
            PortDone::Met { attempt, result } => Some(match result {
                Ok(plan) => LinkInput::Met { attempt, plan },
                Err(failure) => LinkInput::MeetFailed { attempt, failure },
            }),
            PortDone::Rebound { route, ok } => Some(LinkInput::Rebound { route, ok }),
            PortDone::Probed { ok } => Some(LinkInput::ProbeResult { ok }),
        }
    }

    pub(super) fn live_incarnation(&self) -> Option<citadel_link::Incarnation> {
        match self.core.state() {
            citadel_link::LinkState::Up { incarnation, .. } => Some(*incarnation),
            _ => None,
        }
    }
}
