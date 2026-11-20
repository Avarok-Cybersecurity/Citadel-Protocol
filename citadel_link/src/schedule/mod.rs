//! The deterministic two-link scheduler: tests only (`cfg(test)` or feature `harness`).
//!
//! Two `LinkCore`s of one peer pair, a world that answers every port call by fixed rules (a
//! server and a direct path that are up or down on command, a handshake that both ends see),
//! and one clock that jumps to the next wake. Nothing is random: a schedule is a list of
//! [`Action`]s, so every failure replays exactly. The negotiator's merge is modelled by R-DIAL's
//! `stronger_offer`; the negotiator itself is `citadel_negotiation`'s own harness.

mod check;
mod events;
mod resolve;
mod types;

pub use types::{Action, Net, Op, Party, Side};

use crate::core::{LinkCommand, LinkConfig, LinkInput};
use crate::event::LinkEvent;
use crate::kind::Millis;
use crate::{LinkCore, LinkState};

enum InputKind {
    Lost,
    Other,
}

fn degrades(commands: &[LinkCommand]) -> bool {
    commands
        .iter()
        .any(|c| matches!(c, LinkCommand::Report(LinkEvent::Degraded(_))))
}

#[derive(Clone, Debug)]
pub struct World {
    pub a: Party,
    pub b: Party,
    pub net: Net,
    pub now: Millis,
    pub next_route: u64,
    pub epoch: u32,
    pub steps: usize,
    /// Set by every action that legitimately needs the server again (§11.1's server-minimal
    /// property): a NAT or interface change, the server or the direct path going down, a
    /// settings change, a forced failure.
    pub server_needed: bool,
    pub violations: Vec<String>,
    pub(crate) agreeing: bool,
}

impl World {
    pub fn new(a: LinkConfig, b: LinkConfig, net: Net) -> Self {
        let party = |cfg: LinkConfig| Party {
            core: LinkCore::new(cfg).expect("a valid test configuration"),
            ops: Vec::new(),
            commands: Vec::new(),
            events: Vec::new(),
            steps: Vec::new(),
        };
        World {
            a: party(a),
            b: party(b),
            net,
            now: Millis(0),
            next_route: 1,
            epoch: 0,
            steps: 0,
            server_needed: false,
            violations: Vec::new(),
            agreeing: false,
        }
    }

    pub fn party(&self, side: Side) -> &Party {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    pub(crate) fn party_mut(&mut self, side: Side) -> &mut Party {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    pub fn state(&self, side: Side) -> &LinkState {
        self.party(side).core.state()
    }

    pub fn apply(&mut self, action: Action) {
        self.steps += 1;
        match action {
            Action::Start(side) => self.step(side, LinkInput::Start),
            Action::Resolve(side, i, ok) => self.resolve(side, i, ok),
            Action::Lose(cause) => self.lose(cause),
            Action::NatChange(side) => {
                self.server_needed = true;
                let local = self.party(side).core.config().local_nat;
                self.step(side, LinkInput::NatChanged { local })
            }
            Action::Interface(side) => {
                self.server_needed = true;
                self.step(side, LinkInput::InterfaceChanged)
            }
            Action::Agree(settings) => self.agree(settings),
            Action::AgreeBoth(a, b) => {
                let mut merged = a;
                merged.security = citadel_types::proto::stronger_offer(a.security, b.security);
                self.agree(merged)
            }
            Action::Tick(side) => {
                if let Some(wake) = self.party(side).core.next_wake() {
                    self.now = self.now.max(wake);
                }
                self.step(side, LinkInput::Tick)
            }
            Action::Suspend(side) => self.step(side, LinkInput::Suspended),
            Action::Resume(side) => self.step(side, LinkInput::Resumed),
            Action::Shutdown(side) => self.step(
                side,
                LinkInput::Shutdown {
                    reason: crate::event::ShutdownReason::Shutdown,
                },
            ),
            Action::Reachable(side) => self.step(side, LinkInput::PeerReachable),
            Action::ServerDown => {
                self.server_needed = true;
                self.net.server_up = false
            }
            Action::ServerUp => self.net.server_up = true,
            Action::DirectDown => {
                self.server_needed = true;
                self.net.direct_works = false
            }
            Action::DirectUp => self.net.direct_works = true,
        }
    }

    /// One input to one side; every command it returns is handled before the next input.
    pub fn step(&mut self, side: Side, input: LinkInput) {
        let input_kind = match input {
            LinkInput::LinkLost { .. } => InputKind::Lost,
            _ => InputKind::Other,
        };
        let now = self.now;
        let commands = self.party_mut(side).core.step(now, input);
        self.check_step(side, &commands);
        self.party_mut(side).steps.push(commands.clone());
        let lost_here =
            !self.agreeing && !matches!(input_kind, InputKind::Lost) && degrades(&commands);
        for command in commands {
            self.handle(side, command);
        }
        if lost_here {
            self.lose_one(side.other());
        }
    }

    fn handle(&mut self, side: Side, command: LinkCommand) {
        self.party_mut(side).commands.push(command.clone());
        let op = match command {
            LinkCommand::Rendezvous { attempt, .. } => Some(Op::Meet { attempt }),
            LinkCommand::OpenPath {
                attempt,
                stage,
                reuse,
                ..
            } => Some(Op::Open {
                attempt,
                stage,
                reuse,
            }),
            LinkCommand::Seal { incarnation, .. } => Some(Op::Seal { incarnation }),
            LinkCommand::Reattach { incarnation, .. } => Some(Op::Reattach { incarnation }),
            LinkCommand::Retire { incarnation, .. } => Some(Op::Retire { incarnation }),
            LinkCommand::Probe => Some(Op::Probe),
            LinkCommand::Rebind { route } => Some(Op::Rebind { route }),
            LinkCommand::ClosePath => {
                let ops = &mut self.party_mut(side).ops;
                ops.retain(|op| matches!(op, Op::Retire { .. } | Op::Probe));
                None
            }
            LinkCommand::Report(event) => {
                self.report(side, event);
                None
            }
            _ => None,
        };
        if let Some(op) = op {
            self.party_mut(side).ops.push(op);
        }
    }

    fn report(&mut self, side: Side, event: LinkEvent) {
        if let LinkEvent::Closed(summary) = &event {
            if let crate::event::CloseReason::Local(_) = summary.reason {
                self.step(side.other(), LinkInput::PeerClosing { reason: None });
            }
        }
        self.party_mut(side).events.push(event);
    }
}
