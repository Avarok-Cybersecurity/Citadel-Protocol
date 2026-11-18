//! A C2S link with the outbox the shell keeps beside it (§3.3, §5.2, §7): a drop reattaches the
//! live seal and replays what was held, once, in order; a true close returns everything.

mod common;

use std::time::Duration;

use citadel_link::outbox::{LinkOutbox, PayloadLane};
use citadel_link::{
    BufferMode, CloseReason, Incarnation, LinkCommand, LinkCore, LinkEvent, LinkInput, LinkState,
    LossCause, Millis, PathReport, PunchReuse, RouteId, RouteKind, SealFailure, SealRefusal,
    ServerTransport, ShutdownReason, Ticket,
};
use citadel_types::crypto::SecBuffer;
use common::*;

/// The shell's part: the outbox follows the core's `Buffer` commands and the path's fate.
struct Shell {
    core: LinkCore,
    now: Millis,
    outbox: LinkOutbox<SecBuffer>,
    live: Option<Incarnation>,
    wire: Vec<(Incarnation, u64)>,
    log: Vec<LinkCommand>,
}

impl Shell {
    fn new() -> Self {
        Shell {
            core: LinkCore::new(server(ALL)).unwrap(),
            now: Millis(0),
            outbox: LinkOutbox::new(1 << 20, false),
            live: None,
            wire: Vec::new(),
            log: Vec::new(),
        }
    }

    fn step(&mut self, input: LinkInput) -> Vec<LinkCommand> {
        if let LinkInput::LinkLost { incarnation, .. } = input {
            self.outbox.path_lost(incarnation);
            self.live = None;
        }
        let commands = self.core.step(self.now, input);
        for c in &commands {
            match c {
                LinkCommand::Deliver { incarnation } => self.live = Some(*incarnation),
                LinkCommand::Buffer(BufferMode::Live) => self.write(),
                _ => {}
            }
        }
        self.log.extend(commands.clone());
        commands
    }

    fn write(&mut self) {
        if let Some(live) = self.live {
            for seq in self.outbox.take_writes(live) {
                self.wire.push((live, seq.0));
            }
        }
    }

    fn send(&mut self, n: u128) {
        let payload = SecBuffer::from(format!("message {n}").as_str());
        self.outbox
            .push(Ticket(n), PayloadLane::Message, payload)
            .unwrap();
        self.write();
    }

    fn report(route: u64) -> PathReport {
        PathReport {
            kind: RouteKind::Server(ServerTransport::Tcp),
            route: RouteId(route),
            migratable: false,
            extra_stages: vec![],
            reused_socket: false,
            local_nat: nat(),
            peer_nat: None,
        }
    }

    fn up(&mut self) -> Incarnation {
        self.step(LinkInput::Start);
        let attempt = 1;
        self.step(LinkInput::PathOpened {
            attempt,
            report: Shell::report(1),
        });
        let LinkState::Sealing { incarnation, .. } = *self.core.state() else {
            panic!("{:?}", self.core.state());
        };
        self.step(LinkInput::Sealed { incarnation });
        incarnation
    }
}

fn outcomes(log: &[LinkCommand]) -> Vec<citadel_link::PathAttemptOutcome> {
    log.iter()
        .filter_map(|c| match c {
            LinkCommand::Report(LinkEvent::Path(o)) => Some(o.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_cut_c2s_link_reattaches_and_replays_what_it_held_once_in_order() {
    let mut s = Shell::new();
    let one = s.up();
    s.send(1);
    s.step(LinkInput::LinkLost {
        incarnation: one,
        cause: LossCause::Transient,
    });
    s.send(2);
    s.send(3);
    assert_eq!(s.wire, [(one, 0)], "nothing is written while held");
    s.now = Millis(1500);
    s.step(LinkInput::Tick);
    let opens = s.step(LinkInput::Tick);
    assert!(opens.is_empty(), "the heal already started");
    let open = s.log.iter().rev().find_map(|c| match c {
        LinkCommand::OpenPath { attempt, reuse, .. } => Some((*attempt, *reuse)),
        _ => None,
    });
    assert_eq!(open, Some((2, PunchReuse::Reattached)));
    let cmds = s.step(LinkInput::PathOpened {
        attempt: 2,
        report: Shell::report(2),
    });
    assert!(matches!(cmds[0], LinkCommand::Reattach { incarnation, .. } if incarnation == one));
    s.step(LinkInput::Sealed { incarnation: one });
    assert_eq!(
        s.wire,
        [(one, 0), (one, 0), (one, 1), (one, 2)],
        "replayed in order, each once"
    );
    let last = outcomes(&s.log).pop().unwrap();
    assert_eq!(last.punch, PunchReuse::Reattached);
    assert_eq!(last.downtime, Some(Duration::from_millis(1500)));
    let drained = s.outbox.drain();
    assert_eq!(
        drained.undelivered.len(),
        3,
        "a heal returns nothing; all three still held"
    );
}

#[test]
fn a_reattach_the_server_forgot_reseals_on_the_open_path_without_a_new_dial() {
    let mut s = Shell::new();
    let one = s.up();
    s.step(LinkInput::LinkLost {
        incarnation: one,
        cause: LossCause::Transient,
    });
    s.step(LinkInput::Tick);
    s.step(LinkInput::PathOpened {
        attempt: 2,
        report: Shell::report(2),
    });
    let dials = |log: &[LinkCommand]| {
        log.iter()
            .filter(|c| matches!(c, LinkCommand::OpenPath { .. }))
            .count()
    };
    let before = dials(&s.log);
    let cmds = s.step(LinkInput::SealFailed {
        incarnation: one,
        failure: SealFailure::UnknownSeal,
    });
    assert!(cmds
        .iter()
        .any(|c| matches!(c, LinkCommand::Seal { incarnation, .. } if incarnation.n == 2)));
    assert_eq!(dials(&s.log), before, "no new dial for a refused reattach");
    s.step(LinkInput::Sealed {
        incarnation: Incarnation { n: 2, ..one },
    });
    assert_eq!(outcomes(&s.log).pop().unwrap().punch, PunchReuse::NotNeeded);
}

#[test]
fn a_refused_seal_closes_and_a_true_close_returns_every_payload_in_order() {
    let mut s = Shell::new();
    let one = s.up();
    s.step(LinkInput::LinkLost {
        incarnation: one,
        cause: LossCause::Transient,
    });
    for n in 1..=5 {
        s.send(n);
    }
    s.step(LinkInput::Tick);
    s.step(LinkInput::PathOpened {
        attempt: 2,
        report: Shell::report(2),
    });
    let refusal = SealFailure::Refused(SealRefusal::BadCredentials);
    s.step(LinkInput::SealFailed {
        incarnation: one,
        failure: refusal,
    });
    assert!(matches!(
        s.core.state(),
        LinkState::Closing { retiring: 1, .. }
    ));
    s.step(LinkInput::Retired { incarnation: one });
    let LinkState::Closed { reason } = *s.core.state() else {
        panic!();
    };
    assert_eq!(reason, CloseReason::Refused(SealRefusal::BadCredentials));
    let drained = s.outbox.drain();
    let tickets: Vec<_> = drained.undelivered.iter().map(|u| u.ticket.0).collect();
    assert_eq!(tickets, [1, 2, 3, 4, 5]);
    assert_eq!(drained.undelivered[0].payload, b"message 1");
    let closes = s
        .log
        .iter()
        .filter(|c| matches!(c, LinkCommand::Report(LinkEvent::Closed(_))))
        .count();
    assert_eq!(closes, 1);
}

#[test]
fn a_close_before_any_seal_reports_once_with_nothing_to_retire() {
    let mut s = Shell::new();
    s.step(LinkInput::Start);
    s.step(LinkInput::Shutdown {
        reason: ShutdownReason::Aborted,
    });
    let LinkState::Closed { reason } = *s.core.state() else {
        panic!();
    };
    assert_eq!(reason, CloseReason::Local(ShutdownReason::Aborted));
    assert!(
        s.log.contains(&LinkCommand::ClosePath),
        "the in-flight dial is cancelled (§9.1)"
    );
}
