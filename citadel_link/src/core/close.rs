//! A true close (§3.2 rows "any → Closing" and Closing): every incarnation is retired, and the
//! close is reported exactly once, when the last retirement is answered.

use super::{LinkCommand, LinkCore, LinkState};
use crate::event::{CloseReason, CloseSummary, LinkEvent};
use crate::kind::Incarnation;
use crate::typestate::RetireReason;

impl LinkCore {
    pub(super) fn close(&mut self, reason: CloseReason, out: &mut Vec<LinkCommand>) {
        if matches!(
            self.state,
            LinkState::Closing { .. } | LinkState::Closed { .. }
        ) {
            return;
        }
        if self.state != LinkState::Dormant {
            out.push(LinkCommand::ClosePath);
        }
        self.held = None;
        if let LinkState::Resealing { next, .. } = self.state {
            self.retire(next, RetireReason::Abandoned, out);
        }
        for incarnation in std::mem::take(&mut self.live) {
            self.retire(incarnation, RetireReason::Closing, out);
        }
        self.attempt = None;
        self.heal = None;
        self.side = None;
        self.rearm_at = None;
        self.probe_at = None;
        self.rebinding = None;
        self.changing = None;
        self.state = LinkState::Closing {
            reason,
            retiring: self.retiring.len() as u32,
        };
        self.finish_if_retired(out);
    }

    pub(super) fn retired(&mut self, incarnation: Incarnation, out: &mut Vec<LinkCommand>) {
        self.retiring.retain(|i| *i != incarnation);
        if let LinkState::Closing { retiring, .. } = &mut self.state {
            *retiring = self.retiring.len() as u32;
        }
        self.finish_if_retired(out);
    }

    fn finish_if_retired(&mut self, out: &mut Vec<LinkCommand>) {
        let LinkState::Closing {
            reason,
            retiring: 0,
        } = self.state
        else {
            return;
        };
        self.state = LinkState::Closed { reason };
        out.push(LinkCommand::Report(LinkEvent::Closed(CloseSummary {
            link: self.cfg.kind,
            connection: self.cfg.connection,
            reason,
            incarnations: self.sealed_count,
        })));
    }
}
