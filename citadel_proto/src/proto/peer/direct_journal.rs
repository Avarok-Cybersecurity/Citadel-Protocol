//! Messages sent over a direct P2P route that the peer has not yet acknowledged.
//!
//! A direct route can end with packets still queued or in flight: the dual-connect tie-breaker
//! stops the losing stream, and a lost path (NAT rebinding, idle timeout) takes whatever was in
//! flight with it. The receiver's ordered channel waits for every group id in sequence and there
//! is no retransmit below it, so one lost message would stall the channel forever. Every message
//! a peer receives is answered with a GROUP_HEADER_ACK; until that ack arrives the message is kept
//! here, and when the route it went out on ends it is sent again on the surviving route. The
//! receiver drops the copy it already delivered, so each message still arrives exactly once.
//!
//! Only direct routes are journaled: the server relay rides the C2S connection, whose loss ends
//! the session anyway.

use bytes::BytesMut;
use std::collections::BTreeMap;

use crate::proto::outbound_sender::OutboundPrimaryStreamSender;

#[derive(Default)]
pub(crate) struct DirectJournal {
    unacked: BTreeMap<u64, BytesMut>,
}

impl DirectJournal {
    pub(crate) fn record(&mut self, group_id: u64, packet: &BytesMut) {
        let _ = self.unacked.insert(group_id, packet.clone());
    }

    pub(crate) fn ack(&mut self, group_id: u64) {
        let _ = self.unacked.remove(&group_id);
    }

    /// Re-sends every unacknowledged message, oldest first, onto another direct route. They stay
    /// journaled: that route can end too.
    pub(crate) fn replay_onto(&self, route: &OutboundPrimaryStreamSender) -> usize {
        self.unacked
            .values()
            .filter(|packet| route.unbounded_send((*packet).clone()).is_ok())
            .count()
    }

    /// Re-sends every unacknowledged message, oldest first, onto the server relay and forgets
    /// them: the relay is as reliable as the session itself.
    pub(crate) fn drain_onto(&mut self, relay: &OutboundPrimaryStreamSender) -> usize {
        std::mem::take(&mut self.unacked)
            .into_values()
            .filter(|packet| relay.unbounded_send(packet.clone()).is_ok())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.unacked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::outbound_sender::{unbounded, OutboundPacket, UnboundedReceiver};

    fn packet(id: u8) -> BytesMut {
        BytesMut::from(&[id][..])
    }

    fn first_byte(rx: &mut UnboundedReceiver<OutboundPacket>) -> Option<u8> {
        match rx.try_recv().ok()? {
            OutboundPacket::Contiguous(buf) => Some(buf[0]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn only_unacknowledged_messages_are_resent_in_group_order() {
        let mut journal = DirectJournal::default();
        for id in [3u8, 1, 2, 4] {
            journal.record(id as u64, &packet(id));
        }
        journal.ack(2);
        let (tx, mut rx) = unbounded();
        let relay = OutboundPrimaryStreamSender::from(tx);
        assert_eq!(journal.drain_onto(&relay), 3);
        let resent: Vec<u8> = std::iter::from_fn(|| first_byte(&mut rx)).collect();
        assert_eq!(resent, vec![1, 3, 4]);
        assert_eq!(
            journal.len(),
            0,
            "the relay is reliable; nothing stays journaled"
        );
    }

    #[test]
    fn replaying_onto_another_direct_route_keeps_the_messages_journaled() {
        let mut journal = DirectJournal::default();
        journal.record(7, &packet(7));
        let (tx, mut rx) = unbounded();
        assert_eq!(
            journal.replay_onto(&OutboundPrimaryStreamSender::from(tx)),
            1
        );
        assert_eq!(first_byte(&mut rx), Some(7));
        assert_eq!(journal.len(), 1);
    }
}
