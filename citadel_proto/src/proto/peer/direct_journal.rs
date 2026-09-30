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
//! Messages are kept as plaintext and sealed again for every re-send (the `reseal` argument).
//! Re-sending the original ciphertext does not work: its anti-replay id is as old as the message,
//! and once the receiver has accepted `HISTORY_LEN` (1024) newer packets from this peer, the
//! window has moved past it and the copy is refused as a replay, leaving the gap unfilled. A fresh
//! seal also uses the current ratchet, so a rekey in between cannot strand it either.
//!
//! Only direct routes are journaled: the server relay rides the C2S connection, whose loss ends
//! the session anyway.

use bytes::BytesMut;
use citadel_types::crypto::SecurityLevel;
use std::collections::BTreeMap;

use crate::proto::outbound_sender::OutboundPrimaryStreamSender;

/// A group header as crafted, before AEAD protection.
pub(crate) struct JournaledMessage {
    pub(crate) plaintext: BytesMut,
    pub(crate) security_level: SecurityLevel,
}

impl JournaledMessage {
    pub(crate) fn new(plaintext: BytesMut, security_level: SecurityLevel) -> Self {
        Self {
            plaintext,
            security_level,
        }
    }
}

#[derive(Default)]
pub(crate) struct DirectJournal {
    unacked: BTreeMap<u64, JournaledMessage>,
}

impl DirectJournal {
    pub(crate) fn record(&mut self, group_id: u64, message: JournaledMessage) {
        let _ = self.unacked.insert(group_id, message);
    }

    pub(crate) fn ack(&mut self, group_id: u64) {
        let _ = self.unacked.remove(&group_id);
    }

    /// Re-sends every unacknowledged message, oldest first, onto another direct route. They stay
    /// journaled: that route can end too.
    pub(crate) fn replay_onto(
        &self,
        route: &OutboundPrimaryStreamSender,
        reseal: impl Fn(&JournaledMessage) -> Option<BytesMut>,
    ) -> usize {
        self.unacked
            .values()
            .filter_map(&reseal)
            .filter(|packet| route.unbounded_send(packet.clone()).is_ok())
            .count()
    }

    /// Re-sends every unacknowledged message, oldest first, onto the server relay and forgets
    /// them: the relay is as reliable as the session itself.
    pub(crate) fn drain_onto(
        &mut self,
        relay: &OutboundPrimaryStreamSender,
        reseal: impl Fn(&JournaledMessage) -> Option<BytesMut>,
    ) -> usize {
        std::mem::take(&mut self.unacked)
            .into_values()
            .filter_map(|message| reseal(&message))
            .filter(|packet| relay.unbounded_send(packet.clone()).is_ok())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.unacked.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::proto::outbound_sender::{unbounded, OutboundPacket, UnboundedReceiver};

    pub(crate) fn message(id: u8) -> JournaledMessage {
        JournaledMessage::new(BytesMut::from(&[id][..]), SecurityLevel::Standard)
    }

    /// Stands in for sealing: tags the plaintext so a test can see a re-send was sealed again.
    pub(crate) fn tag(message: &JournaledMessage) -> Option<BytesMut> {
        let mut packet = message.plaintext.clone();
        packet.extend_from_slice(b"sealed");
        Some(packet)
    }

    pub(crate) fn first_bytes(rx: &mut UnboundedReceiver<OutboundPacket>) -> Vec<u8> {
        std::iter::from_fn(|| match rx.try_recv().ok()? {
            OutboundPacket::Contiguous(buf) => {
                assert!(buf.ends_with(b"sealed"), "a re-send must be sealed again");
                Some(buf[0])
            }
            other => panic!("unexpected {other:?}"),
        })
        .collect()
    }

    #[test]
    fn only_unacknowledged_messages_are_resent_in_group_order() {
        let mut journal = DirectJournal::default();
        for id in [3u8, 1, 2, 4] {
            journal.record(id as u64, message(id));
        }
        journal.ack(2);
        let (tx, mut rx) = unbounded();
        let relay = OutboundPrimaryStreamSender::from(tx);
        assert_eq!(journal.drain_onto(&relay, tag), 3);
        assert_eq!(first_bytes(&mut rx), vec![1, 3, 4]);
        assert_eq!(
            journal.len(),
            0,
            "the relay is reliable; nothing stays journaled"
        );
    }

    #[test]
    fn replaying_onto_another_direct_route_keeps_the_messages_journaled() {
        let mut journal = DirectJournal::default();
        journal.record(7, message(7));
        let (tx, mut rx) = unbounded();
        assert_eq!(
            journal.replay_onto(&OutboundPrimaryStreamSender::from(tx), tag),
            1
        );
        assert_eq!(first_bytes(&mut rx), vec![7]);
        assert_eq!(journal.len(), 1);
    }
}
