//! A journaled message re-sent after its route ended must be accepted by the receiver however far
//! the receiver's anti-replay window has moved since it was first sealed (see
//! `peer::direct_journal`).
#![cfg(test)]

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::outbound_sender::{unbounded, OutboundPacket, OutboundPrimaryStreamSender};
use crate::proto::packet::HdpHeader;
use crate::proto::packet_crafter::group::{reseal, seal};
use crate::proto::packet_crafter::ObjectTransmitter;
use crate::proto::peer::direct_journal::DirectJournal;
use crate::proto::remote::Ticket;
use crate::proto::state_container::virtual_connections::resealer;
use crate::proto::state_container::VirtualTargetType;
use crate::proto::udp_packet_tests::connected_pair;
use crate::proto::validation::aead::validate_custom;
use bytes::BytesMut;
use citadel_crypt::ratchets::ratchet_manager::RatchetMessage;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::replay_attack_container::HISTORY_LEN;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::ObjectId;
use netbeam::time_tracker::TimeTracker;
use zerocopy::FromZeroes;

const LEVEL: SecurityLevel = SecurityLevel::Standard;

fn plaintext(ratchet: &impl Ratchet, body: &[u8]) -> BytesMut {
    let mut header = HdpHeader::new_zeroed();
    header.security_level = LEVEL.value();
    header.session_cid.set(ratchet.get_cid());
    let mut packet = BytesMut::new();
    header.inscribe_into(&mut packet);
    packet.extend_from_slice(body);
    packet
}

/// Whether `receiver` accepts `packet`, and with what body.
fn accept(receiver: &impl Ratchet, mut packet: BytesMut) -> Option<Vec<u8>> {
    let header = packet.split_to(HDP_HEADER_BYTE_LEN);
    validate_custom(receiver, &header, packet).map(|(_, body)| body.to_vec())
}

#[test]
fn a_resent_message_is_accepted_after_the_replay_window_moved_past_it() {
    let (sender, receiver) = connected_pair(LEVEL);
    let lost = plaintext(&sender, b"the message the dead route lost");
    let original = seal(&sender, LEVEL, lost.clone()).unwrap();

    // The receiver goes on accepting the sender's later traffic, more than a window's worth.
    let mut newest = None;
    for _ in 0..=HISTORY_LEN {
        newest = Some(seal(&sender, LEVEL, plaintext(&sender, b"later")).unwrap());
    }
    assert!(accept(&receiver, newest.unwrap()).is_some());

    // The original ciphertext is now older than the window: refused as a replay.
    assert!(accept(&receiver, original).is_none());

    // Sealed again, the same message is accepted, byte for byte.
    let resent = reseal(&sender, 1, LEVEL, &lost).unwrap();
    assert_eq!(
        accept(&receiver, resent).as_deref(),
        Some(&b"the message the dead route lost"[..])
    );
}

/// Delivers whole messages in group order, each once, the way the receiver's ordered channel
/// does: a copy of a group it already holds is dropped.
#[derive(Default)]
struct OrderedReceiver {
    next: u64,
    held: std::collections::BTreeSet<u64>,
    delivered: Vec<u64>,
}

impl OrderedReceiver {
    /// Validates `packet` under `receiver` and, if accepted, takes in its group.
    fn take(&mut self, receiver: &impl Ratchet, mut packet: BytesMut) -> bool {
        let header = packet.split_to(HDP_HEADER_BYTE_LEN);
        let Some((header, _)) = validate_custom(receiver, &header, packet) else {
            return false;
        };
        let group = header.group.get();
        if group >= self.next {
            let _ = self.held.insert(group);
        }
        while self.held.remove(&self.next) {
            self.delivered.push(self.next);
            self.next += 1;
        }
        true
    }
}

fn contiguous(packet: OutboundPacket) -> BytesMut {
    match packet {
        OutboundPacket::Contiguous(packet) => packet,
        other => panic!("a group header is one contiguous packet, got {other:?}"),
    }
}

/// More than a window of messages goes out over the direct route; the receiver gets the first few
/// and the newest stretch (its window moves past everything in between), and no acknowledgement
/// for the rest survives the route. When the route ends, the journal is drained onto the relay
/// through the production resealer: every message must then arrive exactly once, in order.
#[test]
fn more_than_a_window_of_unacknowledged_messages_crosses_to_the_relay_once_and_in_order() {
    const TOTAL: u64 = 2 * HISTORY_LEN + 1;
    const DELIVERED: u64 = 100;
    let (sender, receiver) = connected_pair(LEVEL);
    let time_tracker = TimeTracker::new();
    let target = VirtualTargetType::LocalGroupPeer {
        session_cid: sender.get_cid(),
        peer_cid: receiver.get_cid(),
    };
    let journal = citadel_io::Mutex::new(DirectJournal::default());
    let (direct_tx, mut direct_rx) = unbounded();
    let direct = OutboundPrimaryStreamSender::from(direct_tx);
    for group in 0..TOTAL {
        ObjectTransmitter::transmit_message(
            direct.clone(),
            ObjectId(group as u128),
            sender.clone(),
            RatchetMessage::Truncate(group as u32),
            LEVEL,
            group,
            Ticket(group as u128),
            time_tracker,
            target,
            Some(&journal),
        )
        .unwrap();
    }
    let originals: Vec<BytesMut> = std::iter::from_fn(|| direct_rx.try_recv().ok())
        .map(contiguous)
        .collect();
    assert_eq!(originals.len() as u64, TOTAL);

    // What the dead route took with it; the newest stretch beyond it did arrive.
    let lost_in_flight = DELIVERED..TOTAL - HISTORY_LEN / 2;
    let mut peer = OrderedReceiver::default();
    for (group, packet) in originals.iter().enumerate() {
        let group = group as u64;
        if !lost_in_flight.contains(&group) {
            assert!(peer.take(&receiver, packet.clone()));
        }
        if group < DELIVERED {
            journal.lock().ack(group);
        }
    }
    assert_eq!(peer.delivered.len() as u64, DELIVERED);

    let (relay_tx, mut relay_rx) = unbounded();
    let relay = OutboundPrimaryStreamSender::from(relay_tx);
    let resent = journal
        .lock()
        .drain_onto(&relay, resealer(Some(sender.clone()), time_tracker));
    assert_eq!(resent as u64, TOTAL - DELIVERED);

    let refused = std::iter::from_fn(|| relay_rx.try_recv().ok())
        .map(contiguous)
        .filter(|packet| !peer.take(&receiver, packet.clone()))
        .count();
    assert_eq!(refused, 0, "the receiver refused re-sent messages");
    assert_eq!(peer.delivered, (0..TOTAL).collect::<Vec<_>>());
}
