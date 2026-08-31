//! Ordered Channel Implementation
//!
//! This module provides an implementation of a channel that maintains message ordering
//! guarantees. It ensures that messages are delivered in the same order they were sent,
//! which is crucial for protocol operations.
//!
//! # Features
//!
//! - Strict message ordering
//! - Asynchronous operation
//! - Backpressure support
//! - Error propagation
//! - Channel state tracking
//!
//! # Important Notes
//!
//! - Messages are delivered in order
//! - Supports multiple producers
//! - Single consumer design
//! - Thread-safe operation
//! - Handles channel closure
//!
//! # Related Components
//!
//! - `kernel_communicator.rs`: Message handling
//! - `session.rs`: Session management
//! - `clean_shutdown.rs`: Resource cleanup
//! - `net.rs`: Network operations
use citadel_io::time::Instant;
use citadel_io::tokio;
use std::collections::HashMap;

/// Interior-mutable reorder state. Held behind a `Mutex` so `on_packet_received` takes `&self`,
/// which lets the per-vconn delivery path run under a shared *read* lock on the StateContainer
/// instead of serializing every vconn's messages on one write lock (the multi-vconn convoy).
struct OrderedChannelState<T> {
    map: HashMap<u64, T>,
    /// Ids that will never arrive here, so the scan must step over them.
    skipped: std::collections::HashSet<u64>,
    last_message_received: Option<u64>,
    last_message_received_instant: Option<Instant>,
}

pub struct OrderedChannel<T> {
    // `UnboundedSender::send` already takes `&self`; only the reorder bookkeeping needs guarding.
    sink: tokio::sync::mpsc::UnboundedSender<T>,
    state: citadel_io::Mutex<OrderedChannelState<T>>,
}

impl<T> OrderedChannel<T> {
    pub fn new(sink: tokio::sync::mpsc::UnboundedSender<T>) -> Self {
        Self {
            sink,
            state: citadel_io::Mutex::new(OrderedChannelState {
                map: HashMap::new(),
                skipped: std::collections::HashSet::new(),
                last_message_received: None,
                last_message_received_instant: None,
            }),
        }
    }

    #[allow(unused_results)]
    pub fn on_packet_received(
        &self,
        id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        let mut state = self.state.lock();

        let next_expected_message_id = state
            .last_message_received
            .map(|r| r.wrapping_add(1))
            .unwrap_or(0);
        log::trace!(target: "citadel", "[ORDERED CHANNEL] Received packet with id {id} | Next expected message id: {next_expected_message_id}");
        if next_expected_message_id == id {
            // we send this packet, then scan sequentially for any other packets that may have been delivered until hitting discontinuity
            self.send_then_scan(&mut state, id, packet)
        } else if Self::is_already_delivered(state.last_message_received, id) {
            // The id is at or below the highest id already forwarded in order (a duplicate /
            // retransmission / replay). The forward-only `scan_send` never revisits ids <= the last
            // delivered one, so inserting it into the reorder map would retain it forever — an
            // unbounded per-channel memory leak driven purely by duplicate inbound packets. Dropping
            // it is behavior-preserving for the consumer: it already received this id in order.
            log::trace!(target: "citadel", "[ORDERED CHANNEL] Dropping already-delivered/duplicate packet id {id} (last delivered: {:?})", state.last_message_received);
            Ok(())
        } else {
            // we store. Since the next needed packet in order is not yet received, we store and return
            state.map.insert(id, packet);
            state.last_message_received_instant = Some(Instant::now());
            Ok(())
        }
    }

    /// Declares that `id` will never arrive as a message on this channel.
    ///
    /// The sequence ids are the endpoint's group ids, and object transfers draw
    /// from the SAME counter as messages (session.rs reserves group ids for a
    /// file exactly as it takes one for a message). Those groups are handled by
    /// the transfer path and never reach this channel, so without this the very
    /// next message waits for an id that does not exist -- and so does every
    /// message after it, for the life of the connection.
    ///
    /// Idempotent, and safe to call for an id already delivered or already
    /// skipped.
    pub fn skip(&self, id: u64) {
        let mut state = self.state.lock();
        if Self::is_already_delivered(state.last_message_received, id) {
            return;
        }
        let _ = state.skipped.insert(id);
        let next_expected = state
            .last_message_received
            .map(|r| r.wrapping_add(1))
            .unwrap_or(0);
        if next_expected == id {
            // Step over it now and release anything queued behind it.
            let _ = state.skipped.remove(&id);
            state.last_message_received = Some(id);
            state.last_message_received_instant = Some(Instant::now());
            if let Err(err) = self.scan_send(&mut state, id) {
                log::warn!(target: "citadel", "[ORDERED CHANNEL] Consumer gone while draining past skipped id {id}: {err}");
            }
        }
    }

    /// Returns `true` if `id` has already been forwarded in order, i.e. it is at or below the
    /// highest delivered id. Such ids can never be delivered again by the forward-only reorder scan,
    /// so they must be dropped rather than buffered.
    #[inline]
    fn is_already_delivered(last_message_received: Option<u64>, id: u64) -> bool {
        match last_message_received {
            Some(last) => id <= last,
            None => false,
        }
    }

    /// Number of out-of-order packets currently held in the reorder buffer. Exposed for tests that
    /// assert the buffer does not retain duplicates.
    #[cfg(test)]
    pub(crate) fn pending_reorder_count(&self) -> usize {
        self.state.lock().map.len()
    }

    fn send_then_scan(
        &self,
        state: &mut OrderedChannelState<T>,
        new_id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.send_unconditional(state, new_id, packet)?;
        if !state.map.is_empty() {
            self.scan_send(state, new_id)
        } else {
            Ok(())
        }
    }

    // Assumes `last_arrived_id` has already been sent through the sink. This function will scan the elements in the hashmap sequentially, sending each enqueued packet, stopping once discontinuity occurs
    fn scan_send(
        &self,
        state: &mut OrderedChannelState<T>,
        last_arrived_id: u64,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        let mut cur_scan_id = last_arrived_id.wrapping_add(1);
        loop {
            // An id declared non-message by `skip` is stepped over rather than
            // waited for; nothing is delivered for it.
            if state.skipped.remove(&cur_scan_id) {
                state.last_message_received = Some(cur_scan_id);
                state.last_message_received_instant = Some(Instant::now());
                cur_scan_id = cur_scan_id.wrapping_add(1);
                continue;
            }
            let Some(next) = state.map.remove(&cur_scan_id) else {
                break;
            };
            self.send_unconditional(state, cur_scan_id, next)?;
            cur_scan_id = cur_scan_id.wrapping_add(1);
        }

        Ok(())
    }

    fn send_unconditional(
        &self,
        state: &mut OrderedChannelState<T>,
        new_id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.sink.send(packet)?;
        state.last_message_received = Some(new_id);
        state.last_message_received_instant = Some(Instant::now());
        Ok(())
    }
}

#[cfg(test)]
mod skipped_group_tests {
    use super::OrderedChannel;
    use citadel_io::tokio;

    /// A group id consumed by an object transfer must not stall the channel.
    ///
    /// Object transfers and messages draw group ids from the same per-endpoint
    /// counter, and this channel is sequenced by that id. Before `skip`, the
    /// first message after any file transfer waited for an id that would never
    /// arrive, and so did every message after it -- for the life of the
    /// connection, while the sender's send kept reporting success.
    #[tokio::test]
    async fn a_skipped_id_does_not_hold_up_later_messages() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let channel = OrderedChannel::new(tx);

        channel.on_packet_received(0, 0).unwrap();
        assert_eq!(rx.recv().await, Some(0));

        // id 1 goes to the transfer path and never arrives here.
        channel.skip(1);
        channel.on_packet_received(2, 2).unwrap();

        assert_eq!(
            rx.recv().await,
            Some(2),
            "the message after a transfer never arrived -- the channel is stalled on the skipped id"
        );
    }

    /// The skip may arrive after the messages queued behind it.
    #[tokio::test]
    async fn a_late_skip_releases_what_was_already_buffered() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let channel = OrderedChannel::new(tx);

        channel.on_packet_received(0, 0).unwrap();
        assert_eq!(rx.recv().await, Some(0));

        channel.on_packet_received(2, 2).unwrap();
        channel.on_packet_received(3, 3).unwrap();
        assert!(
            rx.try_recv().is_err(),
            "both must wait while id 1 is still expected"
        );

        channel.skip(1);

        assert_eq!(
            rx.recv().await,
            Some(2),
            "buffered messages were not released by the skip"
        );
        assert_eq!(rx.recv().await, Some(3));
    }

    /// Ordinary ordering is untouched: a real gap still waits.
    #[tokio::test]
    async fn an_unskipped_gap_still_preserves_order() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let channel = OrderedChannel::new(tx);

        channel.on_packet_received(0, 0).unwrap();
        assert_eq!(rx.recv().await, Some(0));

        channel.on_packet_received(2, 2).unwrap();
        assert!(rx.try_recv().is_err(), "id 2 must wait for id 1");

        channel.on_packet_received(1, 1).unwrap();
        assert_eq!(rx.recv().await, Some(1), "in-order delivery broken");
        assert_eq!(rx.recv().await, Some(2));
    }
}

#[cfg(test)]
mod tests {
    use crate::ordered_channel::OrderedChannel;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::RwLock;
    use citadel_types::crypto::SecBuffer;
    use futures::StreamExt;
    use rand::prelude::SliceRandom;
    use rand::rngs::ThreadRng;
    use rand::Rng;
    use std::error::Error;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn smoke_ordered() -> Result<(), Box<dyn Error>> {
        citadel_logging::setup_log();
        const COUNT: u8 = 100;
        let (tx, mut rx) = unbounded_channel::<SecBuffer>();
        let ordered_channel = OrderedChannel::new(tx.clone());
        let values_ordered = (0..COUNT)
            .map(|r| (r as _, SecBuffer::from(&[r] as &[u8])))
            .collect::<Vec<(u64, SecBuffer)>>();

        let recv_task = async move {
            let mut id = 0;
            while let Some(value) = rx.recv().await {
                assert_eq!(id, value.as_ref()[0]);
                id += 1;

                if id >= COUNT {
                    return;
                }
            }
        };

        let recv_handle = citadel_io::tokio::task::spawn(recv_task);

        for (id, packet) in values_ordered {
            ordered_channel.on_packet_received(id, packet)?;
        }

        recv_handle.await?;

        Ok(())
    }

    #[tokio::test]
    async fn smoke_unordered() -> Result<(), Box<dyn Error>> {
        citadel_logging::setup_log();
        const COUNT: usize = 1000;
        let (tx, mut rx) = unbounded_channel::<SecBuffer>();
        let ordered_channel = OrderedChannel::new(tx.clone());
        let mut values_ordered = (0..COUNT)
            .map(|r| {
                (
                    r as _,
                    SecBuffer::from(&[(r % (u8::MAX as usize)) as u8] as &[u8]),
                )
            })
            .collect::<Vec<(u64, SecBuffer)>>();

        values_ordered[..].shuffle(&mut ThreadRng::default());

        let values_unordered = values_ordered;

        //log::trace!(target: "citadel", "Unordered input: {:?}", &values_unordered);
        let recv_task = async move {
            let mut id: usize = 0;
            while let Some(value) = rx.recv().await {
                assert_eq!((id % u8::MAX as usize) as u8, value.as_ref()[0]);
                id += 1;

                if id >= COUNT {
                    return;
                }
            }
        };

        let recv_handle = citadel_io::tokio::task::spawn(recv_task);

        for (id, packet) in values_unordered {
            ordered_channel.on_packet_received(id, packet)?;
        }

        recv_handle.await?;

        Ok(())
    }

    #[tokio::test]
    async fn duplicate_ids_are_not_buffered() -> Result<(), Box<dyn Error>> {
        citadel_logging::setup_log();
        let (tx, mut rx) = unbounded_channel::<SecBuffer>();
        let ordered_channel = OrderedChannel::new(tx);

        // Deliver 0, 1, 2 in order.
        for id in 0..3u64 {
            ordered_channel.on_packet_received(id, SecBuffer::from(&[id as u8] as &[u8]))?;
        }
        assert_eq!(ordered_channel.pending_reorder_count(), 0);

        // Re-deliver already-forwarded ids (duplicates / retransmissions). These must be dropped, not
        // retained in the reorder buffer (otherwise an attacker/lossy link can grow it without bound).
        for id in [0u64, 1, 2, 0, 2] {
            ordered_channel.on_packet_received(id, SecBuffer::from(&[0xFFu8] as &[u8]))?;
        }
        assert_eq!(
            ordered_channel.pending_reorder_count(),
            0,
            "duplicate, already-delivered ids must not be buffered"
        );

        // A genuine future-but-out-of-order id is still buffered (gap at id 3).
        ordered_channel.on_packet_received(5, SecBuffer::from(&[5u8] as &[u8]))?;
        assert_eq!(ordered_channel.pending_reorder_count(), 1);
        // Re-sending that buffered id is a no-op for the buffer size (overwrite, not growth).
        ordered_channel.on_packet_received(5, SecBuffer::from(&[5u8] as &[u8]))?;
        assert_eq!(ordered_channel.pending_reorder_count(), 1);

        // Filling the gap drains the buffer and resumes in-order delivery.
        ordered_channel.on_packet_received(3, SecBuffer::from(&[3u8] as &[u8]))?;
        ordered_channel.on_packet_received(4, SecBuffer::from(&[4u8] as &[u8]))?;
        assert_eq!(ordered_channel.pending_reorder_count(), 0);

        // Exactly ids 0..=5 must have been delivered in order, each once.
        let mut delivered = Vec::new();
        while let Ok(value) = rx.try_recv() {
            delivered.push(value.as_ref()[0]);
        }
        assert_eq!(delivered, vec![0, 1, 2, 3, 4, 5]);

        Ok(())
    }

    #[citadel_io::tokio::test]
    async fn smoke_unordered_concurrent() -> Result<(), Box<dyn Error>> {
        const COUNT: usize = 10000;
        let (tx, mut rx) = unbounded_channel::<SecBuffer>();
        let ordered_channel = OrderedChannel::new(tx.clone());
        let mut values_ordered = (0..COUNT)
            .map(|r| {
                (
                    r as _,
                    SecBuffer::from(&[(r % (u8::MAX as usize)) as u8] as &[u8]),
                )
            })
            .collect::<Vec<(u64, SecBuffer)>>();

        values_ordered[..].shuffle(&mut ThreadRng::default());

        let values_unordered = values_ordered;

        let ordered_channel = &Arc::new(RwLock::new(ordered_channel));

        //log::trace!(target: "citadel", "Unordered input: {:?}", &values_unordered);
        let recv_task = async move {
            let mut id: usize = 0;
            while let Some(value) = rx.recv().await {
                assert_eq!((id % u8::MAX as usize) as u8, value.as_ref()[0]);
                id += 1;

                if id >= COUNT {
                    return;
                }
            }
        };

        let recv_handle = citadel_io::tokio::task::spawn(recv_task);

        citadel_io::tokio_stream::iter(values_unordered)
            .for_each_concurrent(None, |(id, packet)| async move {
                let rnd = ThreadRng::default().gen_range(1..10);
                citadel_io::time::sleep(Duration::from_millis(rnd)).await;
                ordered_channel
                    .write()
                    .await
                    .on_packet_received(id, packet)
                    .unwrap();
            })
            .await;

        recv_handle.await?;

        Ok(())
    }
}
