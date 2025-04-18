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
use citadel_io::tokio;
use std::collections::HashMap;
use std::time::Instant;

pub struct OrderedChannel<T> {
    sink: tokio::sync::mpsc::UnboundedSender<T>,
    map: HashMap<u64, T>,
    last_message_received: Option<u64>,
    #[allow(dead_code)]
    last_message_received_instant: Option<Instant>,
}

impl<T> OrderedChannel<T> {
    pub fn new(sink: tokio::sync::mpsc::UnboundedSender<T>) -> Self {
        Self {
            sink,
            map: HashMap::new(),
            last_message_received: None,
            last_message_received_instant: None,
        }
    }

    #[allow(unused_results)]
    pub fn on_packet_received(
        &mut self,
        id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        let next_expected_message_id = self
            .last_message_received
            .map(|r| r.wrapping_add(1))
            .unwrap_or(0);
        log::trace!(target: "citadel", "[ORDERED CHANNEL] Received packet with id {id} | Next expected message id: {next_expected_message_id}");
        if next_expected_message_id == id {
            // we send this packet, then scan sequentially for any other packets that may have been delivered until hitting discontinuity
            self.send_then_scan(id, packet)?;
            Ok(())
        } else {
            // we store. Since the next needed packet in order is not yet received, we store and return
            self.store_received_packet(id, packet);
            Ok(())
        }
    }

    #[allow(unused_results)]
    fn store_received_packet(&mut self, id: u64, packet: T) {
        self.map.insert(id, packet);
        self.set_last_message_received_instant();
    }

    fn set_last_message_received_instant(&mut self) {
        self.last_message_received_instant = Some(Instant::now())
    }

    fn set_last_message_received(&mut self, id: u64) {
        self.last_message_received = Some(id)
    }

    fn send_then_scan(
        &mut self,
        new_id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.send_unconditional(new_id, packet)?;
        if !self.map.is_empty() {
            self.scan_send(new_id)
        } else {
            Ok(())
        }
    }

    // Assumes `last_arrived_id` has already been sent through the sink. This function will scan the elements in the hashmap sequentially, sending each enqueued packet, stopping once discontinuity occurs
    fn scan_send(
        &mut self,
        last_arrived_id: u64,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        let mut cur_scan_id = last_arrived_id.wrapping_add(1);
        while let Some(next) = self.map.remove(&cur_scan_id) {
            self.send_unconditional(cur_scan_id, next)?;
            cur_scan_id = cur_scan_id.wrapping_add(1);
        }

        Ok(())
    }

    fn send_unconditional(
        &mut self,
        new_id: u64,
        packet: T,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.sink.send(packet)?;
        self.set_last_message_received(new_id);
        self.set_last_message_received_instant();
        Ok(())
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
        let mut ordered_channel = OrderedChannel::new(tx.clone());
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
        let mut ordered_channel = OrderedChannel::new(tx.clone());
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
                citadel_io::tokio::time::sleep(Duration::from_millis(rnd)).await;
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
