use futures::channel::mpsc::{UnboundedSender, SendError};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::{Sink, SinkExt};
use futures::task::{Context, Poll};
use std::pin::Pin;

/// For keeping the firewall open
pub static KEEP_ALIVE: Bytes = Bytes::from_static(b"ACK");

#[derive(Clone)]
pub struct OutboundUdpSender {
    sender: UnboundedSender<(usize, Bytes)>,
    total_local_ports: usize,
    rolling_idx: Arc<AtomicUsize>

}

unsafe impl Send for OutboundUdpSender {}
unsafe impl Sync for OutboundUdpSender {}

impl OutboundUdpSender {
    pub fn new(sender: UnboundedSender<(usize, Bytes)>, total_local_ports: usize) -> Self {
        let rolling_idx = Arc::new(AtomicUsize::new(0));
        Self { sender, total_local_ports, rolling_idx}
    }

    #[inline]
    pub fn send_with_idx(&self, idx: usize, packet: Bytes) -> bool {
        self.sender.unbounded_send((idx, packet)).is_ok()
    }

    /// Automatically handles the port rotations
    ///
    /// returns false if the channel is closed, true is success
    pub fn unbounded_send(&self, packet: Bytes) -> bool {
        let idx = self.get_and_increment_idx();
        self.send_with_idx(idx, packet)
    }

    pub fn send_keep_alive_through_all(&self) -> bool {
        for idx in 0..self.total_local_ports {
            if !self.send_with_idx(idx, KEEP_ALIVE.clone()) {
                return false;
            }
        }

        true
    }

    // Get and increments value (mod total_local_ports)
    fn get_and_increment_idx(&self) -> usize {
        let total_local_ports = self.total_local_ports;
        let prev = self.rolling_idx.load(Ordering::Relaxed);
        let next = (prev + 1) % total_local_ports;
        self.rolling_idx.store(next, Ordering::Relaxed);
        prev
    }
}


impl Sink<Bytes> for OutboundUdpSender {
    type Error = SendError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let idx = self.get_and_increment_idx();
        self.sender.start_send((idx, item))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_close_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_close_unpin(cx)
    }
}