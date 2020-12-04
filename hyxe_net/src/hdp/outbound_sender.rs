use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use futures::Sink;
use futures::task::{Context, Poll};
//use futures::channel::mpsc::{UnboundedSender, SendError};
use tokio::sync::mpsc::UnboundedSender;

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
        self.sender.send((idx, packet)).is_ok()
    }

    /// Automatically handles the port rotations
    ///
    /// returns false if the channel is closed, true is success
    pub fn send(&self, packet: Bytes) -> bool {
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
    type Error = ();

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let idx = self.get_and_increment_idx();
        self.sender.send((idx, item)).map_err(|_| ())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}