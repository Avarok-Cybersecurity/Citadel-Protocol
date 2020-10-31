use futures::sync::mpsc::{UnboundedSender, Sender};
use crate::prelude::OutboundItem;
use crate::packet::misc::ConnectError;
use futures::Sink;
use crate::connection::STREAM_SHUTDOWN;

/// Allows the temporary communication with a stream without the overhead of a full-blown [BridgeHandler]. Do to its limitation of use,
/// the only function this allows is sending data and shutting down the stream (after use).
pub struct TemporaryBridge {
    stream_outbound_tx: UnboundedSender<OutboundItem>,
    stream_signal_tx: Sender<u8>
}

impl TemporaryBridge {
    /// Created a new [TemporaryBridge] capable of communicating with the underlying stream
    pub fn new(stream_outbound_tx: UnboundedSender<OutboundItem>, stream_signal_tx: Sender<u8>) -> Self {
        Self {stream_outbound_tx, stream_signal_tx }
    }

    /// Sends data outbound
    pub fn send<T: AsRef<[u8]>>(&self, data: &T) -> Result<(), ConnectError> {
        self.stream_outbound_tx.unbounded_send(data.as_ref().to_vec())
            .map_err(|err| ConnectError::Generic(err.to_string()))
    }

    /// This should be called before the item is dropped
    pub fn shutdown(&mut self) -> Result<(), ConnectError> {
        self.stream_signal_tx.try_send(STREAM_SHUTDOWN)
            .map_err(|err| ConnectError::Generic(err.to_string()))
    }
}