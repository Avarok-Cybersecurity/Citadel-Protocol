use futures::Stream;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::misc::AccountError;
use citadel_types::proto::{
    ObjectTransferOrientation, ObjectTransferStatus, VirtualObjectMetadata,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Used to keep track of file transfer progress for either
/// sender or receiver orientation
#[derive(Debug)]
pub struct ObjectTransferHandlerInner {
    inner: UnboundedReceiver<ObjectTransferStatus>,
}

#[derive(Debug)]
pub struct ObjectTransferHandler {
    pub source: u64,
    pub receiver: u64,
    pub metadata: VirtualObjectMetadata,
    pub orientation: ObjectTransferOrientation,
    start_recv_tx: Option<tokio::sync::oneshot::Sender<bool>>,
    pub inner: ObjectTransferHandlerInner,
}

impl Stream for ObjectTransferHandlerInner {
    type Item = ObjectTransferStatus;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

impl Deref for ObjectTransferHandler {
    type Target = ObjectTransferHandlerInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ObjectTransferHandler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl ObjectTransferHandler {
    pub fn new(
        source: u64,
        receiver: u64,
        metadata: VirtualObjectMetadata,
        orientation: ObjectTransferOrientation,
        start_recv_tx: Option<tokio::sync::oneshot::Sender<bool>>,
    ) -> (Self, UnboundedSender<ObjectTransferStatus>) {
        let (tx, inner) = unbounded_channel();

        let this = Self {
            inner: ObjectTransferHandlerInner { inner },
            source,
            receiver,
            orientation,
            metadata,
            start_recv_tx,
        };

        (this, tx)
    }

    /// When the local handle type is for a Receiver,
    /// the receiver must accept the transfer before
    /// receiving the data
    pub fn accept(&mut self) -> Result<(), AccountError> {
        self.respond(true)
    }

    /// When the local handle type is for a Receiver,
    /// the receiver can deny a request
    pub fn decline(&mut self) -> Result<(), AccountError> {
        self.respond(false)
    }

    fn respond(&mut self, accept: bool) -> Result<(), AccountError> {
        if matches!(
            self.orientation,
            ObjectTransferOrientation::Receiver {
                is_revfs_pull: true
            }
        ) {
            return Ok(());
        }

        if matches!(self.orientation, ObjectTransferOrientation::Receiver { .. }) {
            self.start_recv_tx
                .take()
                .ok_or_else(|| AccountError::msg("Start_recv_tx already called"))?
                .send(accept)
                .map_err(|err| AccountError::msg(err.to_string()))
        } else {
            Ok(())
        }
    }
}
