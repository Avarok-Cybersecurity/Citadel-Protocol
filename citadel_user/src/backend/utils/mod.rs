//! Backend Object Transfer Utilities
//!
//! This module provides utilities for handling object transfers between peers in the
//! Citadel network, managing both sending and receiving operations asynchronously.
//!
//! # Features
//!
//! * **Transfer Management**
//!   - Bidirectional file transfers
//!   - Progress tracking
//!   - Transfer status updates
//!   - Stream-based operations
//!
//! * **Control Flow**
//!   - Transfer acceptance/rejection
//!   - Stream exhaustion
//!   - Error handling
//!   - Resource cleanup
//!
//! * **Async Support**
//!   - Non-blocking operations
//!   - Channel-based communication
//!   - Task coordination
//!   - Resource management
//!
//! # Important Notes
//!
//! * Transfer handlers must be properly closed
//! * Receivers must explicitly accept transfers
//! * Progress updates are streamed asynchronously
//! * Resource cleanup is automatic on drop
//! * Transfer orientation determines available operations
//!
//! # Related Components
//!
//! * `BackendConnection` - Uses transfer utilities
//! * `VirtualObjectMetadata` - Transfer metadata
//! * `ObjectTransferStatus` - Progress updates
//! * `AccountManager` - Initiates transfers

use futures::Stream;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::misc::AccountError;
use citadel_io::tokio;
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
    start_recv_tx: FileTransferStarter,
    pub inner: ObjectTransferHandlerInner,
}

#[derive(Debug)]
pub struct FileTransferStarter {
    inner: Option<tokio::sync::oneshot::Sender<bool>>,
}

impl Deref for FileTransferStarter {
    type Target = Option<tokio::sync::oneshot::Sender<bool>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for FileTransferStarter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for FileTransferStarter {
    fn drop(&mut self) {
        if self.inner.is_some() {
            log::warn!(target: "citadel", "FileTransferStarter dropped without being used");
        }
    }
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
            start_recv_tx: FileTransferStarter {
                inner: start_recv_tx,
            },
        };

        (this, tx)
    }

    /// Exhausts the steam, independently of the orientation
    /// If the orientation is Sender, this will return no path
    /// If the orientation is Receiver, this will return the path of the received file
    pub async fn exhaust_stream(&mut self) -> Result<Option<PathBuf>, AccountError> {
        self.accept()?;

        let mut save_path = None;
        while let Some(event) = self.inner.inner.recv().await {
            match event {
                ObjectTransferStatus::ReceptionBeginning(path, _) => {
                    save_path = Some(path);
                }
                ObjectTransferStatus::ReceptionComplete => {
                    return Ok(save_path);
                }

                ObjectTransferStatus::TransferComplete => {
                    return Ok(None);
                }

                ObjectTransferStatus::Fail(err) => {
                    return Err(AccountError::msg(err));
                }

                _ => {}
            }
        }

        Err(AccountError::msg("Failed to receive file: stream ended"))
    }

    /// Receives the file, exhausting the underlying stream and returning the save path
    /// after completion.
    ///
    /// If the orientation is Sender, this will return an error
    pub async fn receive_file(&mut self) -> Result<PathBuf, AccountError> {
        if !matches!(self.orientation, ObjectTransferOrientation::Receiver { .. }) {
            return Err(AccountError::msg(
                "Cannot receive file: orientation is not Receiver",
            ));
        }

        let file = self.exhaust_stream().await?;
        file.ok_or_else(|| AccountError::msg("Failed to receive file: no file path"))
    }

    /// Transfers the file, exhausting the underlying stream
    ///
    /// If the orientation is Receiver, this will return an error
    pub async fn transfer_file(&mut self) -> Result<(), AccountError> {
        if !matches!(self.orientation, ObjectTransferOrientation::Sender { .. }) {
            return Err(AccountError::msg(
                "Cannot transfer file: orientation is not Sender",
            ));
        }

        let file = self.exhaust_stream().await?;
        if file.is_some() {
            Err(AccountError::msg("An unexpected error occurred: file transfer occurred, yet, returned a save path. Please report to developers"))
        } else {
            Ok(())
        }
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
        if let Some(tx) = self.start_recv_tx.take() {
            tx.send(accept)
                .map_err(|_| AccountError::msg("Failed to send response"))?;
        }

        Ok(())
    }
}
