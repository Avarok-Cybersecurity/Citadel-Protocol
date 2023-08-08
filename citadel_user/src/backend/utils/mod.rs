use crate::serialization::SyncIO;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::misc::AccountError;
use citadel_crypt::misc::TransferType;
use citadel_crypt::prelude::SecurityLevel;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VirtualObjectMetadata {
    pub name: String,
    pub date_created: String,
    pub author: String,
    pub plaintext_length: usize,
    pub group_count: usize,
    pub object_id: u32,
    pub cid: u64,
    pub transfer_type: TransferType,
}

impl VirtualObjectMetadata {
    pub fn serialize(&self) -> Vec<u8> {
        Self::serialize_to_vector(self).unwrap()
    }

    pub fn deserialize_from<'a, T: AsRef<[u8]> + 'a>(input: T) -> Option<Self> {
        Self::deserialize_from_vector(input.as_ref()).ok()
    }

    pub fn get_security_level(&self) -> Option<SecurityLevel> {
        match &self.transfer_type {
            TransferType::FileTransfer => None,
            TransferType::RemoteEncryptedVirtualFilesystem { security_level, .. } => {
                Some(*security_level)
            }
        }
    }
}

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
        orientation: ObjectTransferOrientation,
        start_recv_tx: Option<tokio::sync::oneshot::Sender<bool>>,
    ) -> (Self, UnboundedSender<ObjectTransferStatus>) {
        let (tx, inner) = unbounded_channel();

        let this = Self {
            inner: ObjectTransferHandlerInner { inner },
            source,
            receiver,
            orientation,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ObjectTransferOrientation {
    Receiver { is_revfs_pull: bool },
    Sender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum ObjectTransferStatus {
    TransferBeginning,
    ReceptionBeginning(PathBuf, VirtualObjectMetadata),
    // relative group_id, total groups, Mb/s
    TransferTick(usize, usize, f32),
    ReceptionTick(usize, usize, f32),
    TransferComplete,
    ReceptionComplete,
    Fail(String),
}

impl ObjectTransferStatus {
    pub fn is_tick_type(&self) -> bool {
        matches!(
            self,
            ObjectTransferStatus::TransferTick(_, _, _)
                | ObjectTransferStatus::ReceptionTick(_, _, _)
        )
    }

    /// Even if an error, returns true if the file transfer is done
    pub fn is_finished_type(&self) -> bool {
        matches!(
            self,
            ObjectTransferStatus::TransferComplete
                | ObjectTransferStatus::ReceptionComplete
                | ObjectTransferStatus::Fail(_)
        )
    }
}

impl std::fmt::Display for ObjectTransferStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectTransferStatus::TransferBeginning => {
                write!(f, "Transfer beginning")
            }

            ObjectTransferStatus::ReceptionBeginning(_, vfm) => {
                write!(f, "Download for object {vfm:?} beginning")
            }

            ObjectTransferStatus::TransferTick(relative_group_id, total_groups, transfer_rate) => {
                print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            ObjectTransferStatus::ReceptionTick(relative_group_id, total_groups, transfer_rate) => {
                print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            ObjectTransferStatus::TransferComplete => {
                write!(f, "Transfer complete")
            }

            ObjectTransferStatus::ReceptionComplete => {
                write!(f, "Download complete")
            }

            ObjectTransferStatus::Fail(reason) => {
                write!(f, "Failure. Reason: {reason}")
            }
        }
    }
}

fn print_tick(
    f: &mut Formatter<'_>,
    relative_group_id: usize,
    total_groups: usize,
    transfer_rate: f32,
) -> std::fmt::Result {
    if can_print_progress(relative_group_id, total_groups) {
        write!(
            f,
            " ({}% @ {} MB/s) ",
            get_progress_percent(relative_group_id, total_groups),
            transfer_rate
        )
    } else {
        write!(f, "...")
    }
}

/// There are two boundaries when this returns false: when the relative group ID == 0 (first) || == total_groups -1 (last)
/// Then, there are intermediate points in a cycle when this returns false
fn can_print_progress(relative_group_id: usize, total_groups: usize) -> bool {
    if relative_group_id != 0 && relative_group_id != total_groups - 1 {
        // suppose the total # of groups is n. We want to print out only every v% complete (where 0 < v < 1)
        // Let floor(n * v) = k. Thus every k relative_group_id's, a print out occurs.
        // Thus, if r = the current relative group id, then print-out when:
        // [r mod k == 0] <==> [r mod floor(n*v) == 0]
        // if total_groups < v, then each time a print-out occurs (except end points, per above condition)
        const V: f32 = 0.1;
        relative_group_id % (total_groups as f32 * V).ceil() as usize == 0
    } else {
        false
    }
}

fn get_progress_percent(relative_group_id: usize, total_groups: usize) -> f32 {
    100f32 * (relative_group_id as f32 / total_groups as f32)
}
