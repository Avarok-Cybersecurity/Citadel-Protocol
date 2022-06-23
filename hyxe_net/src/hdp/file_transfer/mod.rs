use serde::{Serialize, Deserialize};
use std::fmt::Formatter;
use hyxe_user::serialization::SyncIO;
use crate::hdp::outbound_sender::{unbounded, UnboundedSender, UnboundedReceiver};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VirtualFileMetadata {
    pub name: String,
    pub date_created: String,
    pub author: String,
    pub plaintext_length: usize,
    pub group_count: usize,
    pub object_id: u32
}

impl VirtualFileMetadata {
    pub fn serialize(&self) -> Vec<u8> {
        Self::serialize_to_vector(self).unwrap()
    }

    pub fn deserialize_from<'a, T: AsRef<[u8]> + 'a>(input: T) -> Option<Self> {
        Self::deserialize_from_vector(input.as_ref()).ok()
    }
}

/// Used to keep track of file transfer progress for either
/// sender or receiver orientation
#[derive(Debug)]
pub struct FileTransferHandle {
    inner: UnboundedReceiver<FileTransferStatus>,
    pub source: u64,
    pub receiver: u64,
    pub orientation: FileTransferOrientation
}

impl Stream for FileTransferHandle {
    type Item = FileTransferStatus;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

impl FileTransferHandle {
    pub fn new(source: u64, receiver: u64, orientation: FileTransferOrientation) -> (Self, UnboundedSender<FileTransferStatus>) {
        let (tx, inner) = unbounded();

        let this = Self {
            inner,
            source,
            receiver,
            orientation
        };

        (this, tx)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileTransferOrientation {
    Receiver, Sender
}

#[derive(Debug, Clone)]
#[allow(variant_size_differences)]
pub enum FileTransferStatus {
    TransferBeginning,
    ReceptionBeginning(PathBuf, VirtualFileMetadata),
    // relative group_id, total groups, Mb/s
    TransferTick(usize, usize, f32),
    ReceptionTick(usize, usize, f32),
    TransferComplete,
    ReceptionComplete,
    Fail(String)
}

impl FileTransferStatus {
    pub fn is_tick_type(&self) -> bool {
        match self {
            FileTransferStatus::TransferTick(_, _, _) | FileTransferStatus::ReceptionTick(_, _, _) => true,
            _ => false
        }
    }

    /// Even if an error, returns true if the file transfer is done
    pub fn is_finished_type(&self) -> bool {
        match self {
            FileTransferStatus::TransferComplete | FileTransferStatus::ReceptionComplete | FileTransferStatus::Fail(_) => true,
            _ => false
        }
    }
}

impl std::fmt::Display for FileTransferStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileTransferStatus::TransferBeginning => {
                write!(f, "Transfer beginning")
            }

            FileTransferStatus::ReceptionBeginning(_, vfm) => {
                write!(f, "Download for object {} beginning | Total size: {} bytes | Name: {}", vfm.object_id, vfm.plaintext_length, vfm.name)
            }

            FileTransferStatus::TransferTick(relative_group_id, total_groups, transfer_rate) => {
                print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            FileTransferStatus::ReceptionTick(relative_group_id, total_groups, transfer_rate) => {
                print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            FileTransferStatus::TransferComplete => {
                write!(f, "Transfer complete")
            }

            FileTransferStatus::ReceptionComplete => {
                write!(f, "Download complete")
            }

            FileTransferStatus::Fail(reason) => {
                write!(f, "Failure. Reason: {}", reason)
            }
        }
    }
}

fn print_tick(f: &mut Formatter<'_>, relative_group_id: usize, total_groups: usize, transfer_rate: f32) -> std::fmt::Result {
    if can_print_progress(relative_group_id, total_groups) {
        write!(f, " ({}% @ {} MB/s) ", get_progress_percent(relative_group_id, total_groups), transfer_rate)
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