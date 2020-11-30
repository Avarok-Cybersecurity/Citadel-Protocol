use nanoserde::{SerBin, DeBin};
use hyxe_user::re_imports::export::Formatter;

#[derive(SerBin, DeBin, Debug, Clone)]
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
        SerBin::serialize_bin(self)
    }

    pub fn deserialize_from<T: AsRef<[u8]>>(input: T) -> Option<Self> {
        DeBin::deserialize_bin(input.as_ref()).ok()
    }
}

#[derive(Debug, Clone)]
#[allow(variant_size_differences)]
pub enum FileTransferStatus {
    TransferBeginning,
    ReceptionBeginning(VirtualFileMetadata),
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

            FileTransferStatus::ReceptionBeginning(vfm) => {
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