//! Partitioned Secure Buffer Implementation
//!
//! This module provides a secure buffer implementation that supports fixed-size
//! partitioning for efficient memory management and data isolation. Each partition
//! maintains its own boundaries while sharing a single underlying buffer.
//!
//! # Features
//!
//! - Generic over number of partitions
//! - Zero-copy partition access
//! - Boundary-checked partition operations
//! - Memory-safe partition windows
//! - Automatic buffer zeroing
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::secure_buffer::partitioned_sec_buffer::PartitionedSecBuffer;
//!
//! // Create a buffer with 2 partitions
//! let mut buffer = PartitionedSecBuffer::<2>::new().unwrap();
//!
//! // Reserve space in partitions
//! buffer.reserve_partition(0, 32).unwrap(); // 32 bytes for first partition
//! buffer.reserve_partition(1, 64).unwrap(); // 64 bytes for second partition
//!
//! // Access partition windows
//! let mut window = buffer.partition_window(0).unwrap();
//! window.copy_from_slice(&[0u8; 32]); // Write to first partition
//! ```
//!
//! # Important Notes
//!
//! - Partitions must be reserved in order
//! - Partition boundaries are strictly enforced
//! - Buffer is automatically zeroed on drop
//! - Windows provide safe partition access
//!
//! # Related Components
//!
//! - [`SecBuffer`] - Underlying secure buffer
//! - [`crate::secure_buffer::sec_packet`] - Packet buffer implementation
//!

use bytes::{BufMut, BytesMut};
use citadel_types::crypto::SecBuffer;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::ops::{Deref, DerefMut, Range};

/// A secure buffer implementation with N fixed-size partitions
///
/// The buffer is divided into N partitions, each with its own size and boundaries.
/// Partitions must be reserved in order and provide safe, isolated access to their
/// respective memory regions.
///
/// # Type Parameters
///
/// * `N` - Number of partitions in the buffer
///
/// # Fields
///
/// * `layout` - Array storing the size of each partition
/// * `buffer` - Underlying secure buffer storing all partition data
#[derive(Debug, Serialize, Deserialize)]
pub struct PartitionedSecBuffer<const N: usize> {
    #[serde(with = "BigArray")]
    layout: [u32; N],
    buffer: SecBuffer,
}

impl<const N: usize> PartitionedSecBuffer<N> {
    /// Creates a new partitioned secure buffer with N partitions
    ///
    /// # Errors
    ///
    /// Returns an error if the number of partitions is zero
    pub fn new() -> std::io::Result<Self> {
        if N != 0 {
            Ok(Self {
                layout: [0; N],
                buffer: SecBuffer::empty(),
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Partitions == 0",
            ))
        }
    }

    /// Reserves space for a partition at the specified index
    ///
    /// # Parameters
    ///
    /// * `idx` - Index of the partition to reserve
    /// * `len` - Size of the partition in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds, the partition is already reserved,
    /// or if previous partitions have not been reserved
    pub fn reserve_partition(&mut self, idx: usize, len: u32) -> std::io::Result<()> {
        self.check_reserve(idx)?;
        self.buffer.handle().put_bytes(0, len as _);
        self.layout[idx] = len;

        Ok(())
    }

    /// Returns a window to the partition slice at the specified index
    ///
    /// # Parameters
    ///
    /// * `idx` - Index of the partition to access
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds
    pub fn partition_window(&mut self, idx: usize) -> std::io::Result<SliceHandle> {
        let range = self.get_range(idx)?;
        Ok(SliceHandle {
            ptr: &mut self.buffer,
            range,
        })
    }

    /// Returns the range of the partition at the specified index
    ///
    /// # Parameters
    ///
    /// * `idx` - Index of the partition to access
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds
    fn get_range(&self, idx: usize) -> std::io::Result<Range<usize>> {
        self.check_index(idx)?;
        let start_idx = self.layout.iter().take(idx).copied().sum::<u32>() as usize; // at 0, we get 0. At 1, we get the sum of the first partition width
        let end_idx = if idx + 1 == N {
            // this is the final partition. End index is the length
            self.buffer.len()
        } else {
            // this is not the final partition. Take the start index, and add to it the length of the partition at idx
            start_idx + self.layout[idx] as usize
        };

        Ok(start_idx..end_idx)
    }

    /// Checks if the index is within bounds
    ///
    /// # Parameters
    ///
    /// * `idx` - Index to check
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds
    fn check_index(&self, idx: usize) -> std::io::Result<()> {
        if idx >= N {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "idx > partitions",
            ))
        } else {
            Ok(())
        }
    }

    /// Checks if the partition can be reserved
    ///
    /// # Parameters
    ///
    /// * `idx` - Index of the partition to reserve
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds, the partition is already reserved,
    /// or if previous partitions have not been reserved
    fn check_reserve(&self, idx: usize) -> std::io::Result<()> {
        self.check_index(idx)?;
        // make sure current value is unset
        if self.layout[idx] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Current index already set",
            ));
        }

        // make sure every index before idx has a nonzero value
        for idx in 0..idx {
            if self.layout[idx] == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Previously unset partition detected",
                ));
            }
        }

        // make sure every index after idx has a zero value
        for idx in idx..N {
            if self.layout[idx] != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Next partitions already set",
                ));
            }
        }

        Ok(())
    }

    /// Consumes the buffer and returns the underlying bytes
    pub fn into_buffer(self) -> BytesMut {
        self.buffer.into_buffer()
    }

    /// Returns a reference to the partition layout
    pub fn layout(&self) -> &[u32; N] {
        &self.layout
    }
}

/// A handle to a partition slice
pub struct SliceHandle<'a> {
    pub(crate) range: Range<usize>,
    ptr: &'a mut SecBuffer,
}

impl Deref for SliceHandle<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.ptr.as_ref()[self.range.clone()]
    }
}

impl DerefMut for SliceHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ptr.as_mut()[self.range.clone()]
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_buffer::partitioned_sec_buffer::PartitionedSecBuffer;

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_0() {
        citadel_logging::should_panic_test();
        let _ = PartitionedSecBuffer::<0>::new().unwrap();
    }

    #[test]
    fn partitioned_sec_buffer_1_proper() {
        citadel_logging::setup_log();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        assert_eq!(buf.into_buffer(), &vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_1_improper() {
        citadel_logging::should_panic_test();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(1, 10).unwrap();
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_1_improper_2() {
        citadel_logging::should_panic_test();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.partition_window(1).unwrap().fill(1);
    }

    #[test]
    fn partitioned_sec_buffer_2_proper() {
        citadel_logging::setup_log();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        buf.partition_window(1).unwrap().fill(2);
        assert_eq!(
            buf.into_buffer(),
            &vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2]
        )
    }

    #[test]
    fn partitioned_sec_buffer_2_proper_2() {
        citadel_logging::setup_log();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.partition_window(1).unwrap().fill(2); // order doesn't matter so long as reserves are set properly
        buf.partition_window(0).unwrap().fill(1);
        assert_eq!(
            buf.into_buffer(),
            &vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2]
        )
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_2_improper() {
        citadel_logging::should_panic_test();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        //buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
    }

    #[test]
    fn partitioned_sec_buffer_3_proper() {
        citadel_logging::setup_log();
        let mut buf = PartitionedSecBuffer::<3>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.reserve_partition(2, 5).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        buf.partition_window(1).unwrap().fill(2);
        buf.partition_window(2).unwrap().fill(3);
        assert_eq!(
            buf.into_buffer(),
            &vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3]
        )
    }
}
