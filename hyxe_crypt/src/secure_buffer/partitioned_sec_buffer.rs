use crate::prelude::SecBuffer;
use bytes::{BufMut, BytesMut};
use std::ops::{Range, Deref, DerefMut};

/// N determines the number of partitions in the buffer
#[derive(Debug)]
pub struct PartitionedSecBuffer<const N: usize> {
    layout: [u32; N],
    buffer: SecBuffer
}

impl<const N: usize> PartitionedSecBuffer<N> {
    pub fn new() -> std::io::Result<Self> {
        if N != 0 {
            Ok(Self { layout: [0; N], buffer: SecBuffer::empty() })
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Partitions == 0"))
        }
    }

    /// This should only be called once, and called in order. Adds 'len' bytes to buffer at partition index 'idx'
    pub fn reserve_partition(&mut self, idx: usize, len: u32) -> std::io::Result<()> {
        self.check_reserve(idx)?;
        self.buffer.handle().put_bytes(0, len as _);
        self.layout[idx] = len;

        Ok(())
    }

    /// Returns a window to the partition slice
    pub fn partition_window(&mut self, idx: usize) -> std::io::Result<SliceHandle> {
        let range = self.get_range(idx)?;
        Ok(SliceHandle { ptr: &mut self.buffer, range })
    }

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

    fn check_index(&self, idx: usize) -> std::io::Result<()> {
        if idx >= N {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "idx > partitions"))
        } else {
            Ok(())
        }
    }

    fn check_reserve(&self, idx: usize) -> std::io::Result<()> {
        self.check_index(idx)?;
        // make sure current value is unset
        if self.layout[idx] != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Current index already set"))
        }

        // make sure every index before idx has a nonzero value
        for idx in 0..idx {
            if self.layout[idx] == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Previously unset partition detected"))
            }
        }

        // make sure every index after idx has a zero value
        for idx in idx..N {
            if self.layout[idx] != 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Next partitions already set"))
            }
        }

        Ok(())
    }

    pub fn into_buffer(self) -> BytesMut {
        self.buffer.into_buffer()
    }

    pub fn layout(&self) -> &[u32; N] {
        &self.layout
    }
}

pub struct SliceHandle<'a> {
    pub(crate) range: Range<usize>,
    ptr: &'a mut SecBuffer
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

    fn setup_log() {
        std::env::set_var("RUST_LOG", "info");
        let _ = env_logger::try_init();
        log::trace!(target: "lusna", "TRACE enabled");
        log::trace!(target: "lusna", "INFO enabled");
        log::warn!(target: "lusna", "WARN enabled");
        log::error!(target: "lusna", "ERROR enabled");
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_0() {
        setup_log();
        let _ = PartitionedSecBuffer::<0>::new().unwrap();
    }

    #[test]
    fn partitioned_sec_buffer_1_proper() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        assert_eq!(buf.into_buffer(), &vec![1,1,1,1,1,1,1,1,1,1])
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_1_improper() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(1, 10).unwrap();
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_1_improper_2() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<1>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.partition_window(1).unwrap().fill(1);
    }

    #[test]
    fn partitioned_sec_buffer_2_proper() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        buf.partition_window(1).unwrap().fill(2);
        assert_eq!(buf.into_buffer(), &vec![1,1,1,1,1,1,1,1,1,1,2,2,2])
    }

    #[test]
    fn partitioned_sec_buffer_2_proper_2() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.partition_window(1).unwrap().fill(2); // order doesn't matter so long as reserves are set properly
        buf.partition_window(0).unwrap().fill(1);
        assert_eq!(buf.into_buffer(), &vec![1,1,1,1,1,1,1,1,1,1,2,2,2])
    }

    #[test]
    #[should_panic]
    fn partitioned_sec_buffer_2_improper() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<2>::new().unwrap();
        //buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
    }

    #[test]
    fn partitioned_sec_buffer_3_proper() {
        setup_log();
        let mut buf = PartitionedSecBuffer::<3>::new().unwrap();
        buf.reserve_partition(0, 10).unwrap();
        buf.reserve_partition(1, 3).unwrap();
        buf.reserve_partition(2, 5).unwrap();
        buf.partition_window(0).unwrap().fill(1);
        buf.partition_window(1).unwrap().fill(2);
        buf.partition_window(2).unwrap().fill(3);
        assert_eq!(buf.into_buffer(), &vec![1,1,1,1,1,1,1,1,1,1,2,2,2,3,3,3,3,3])
    }
}