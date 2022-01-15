use std::sync::atomic::{AtomicUsize, Ordering};
use crate::connection::stream_wrappers::old::RawInboundItem;
use std::pin::Pin;
use crate::packet::inbound::stage_driver::StageDriverPacket;
use hyxe_netdata::packet::StageDriverPacket;

/// This is a small abstraction for adding data within known start points. This does not check to see if overlaps are detected, and as such, this
/// cannot detect any index errors
#[repr(C)]
pub struct DataReconstructor {
    packet: Pin<Box<RawInboundItem>>,
    /// Whenever data is added into the vector above, the number of bytes herein is incremented. Once the `bytes_reconstructed`
    /// is equal to the capacity of the vec, the future completes
    bytes_reconstructed: AtomicUsize,
    bytes_needed: usize
}

impl DataReconstructor {
    /// This allocates a vector, sets its length, and returns Self
    /// `offset`: The absolute position from where to begin counting the data chunk. In the case of a packet,
    /// the offset should be the start index of the payload.
    /// `expected_length`: The size of the payload alone in bytes
    pub fn new(packet: RawInboundItem, offset: usize, expected_length: usize) -> Self {
        let mut this = Self { packet: Box::pin(packet), bytes_reconstructed: AtomicUsize::new(0), bytes_needed: expected_length };
        this.packet.data.reserve(expected_length); //forces the allocator to make room to allow for direct insertion of indexes
        unsafe { this.packet.data.set_len(offset) };
        this
    }

    /// Places data into the correct index and increments the number of bytes reconstructed.
    /// Return Ok(true) if finished, or Ok(false) if not yet finished. Return Err(()) if the indexes are off
    pub fn add_data<R: AsRef<[u8]>>(&mut self, starting_point: usize, input: R) -> Result<bool, ()> {
        let input = input.as_ref();
        let input_len = input.len();
        if starting_point + input_len > self.packet.data.capacity() {
            Err(())
        } else {
            let _ = self.bytes_reconstructed.fetch_add(input_len, Ordering::SeqCst);
            let vec_ptr = self.packet.get_payload_mut_ptr();
            let mut counter = 0;
            for idx in starting_point..(starting_point + input_len) {
                // This is a safe operation because we already used the resize function in the constructor as well.
                // We are derefing a raw pointer instead of using IndexMut to skip additional bounds checks. This gives
                // us greater performance
                unsafe { *vec_ptr.add(idx) = input[counter] };
                counter += 1;
            }

            Ok(self.is_finished())
        }
    }

    /// Determines if the reconstruction process is complete
    pub fn is_finished(&self) -> bool {
        self.bytes_needed == self.bytes_reconstructed.load(Ordering::Relaxed)
    }

    /// Returns a pointer to the heap-pinned packet
    pub fn get_packet_ptr(&self) -> StageDriverPacket {
        StageDriverPacket::from(&self.packet)
    }
}