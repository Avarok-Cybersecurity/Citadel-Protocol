use std::alloc::Layout;
use crate::misc::{CryptError, munlock, mlock};
use rand::random;
use secstr::SecVec;

/// This is simply to help promote the idea that small data types ONLY should be guarded with the
/// [EncryptedMemoryArtifact].
pub const MAX_DATA_SIZE: usize = 256;

/// Provides the encryption type
pub enum EncryptionType {
    /// The caesarian shift is one of the most basic forms of encryption
    CaesarianShift,
    /// The drill provides a much more complex form of encryption
    Drill,
    /// Using both may also be advantageous
    Both
}

/// A datatype which uses both drilling and pointer-scattering to store information to RAM non-continuously.
/// This datatype should NOT be used for long types, as this does cost performance for the added
/// security. This is optimal for storing password types to RAM. This ends-up being more efficient
/// then encrypting data to the disk and flushing the data from memory cyclically, but that doesn't say much.
///
/// This is a costly, yet very safe way of handling sensitive data types
pub struct EncryptedMemoryArtifact {
    /// A vector which stores atomic pointers to memory. Upon dropping, the pointer and pointees
    /// get zeroed-out from RAM
    data: Vec<*mut u8>,
    /// Stores the layouts
    layout: Vec<Layout>,
    dummy_ptrs: Vec<(*mut u8, Layout)>,
    total_len: usize
}


unsafe impl Send for EncryptedMemoryArtifact {}
unsafe impl Sync for EncryptedMemoryArtifact {}

/// Zeroes-out the memory and deallocs the information
impl Drop for EncryptedMemoryArtifact {
    fn drop(&mut self) {
        unsafe {
            let mut layout_get_idx = 0;
            if self.layout.len() == 2 {
                let mut_ptr = self.data[0];
                *mut_ptr = 0;
                munlock(mut_ptr as *const u8, 1);
                std::alloc::dealloc(mut_ptr, self.layout[0]);
                layout_get_idx = 1;
            }

            for x in 1..self.data.len() {
                let mut_ptr = self.data[x];
                let len = self.layout[layout_get_idx].size();
                for x in 0..len as isize {
                    *mut_ptr.offset(x) = 0;
                }
                munlock(mut_ptr as *const u8, len);
                std::alloc::dealloc(mut_ptr, self.layout[0]);
            }

            // free dummys
            for dummy in self.dummy_ptrs.iter() {
                std::alloc::dealloc(dummy.0, dummy.1);
            }
        }

    }
}

impl EncryptedMemoryArtifact {
    /// Security warning: this function is marked UNSAFE because the data you place herein will be COPIED.
    /// Since a copy occurs, make sure to DROP the old data if you input a reference to the data. If, however,
    /// you move the data, there is no need for this.
    ///
    /// IMPORTANT NOTE: This function returns a KEY. This key is necessary to read the data. For this reason,
    /// make sure to store this key in another place in memory, preferably allocated far away. This key only
    /// adds a layer of difficulty for trying to unscramble the data.
    ///
    /// The encryption performed can be chosen [TODO]
    pub unsafe fn new<Input: AsRef<[u8]>>(data: Input) -> Result<(Self, u8), CryptError<String>> {
        let data_in = data.as_ref();
        if data_in.len() > 1 && data_in.len() < MAX_DATA_SIZE {
            let key = random::<u8>();
            let (data, layout, dummy_ptrs) = Self::alloc_n_blocks(data_in, 2, key);
            let total_len = data_in.len();
            Ok((Self {data, layout, total_len, dummy_ptrs}, key))
        } else {
            Err(CryptError::OutOfBoundsError)
        }
    }

    /// For odd-sized datatypes (the last or first byte only)
    unsafe fn alloc_1_block(byte: u8, shift: u8) -> (*mut u8, Layout) {
        let layout = Layout::array::<u8>(1).unwrap();
        let ptr= std::alloc::alloc(layout);
        mlock(ptr as *const u8, 1);
        *ptr = byte.wrapping_add(shift);
        (ptr, layout)
    }

    /// Panics if the value is not a power of two, data is too long, or bytes supplied wont fit
    unsafe fn alloc_n_blocks(bytes: &[u8], block_size_power_of_two: u8, shift: u8) -> (Vec<*mut u8>, Vec<Layout>, Vec<(*mut u8, Layout)>) {

        if bytes.len() <= 1 {
            panic!("Power of two's greater than 1 only. Exiting for security purposes");
        }

        if !block_size_power_of_two.is_power_of_two() {
            panic!("Power of two's only. Exiting for security purposes");
        }

        if bytes.len() > MAX_DATA_SIZE {
            panic!("The amount of space needed is too large. Exiting for security purposes");
        }

        let mut ptr_vec = Vec::new();
        let mut ret_layouts = Vec::<Layout>::with_capacity(2);


        let layout_block_default = Layout::array::<u8>(block_size_power_of_two as usize).unwrap();

        let block_count;
        let mut idx = 0;

        if bytes.len() % 2 != 0  {
            let (ptr, layout) = Self::alloc_1_block(bytes[0], shift);
            ptr_vec.push(ptr);
            ret_layouts.push(layout);

            if bytes.len() == 1 {
                return (ptr_vec, ret_layouts, Vec::with_capacity(0));
            }

            block_count = (bytes.len() - 1)/(block_size_power_of_two as usize);
            idx += 1;
        } else {
            block_count = bytes.len()/(block_size_power_of_two as usize);
        }

        let mut dummy_allocs = Vec::with_capacity(block_count);

        for _ in 0..block_count {
            dummy_allocs.push(Self::dummy_allocate());
            let ptr = std::alloc::alloc(layout_block_default);
            mlock(ptr as *const u8, block_size_power_of_two as usize);
            for x in 0..block_size_power_of_two as isize {
                *ptr.offset(x) = bytes[idx].wrapping_add(shift);
                idx +=1;
            }
            ptr_vec.push(ptr);
        }

        ret_layouts.push(layout_block_default);
        (ptr_vec, ret_layouts, dummy_allocs)
    }

    /// This help ensure fragmentation within the dataset. The data may still exist within the same arena
    /// (when the global allocator is Jemalloc)
    unsafe fn dummy_allocate() -> (*mut u8, Layout) {
        let amt = random::<u8>() / 2;
        let layout = Layout::array::<u8>(amt as usize).unwrap();
        (std::alloc::alloc(layout), layout)
    }

    /// For safety reasons, this is marked as unsafe, as this returns the unencrypted data. If you only need
    /// to perform a comparison, consider using `read_compare`. This returns a new key to access the data again.
    ///
    /// Each time the data is read, the data is re-scrambled via caesar's cipher. This is thus a semi-active
    /// algorithm, as it only engages as it is engaged unto.
    ///
    /// Security note: MAKE SURE to dispose of the vector MANUALLY via the convenience function called
    /// `zero_and_drop_vector`. If you do not do this, the data will be dropped without being zeroed, and will
    /// be completely visible if an allocator allocates a chunk of memory over that slice later on without zeroing.
    pub unsafe fn read(&mut self, key: u8) -> (Vec<u8>, u8) {
        let mut data = Vec::with_capacity(self.total_len);
        let new_key = random::<u8>();
        let block_size;
        let ptr_idx;
        if self.total_len % 2 != 0 {
            let real_val = (*self.data[0]).wrapping_sub(key);
            data.push(real_val);
            *self.data[0] = real_val.wrapping_add(new_key);
            block_size = self.layout[1].size();
            ptr_idx = 1;
        } else {
            block_size = self.layout[0].size();
            ptr_idx = 0;
        }

        for ptr in self.data[ptr_idx..].iter() {
            let ptr = *ptr;
            for idx in 0..block_size as isize {
                let real_val = (*ptr.offset(idx)).wrapping_sub(key);
                data.push(real_val);
                (*ptr.offset(idx)) = real_val.wrapping_add(new_key);
            }
        }

        (data, new_key)
    }

    /// This is somewhat safer than `read`, as no new data is allocated. For security purposes,
    /// this consumes the `compare_to` vector, and then zeroes it out and drops it (done by SecVec
    /// automatically).
    pub unsafe fn read_compare(&mut self, key: u8, mut compare_to: SecVec<u8>) -> (bool, u8) {

        let compare = compare_to.unsecure_mut().as_mut_ptr();

        let new_key = random::<u8>();
        let block_size;
        let ptr_idx;
        if self.total_len % 2 != 0 {
            let real_val = (*self.data[0]).wrapping_sub(key);
            if real_val != *compare.offset(0) {

                return (false, 0);
            }

            *self.data[0] = real_val.wrapping_add(new_key);
            block_size = self.layout[1].size();
            ptr_idx = 1;
        } else {
            block_size = self.layout[0].size();
            ptr_idx = 0;
        }

        let mut cmp_idx = ptr_idx;
        for ptr in self.data[ptr_idx..].iter() {
            let ptr = *ptr;
            for idx in 0..block_size as isize {
                let real_val = (*ptr.offset(idx)).wrapping_sub(key);
                if real_val != *compare.offset(cmp_idx as isize) {
                    return (false, 0);
                }

                (*ptr.offset(idx)) = real_val.wrapping_add(new_key);
                cmp_idx += 1;
            }
        }

        (true, new_key)
    }

    #[inline]
    /// This consumes, zeroes, and then drops the input
    pub fn zero_and_drop_vector(mut input: Vec<u8>) {
        let len = input.len();
        let ptr = input.as_mut_ptr();
        for idx in 0..len as isize {
            unsafe {
                *ptr.offset(idx) = 0;
            }
        }
    }
}