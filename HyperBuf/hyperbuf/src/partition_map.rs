/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::any::TypeId;
use std::alloc::Layout;
use std::ops::{Index, IndexMut};
use std::fmt::{Display, Formatter, Error};

/// A low-level method of keeping track of structures without the need for storing specific types
#[repr(C)]
pub struct PartitionMap where {
    /// ptr_sizes, for each pointee, exists the size (in bytes) of the object in memory.
    /// We use a pointer with type usize to accommodate large data structures.
    /// Each offset points to a usize that implies the length of the object in memory.
    /// Typically, usize occupies 8 bytes of memory (64-bit)
    pub(crate) ptr: *mut RelativeObjectLocation,
    /// `object_count` is synonymous to "len" fields of vectors; herein, `object_count` represents the number of pointees from ptr
    pub(crate) object_count: isize,
    pub(crate) layout: Layout
}

/// While only some objects need to be expressed in terms of type, the rest do not and instead are treated as singular bytes.
/// This is to save memory. For example, if there is an array of 16 bytes, and, say, the first 8 bytes are just bytes while the
/// last 8 bytes are a u64, then the net object from 0..16 can be pseudo expressed as:
/// (0..8) => (empty; do not create a [RelativeObjectLocation])
/// (9..16) => create a [RelativeObjectLocation] with location=9, len=8, and type_id of std::mem::type_id::<u64>()
///
/// NOTE: `location` does NOT correspond to the actual pointer to the object (Don't cast to a pointer!). Instead, it corresponds to the RELATIVE location
/// in the underlying buffer of the HyperVec
#[repr(C)]
pub struct RelativeObjectLocation {
    pub(crate) location: isize,
    pub(crate) length: isize,
    pub(crate) type_id: TypeId
}

#[allow(dead_code)]
impl RelativeObjectLocation {
    /// Creates a new tracker for a point in memory (designed especially for: [HyperVec]
    pub fn new(location: isize, length: isize, type_id: TypeId) -> Self {
        Self {location, length, type_id}
    }

    /// `bytes` should be a reference to the bytes within the [HyperVec]. This function
    /// automatically accounts for the locational offset
    pub unsafe fn transform_unchecked<T: Sized>(&self, bytes: &[u8]) -> &T {
        &*(bytes[self.location as usize] as *const T)
    }

    /// `bytes` should be a reference to the bytes within the [HyperVec]. This function
    /// automatically accounts for the locational offset
    pub unsafe fn transform_unchecked_mut<T: Sized>(&mut self, bytes: &[u8]) -> &mut T {
        &mut *(bytes[self.location as usize] as *mut T)
    }

    /// As objects within the [HyperVec] change size, it becomes necessary to update the fields within self
    pub fn shift(&mut self, shift: isize) {
        self.location += shift;
    }

    /// Returns the underlying u64 with some unsafe magic
    pub fn get_raw_type_id(&self) -> u64 {
        unsafe { std::ptr::read_volatile((&self.type_id as *const TypeId) as *const u64) }
    }

}

impl Index<isize> for PartitionMap {
    type Output = RelativeObjectLocation;

    fn index(&self, index: isize) -> &Self::Output {
        unsafe { &*self.ptr.offset(index) }
    }
}

impl IndexMut<isize> for PartitionMap {
    fn index_mut(&mut self, index: isize) -> &mut Self::Output {
        unsafe { &mut *self.ptr.offset(index) }
    }
}

#[allow(unused, clippy::cast_ptr_alignment)]
impl PartitionMap {
    /// Creates a low-level system for tracking memory, and eliminating the need to have a unary array of item types
    pub fn new() -> Self {
        // We allocate space for (initially!) "1", hence the 1 * ... side_of(). This is for readability, as well as for our first item
        // TODO: Below may cause a bug, because does n * size_of may not be accurate
        let layout = Layout::array::<RelativeObjectLocation>(std::mem::size_of::<RelativeObjectLocation>()).unwrap();
        //println!("sz {} al {}", std::mem::size_of::<RelativeObjectLocation>(), std::mem::align_of::<RelativeObjectLocation>());
        let ptr = unsafe {std::alloc::alloc(layout)} as *mut RelativeObjectLocation;
        //let m = TypeId {t: 88};
        let object_count = 0;
        Self {ptr, object_count, layout}
    }

    /// Appends to the dataset and increments the object count. No shifting of other entries is required.
    #[inline]
    pub fn store(&mut self, location: isize, length: isize, type_id: TypeId) {
        unsafe {
            self.extend(1);
            *self.ptr.offset(self.object_count) = RelativeObjectLocation::new(location, length, type_id)
        };

        self.object_count += 1;
    }

    /// Updates the [RelativeObjectLocation]'s size by the delta specified about the point `idx` of Self.
    /// Importantly: This will also shift all the other values if idx != self.object_count. Why? Well, in the case that
    /// the index specified is the last (i.e., idx == self.object_count), then any shift in location or size won't affect
    /// the values of the others. However, if idx != self.object_count, then we must shift the location field of all indexes
    /// greater than idx by the supplied delta as well.
    pub fn update_cause_size_delta(&mut self, idx: isize, size_delta: isize) {
        if idx == self.object_count {
            self[idx].length += size_delta;
        } else {
            for rol_idx in idx..self.object_count {
                self[rol_idx].location += size_delta;
            }
        }
    }


    /// Adjusts the locations of entities with an idx greater than `idx`, and then removes it from the list, thereafter it shrinks the underlying layout.
    /// It is the duty for the caller to ensure that the HyperVec's underyling buffer has been shifted. Keep in mind, this partition map is not necessarily
    /// dependent upon the HyperVec it keeps track of
    pub unsafe fn delete(&mut self, idx: isize) {
        self.update_cause_size_delta(idx + 1, self[idx].length);
        // Now that the entities have been shifted, let's replace the ROL as idx about self with the ROL at idx + 1 [..]. Then, recursively so idx + (object_count - idx).
        // By doing that, we can then call std::mem::replace
        self.defrag_at(idx);
    }

    /// Shifts all memory points higher than idx down by 1. E.g., (idx + 1) gets shifted to (idx), (idx + 2) gets shifted to (idx + 1). This is useful after deleting an entry.
    /// This will immediately return if `idx` == self.object_count.
    ///
    /// NOTE: AN ENTRY MUST EXIST AT `idx`, or UB!!
    ///
    /// The final step in this process is dropping the value at `idx`
    #[allow(unused_results)]
    #[inline]
    pub unsafe fn defrag_at(&mut self, idx: isize) {
        if idx == self.object_count {
            return;
        }

        // This pushes the soon-to-be-dropped value
        for pt in idx..(self.object_count -1) {
            std::ptr::swap(self.ptr.offset(pt), self.ptr.offset(pt + 1));
        }

        // This reads the value in an unaligned way, and then drops it. Calling std::mem::drop is redundant,
        // since all values on the stack of a closure gets dropped at the end of that closure
        std::ptr::read_unaligned(self.ptr.offset(idx));
    }

    /// Returns the object at idc
    pub unsafe fn retrieve(&self, idx: &usize) -> &RelativeObjectLocation {
        &self[*idx as isize]
    }

    /// Extends the entire layout; this should only be called by store() in order to accomidate another set of data
    unsafe fn extend(&mut self, amt: usize) {
        if let Ok((lyt, _)) = self.layout.extend(Layout::array::<RelativeObjectLocation>(amt * std::mem::size_of::<RelativeObjectLocation>()).unwrap()) {
            self.layout = lyt;
        }
    }
}

impl Display for RelativeObjectLocation {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        writeln!(f, "\t=> [RelativeObjectLocation] [relative location: {}] [size: {}] [type_id: {}]", self.location, self.length, self.get_raw_type_id())
    }
}

impl Display for PartitionMap {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        writeln!(f, "|----------[PartitionMap] [length: {}]----------|", self.object_count)?;
        for x in 0..self.object_count {
            write!(f, "[{}]", x)?;
            self[x].fmt(f)?;
        }

        write!(f, "|----------------------------------------------|")
    }
}

impl Default for PartitionMap {
    fn default() -> Self {
        Self::new()
    }
}