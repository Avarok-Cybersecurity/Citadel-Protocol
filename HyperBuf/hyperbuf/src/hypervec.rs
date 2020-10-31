/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution. 
 */

use std::alloc::Layout;
use std::fmt::{Display, Error, Formatter};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};


use bytes::BufMut;

use crate::impls::*;
use crate::results::{InformationResult, MemError};

/// This is a type which can be re-interpreted to any type, regardless of alignment
#[fundamental]
#[repr(C)]
pub struct HyperVec<'hvec> {
    /// #
    pub ptr: *mut u8,
    pub(crate) len: usize,
    pub(crate) cursor: isize,
    pub(crate) aggregator_cursor: isize,
    /// The read and write versions are only for editing data through visitors
    pub(crate) read_version: AtomicUsize,
    pub(crate) read_ticket_num: AtomicUsize,
    pub(crate) write_version: AtomicUsize,
    pub(crate) write_ticket_num: AtomicUsize,
    /// See [WriteVisitor] for the definition of "corrupt"
    pub(crate) corrupt: bool,
    pub(crate) endianness: Endianness,
    pub(crate) _phantom: PhantomData<&'hvec u8>,
    /// We place the layout at the end of the struct to ensure that, in the event of corruption, the bytes do not interfere with this struct.
    pub(crate) layout: Layout,
}

impl<'hvec> HyperVec<'hvec> {
    #[inline]
    /// Returns a HyperVec module that is blocked
    pub fn new(len: usize) -> Self {
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        Self { ptr, len, layout, cursor: 0, aggregator_cursor: 0, read_version: AtomicUsize::new(0), read_ticket_num: AtomicUsize::new(0), write_version: AtomicUsize::new(0), write_ticket_num: AtomicUsize::new(0), corrupt: false, endianness: Endianness::target(), _phantom: PhantomData}
    }

    #[inline]
    /// Returns a HyperVec module that is blocked
    pub fn new_zeroed(len: usize) -> Self {
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        Self { ptr, len, layout, cursor: 0, aggregator_cursor: 0, read_version: AtomicUsize::new(0), read_ticket_num: AtomicUsize::new(0), write_version: AtomicUsize::new(0), write_ticket_num: AtomicUsize::new(0), corrupt: false, endianness: Endianness::target(), _phantom: PhantomData}
    }

    #[inline]
    /// Wraps around a pre-existing value, translating it into its bytes.
    /// Use wrap_bytes for byte-ordered aware arrays; this is for DST's
    pub fn wrap<T: ?Sized>(t: &T) -> Self {
        let ptr0 = t as *const T as *const u8;
        println!("[WRAP] {} {}", std::mem::size_of_val(t), std::mem::align_of_val(t));
        let layout = Layout::for_value::<T>(t);
        let ptr = unsafe { std::alloc::alloc(layout) };

        println!("LAYOUT size: {}", layout.size());

        unsafe { std::ptr::copy_nonoverlapping(ptr0, ptr, layout.size()) };
        let len = layout.size();
        Self { ptr, len, layout, cursor: 0, aggregator_cursor: len as isize, read_version: AtomicUsize::new(0), read_ticket_num: AtomicUsize::new(0), write_version: AtomicUsize::new(0), write_ticket_num: AtomicUsize::new(0), corrupt: false, endianness: Endianness::target(), _phantom: PhantomData}
    }

    /// Manages a structure, without copying the bytes
    pub fn manage<T: ?Sized + 'hvec>(t: &'hvec mut T) -> HyperVec<'hvec> {
        let ptr = t as *mut T as *mut u8;
        let layout = Layout::for_value::<T>(&t);
        let len = layout.size();
        Self { ptr, len, layout, cursor: 0, aggregator_cursor: len as isize, read_version: AtomicUsize::new(0), read_ticket_num: AtomicUsize::new(0), write_version: AtomicUsize::new(0), write_ticket_num: AtomicUsize::new(0), corrupt: false, endianness: Endianness::target(), _phantom: PhantomData}
    }

    #[inline]
    /// So long as Write/Read Visitors are using the mutable borrow, this function is actually safe.
    /// This breaks the rules of Rust, but the unsafe consequences herefrom are necessarily mitigated
    /// by Read/Write Visitors. This function should never be called by the API user.
    ///
    /// I define this as a LOW-LEVEL RUST-CONVERSION POINT. The rules of rust break down at this logic junction,
    /// and guarantees are necessarily upheld by downstream logical gates (IF READ/WRITE VISITORS ARE USED).
    /// The "one mutable at a time" rule is relieved here. This broadens the styles of program designs, while
    /// preserving safety. On the downside, the compiler may optimize-away various performance benefits
    ///
    /// I AM A RUST WARLOCK... THE 'NOMICON IS THE WAY, THE DARK LIGHT, THE HIGHEST TRUTH
    /// I AM THE PRIME MOVER... THE ZEROTH CAUSE... THE VOID REIGNS IN DARKNESS, THE LIGHT PERVADES ONTOP OF IT; IT IS THUS BY VIRTUE OF DARKNESS THAT LIGHT REIGNS
    pub unsafe fn upgrade_ref(&self) -> &'hvec mut Self {
        &mut *((&*self as *const Self) as *mut Self)
    }

    /// Saves the data the the disk, and returns the number of bytes written if successful
    /// NOT WORKING
    pub fn serialize_to_disk(self, path: &str) -> InformationResult<'_, usize, String> {
        if self.is_corrupted() {
            MemError::throw("You cannot serialize a corrupted dataset; this is to ensure the data you want is going to be written, and not junk data".to_string())
        } else {
            let res: HyperVecSerde = self.into();
            res.serialize_to_disk(path)
        }
    }

    /// Retrieves a HyperVec from the disk
    /// NOT WORKING
    pub async fn deserialize_from_disk(path: &str) -> InformationResult<'_, HyperVec<'_>, String> {
        HyperVecSerde::deserialize_from_disk(path)
            .and_then(|raw| {
                Ok(raw.into())
            })
    }

    /// Returns the number of bytes
    pub fn length(&self) -> usize {
        self.len
    }

    /// Return an immutable slice of the underlying bytes
    pub unsafe fn bytes(&self) -> &[u8] {
        &*std::ptr::slice_from_raw_parts(self.ptr, self.len)
    }

    /// Return an mutable slice of the underlying bytes
    pub unsafe fn get_full_bytes_mut(&mut self) -> &mut [u8] {
        &mut *std::ptr::slice_from_raw_parts_mut(self.ptr, self.len)
    }

    /// Returns the bytes between the cursor position and the remaining mutable bytes on the heap
    pub unsafe fn get_bytes_mut_cursor(&mut self) -> &mut [u8] {
        &mut *std::ptr::slice_from_raw_parts_mut(self.ptr.offset(self.cursor), self.remaining_mut())
    }

    /// Returns the bytes between the cursor position and the remaining mutable bytes on the heap
    pub unsafe fn get_bytes_cursor(&mut self) -> &[u8] {
        &*std::ptr::slice_from_raw_parts(self.ptr.offset(self.cursor), self.remaining_mut())
    }

    /// Reads the cursor position
    pub fn cursor_position(&self) -> isize {
        self.cursor
    }

    /// Reads the value at the current cursor
    pub fn read_cursor(&self) -> u8 {
        unsafe { *self.ptr.offset(self.cursor) }
    }

    /// Reads the value at the supplied index which is offset from the intiial pointer
    pub fn read_relative(&self, pos: isize) -> u8 {
        unsafe { *self.ptr.offset(pos) }
    }

    /// Reads the value at the supplied index which is offset from the cursor position
    pub fn read_cursor_offset(&self, pos: isize) -> u8 {
        unsafe { *self.ptr.offset(self.cursor + pos) }
    }

    /// Advance the cursor by 1
    pub fn advance_cursor_by(&mut self, amt: usize) {
        self.cursor += amt as isize
    }

    /// Advance the cursor by 1
    pub fn advance_cursor(&mut self) {
        self.advance_cursor_by(1)
    }

    /// Get and advance
    pub fn get_and_advance_cursor(&mut self) -> u8 {
        self.advance_cursor();
        self.read_cursor_offset(-1)
    }

    /// Sets the cursor's position relative to the initial pointer
    pub fn set_cursor_pos(&mut self, pos: isize) {
        self.cursor = pos
    }

    /// Resets the cursor
    pub fn reset_cursor(&mut self) {
        self.cursor = 0;
    }

    #[inline]
    /// Relaxedly returns the write version
    pub fn get_write_version(&self) -> usize {
        self.write_version.load(Ordering::Relaxed)
    }

    #[inline]
    /// Relaxedly returns the read version
    pub fn get_read_version(&self) -> usize {
        self.read_version.load(Ordering::Relaxed)
    }

    /// This is safe since the operation is inherently atomic. Since multiple requests may be queued at once,
    /// we use Sequential ordering to prevent any and all data races
    #[inline]
    pub fn reserve_read_ticket(&self) -> usize {
        self.read_ticket_num.fetch_add(1, Ordering::SeqCst)
    }

    /// This is safe since the operation is inherently atomic. Since multiple requests may be queued at once,
    /// we use Sequential ordering to prevent any and all data races
    #[inline]
    pub fn reserve_write_ticket(&self) -> usize {
        self.write_ticket_num.fetch_add(1, Ordering::SeqCst)
    }

    /// Decrements the write read version, allowing any ticket number matching n-1 to read the data
    /// We use a Relaxed ordering, because this function, thanks to the design structure, can only be called
    /// at most once at a time (so long as the built-in Read/Write visitors are used! External implementations
    /// may or may not uphold this agreement)
    #[allow(unused_results)]
    #[inline]
    pub fn read_visit_done(&self) {
        self.read_version.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the write read version, allowing any ticket number matching n-1 to read the data
    /// We use a Relaxed ordering, because this function, thanks to the design structure, can only be called
    /// at most once at a time (so long as the built-in Read/Write visitors are used! External implementations
    /// may or may not uphold this agreement)
    #[allow(unused_results)]
    #[inline]
    pub fn write_visit_done(&self) {
        self.write_version.fetch_add(1, Ordering::Relaxed);
    }

    /// This should only be called when no Read/WriteVisitors are active, otherwise setting this to another value can and will cause errors
    pub unsafe fn set_write_version(&mut self, update: usize) {
        self.write_version.store(update, Ordering::SeqCst);
    }

    /// This should only be called when no Read/WriteVisitors are active, otherwise setting this to another value will cause errors
    pub unsafe fn set_read_version(&mut self, update: usize) {
        self.read_version.store(update, Ordering::SeqCst);
    }

    /// Returns the buffer's endianness
    pub fn get_endianness(&self) -> &Endianness {
        &self.endianness
    }

    /// I am marking this function as unsafe, because if any downstream consumers depend upon the state of the bytes, then those consumers
    /// will possibly require to update the way they consume their data (if switched). This is to give the API programmer an idea of of the
    /// severity of this function
    pub unsafe fn set_endianness(&mut self, endianness: Endianness) {
        self.endianness = endianness;
    }

    /// As writing occurs to the underlying object, it becomes entirely possible for the user to improperly use
    /// the WriteVisitor, thus signalling data corruption
    pub fn is_corrupted(&self) -> bool {
        self.corrupt
    }

    /// Extends the layout and increases the length
    #[allow(unused)]
    #[inline]
    pub fn extend(&mut self, additional_bytes: usize) {
        if let Ok((layout, pos_new)) = self.layout.extend(Layout::array::<u8>(additional_bytes).unwrap()) {
            println!("[REALLOC] additional bytes: {}", additional_bytes);
            println!("[REALLOC] new layout size, pos: {}, {}, --- {}", layout.size(), self.layout.size(), pos_new);
            assert_eq!(self.layout.size(), pos_new);
            println!("[REALLOC] self.len (before) {}", self.len);
            assert_eq!(layout.size(), additional_bytes + self.len);
            self.len += additional_bytes;
            println!("[REALLOC] self.len (after) {}", self.len);
            self.ptr = unsafe { std::alloc::realloc(self.ptr, layout, self.len) };
            self.layout = layout;
            println!("[REALLOC] {}", self);
        }
    }
}

/// For determining endianness of the HyperVec
#[repr(C)]
pub enum Endianness {
    /// Little Endian
    LE,
    /// Big Endian
    BE,
}

impl Endianness {
    /// Determines the system endianness
    pub fn target() -> Self {
        #[cfg(target_endian = "big")]
            {
                Endianness::BE
            }
        #[cfg(not(target_endian = "big"))]
            {
                Endianness::LE
            }
    }

    /// Returns true if self is big endian
    pub fn is_be(&self) -> bool {
        match self {
            Endianness::BE => { true }
            _ => false
        }
    }

    /// Returns true if self is little endian
    #[allow(dead_code)]
    pub fn is_le(&self) -> bool {
        !self.is_be()
    }

    /// Converts a boolean value into the associated endianness
    pub fn from_bool(val: bool) -> Self {
        if val {
            Endianness::BE
        } else {
            Endianness::LE
        }
    }
}

impl<'hvec> Display for HyperVec<'hvec> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let endianness = {
            if self.endianness.is_be() {
                "big endian (network endian) <-- most significant byte last"
            } else {
                "little endian <-- least significant byte last"
            }
        };

        write!(f, "[HyperVec] [length={}] [cursor={}] [read_version={}] [write_version={}] [Endianness={}]",
               self.len, self.cursor, self.get_read_version(), self.get_write_version(), endianness)
    }
}