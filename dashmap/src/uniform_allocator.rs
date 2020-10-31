//! This is a thin allocator wrapper for use in some datastructures.
//! This is here incase we want to implement a custom allocator at a later date.

use std::alloc::{alloc, dealloc, Layout};
use std::marker::PhantomData;
use std::ptr;

/// Please see module level documentation.
pub struct UniformAllocator<T> {
    marker: PhantomData<T>,
}

impl<T> UniformAllocator<T> {
    pub fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn alloc(&self, _tag: usize) -> *mut u8 {
        unsafe { alloc(Layout::new::<T>()) }
    }

    #[inline(always)]
    pub fn dealloc(&self, _tag: usize, ptr: *mut u8) -> Option<T> {
        unsafe {
            let data = ptr::read(ptr as *const _);
            dealloc(ptr, Layout::new::<T>());
            data
        }
    }
}

impl<T> Default for UniformAllocator<T> {
    fn default() -> Self {
        Self::new()
    }
}
