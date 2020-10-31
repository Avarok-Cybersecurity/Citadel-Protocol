use crate::uniform_allocator::UniformAllocator;
use ccl_crossbeam_epoch::{self as epoch, Atomic, Owned, Pointer, Shared};
use std::hash::{Hash, Hasher};
use std::mem;
use std::ptr;
use std::sync::atomic::Ordering;

pub trait UniformAllocExt<T> {
    fn uniform_alloc(allocator: &UniformAllocator<T>, tag: usize, v: T) -> Self;
}

pub trait UniformDeallocExt<T> {
    fn uniform_dealloc(&self, allocator: &UniformAllocator<T>, tag: usize) -> Option<T>;
}

impl<T> UniformAllocExt<T> for Atomic<T> {
    #[inline]
    fn uniform_alloc(allocator: &UniformAllocator<T>, tag: usize, v: T) -> Self {
        let ptr = allocator.alloc(tag) as usize;
        unsafe {
            ptr::write(ptr as *mut T, v);
            let atomicptr = Atomic::null();
            atomicptr.store(Shared::from_usize(ptr), Ordering::Release);
            atomicptr
        }
    }
}

impl<T> UniformDeallocExt<T> for Atomic<T> {
    #[inline]
    fn uniform_dealloc(&self, allocator: &UniformAllocator<T>, tag: usize) -> Option<T> {
        unsafe {
            let ptr = self
                .load(Ordering::Acquire, epoch::unprotected())
                .into_usize() as *mut u8;
            allocator.dealloc(tag, ptr)
        }
    }
}

impl<T> UniformAllocExt<T> for Owned<T> {
    #[inline]
    fn uniform_alloc(allocator: &UniformAllocator<T>, tag: usize, v: T) -> Self {
        let ptr = allocator.alloc(tag) as usize;
        unsafe {
            ptr::write(ptr as *mut T, v);
            Owned::from_usize(ptr)
        }
    }
}

impl<'a, T> UniformDeallocExt<T> for Shared<'a, T> {
    #[inline]
    fn uniform_dealloc(&self, allocator: &UniformAllocator<T>, tag: usize) -> Option<T> {
        let ptr = self.clone().into_usize();
        allocator.dealloc(tag, ptr as *mut u8)
    }
}

#[inline]
pub fn hash_with_nonce<T: Hash>(v: &T, nonce: u8) -> u64 {
    let mut hasher = seahash::SeaHasher::new();
    hasher.write_u8(nonce);
    v.hash(&mut hasher);
    hasher.finish()
}

#[inline(always)]
pub fn sharedptr_null<'a, T>() -> Shared<'a, T> {
    unsafe { Shared::from_usize(0) }
}

pub trait UnsafeOption<T> {
    unsafe fn unsafe_unwrap(self) -> T;
    unsafe fn unsafe_take(&mut self) -> Option<T>;
}

impl<T> UnsafeOption<T> for Option<T> {
    #[inline]
    unsafe fn unsafe_unwrap(self) -> T {
        match self {
            None => std::hint::unreachable_unchecked(),
            Some(v) => v,
        }
    }

    #[inline]
    #[allow(clippy::mem_replace_option_with_none)]
    unsafe fn unsafe_take(&mut self) -> Option<T> {
        mem::replace(self, None)
    }
}

#[inline(always)]
pub const fn ptr_size_bits() -> usize {
    mem::size_of::<usize>() * 8
}

/// Must not panic
#[inline]
pub unsafe fn map_in_place<T>(r: &mut T, f: impl FnOnce(T) -> T) {
    ptr::write(r, f(ptr::read(r)));
}
