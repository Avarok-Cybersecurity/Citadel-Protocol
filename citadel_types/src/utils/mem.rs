use std::os::raw::c_void;

/// Locks-down the memory location, preventing it from being read until unlocked
/// For linux, returns zero if successful
/// # Safety
///
/// uses libc functions with proper len and start ptr idx
#[cfg(target_family = "unix")]
#[allow(unused_results)]
pub unsafe fn mlock(ptr: *const u8, len: usize) {
    libc::mlock(ptr as *const c_void, len);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr as *mut c_void, len, libc::MADV_NOCORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr as *mut c_void, len, libc::MADV_DONTDUMP);
}

#[cfg(target_family = "wasm")]
pub unsafe fn mlock(_ptr: *const u8, _len: usize) {}

#[cfg(target_family = "windows")]
#[allow(unused_results)]
/// Locks-down the memory location, preventing it from being read until unlocked
/// For windows, returns nonzero if successful
pub unsafe fn mlock(ptr: *const u8, len: usize) {
    kernel32::VirtualLock(ptr as _, len as u64);
}

/// Locks-down the memory location, preventing it from being read until unlocked
/// For linux, returns zero if successful
/// # Safety
///
/// uses libc functions with proper len and start ptr idx
#[cfg(target_family = "unix")]
#[allow(unused_results)]
pub unsafe fn munlock(ptr: *const u8, len: usize) {
    libc::munlock(ptr as *const c_void, len);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr as *mut c_void, len, libc::MADV_CORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr as *mut c_void, len, libc::MADV_DODUMP);
}

#[cfg(target_family = "wasm")]
pub unsafe fn munlock(_ptr: *const u8, _len: usize) {}

#[cfg(target_family = "windows")]
#[allow(unused_results)]
/// Locks-down the memory location, preventing it from being read until unlocked
/// For windows, returns nonzero if successful. Returns 158 if already unlocked.
/// Windows unlocks a page all at once
pub unsafe fn munlock(ptr: *const u8, len: usize) {
    kernel32::VirtualUnlock(ptr as _, len as u64);
}

/// General `memset`.
#[inline(never)]
unsafe fn memset(s: *mut u8, c: u8, n: usize) {
    volatile_set(s, c, n)
}

/// General `memzero`.
/// # Safety
///
/// uses libc functions with proper len and start ptr idx
#[inline]
pub unsafe fn zeroize(dest: *const u8, n: usize) {
    memset(dest as *mut u8, 0, n);
    atomic_fence()
}

/// Uses a fence to ensure operations are not reordered when zeroing
#[inline]
fn atomic_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline]
unsafe fn volatile_set<T: Copy + Sized>(dst: *mut T, src: T, count: usize) {
    for i in 0..count {
        let ptr = dst.add(i);
        std::ptr::write_volatile(ptr, src);
    }
}
