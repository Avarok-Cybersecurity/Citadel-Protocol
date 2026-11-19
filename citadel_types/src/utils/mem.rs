//! The OS side of memory hygiene: locking pages (counted by [`super::page_locks`]) and wiping.

#[cfg(not(target_family = "wasm"))]
use super::page_locks::{PageCounts, PageLocker};
#[cfg(not(target_family = "wasm"))]
use std::sync::Mutex;

/// Locks pages with the OS's own call, and keeps them out of core dumps where the OS can.
#[cfg(not(target_family = "wasm"))]
pub(crate) struct OsPages;

#[cfg(target_family = "unix")]
impl PageLocker for OsPages {
    fn lock(&self, start: usize, len: usize) -> Result<(), i32> {
        let ptr = start as *mut std::os::raw::c_void;
        // SAFETY: `start..start + len` are whole pages that a live buffer occupies; locking and
        // advising pages has no effect on their contents.
        unsafe {
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            let _ = libc::madvise(ptr, len, libc::MADV_NOCORE);
            #[cfg(target_os = "linux")]
            let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
            if libc::mlock(ptr, len) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
            }
        }
    }

    fn unlock(&self, start: usize, len: usize) {
        let ptr = start as *mut std::os::raw::c_void;
        // SAFETY: as for `lock`: whole pages, contents unaffected.
        unsafe {
            let _ = libc::munlock(ptr, len);
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            let _ = libc::madvise(ptr, len, libc::MADV_CORE);
            #[cfg(target_os = "linux")]
            let _ = libc::madvise(ptr, len, libc::MADV_DODUMP);
        }
    }
}

#[cfg(target_family = "windows")]
impl PageLocker for OsPages {
    fn lock(&self, start: usize, len: usize) -> Result<(), i32> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        // SAFETY: whole pages that a live buffer occupies; locking does not touch their contents.
        if unsafe { VirtualLock(start as *const _, len) } != 0 {
            Ok(())
        } else {
            Err(unsafe { windows_sys::Win32::Foundation::GetLastError() } as i32)
        }
    }

    fn unlock(&self, start: usize, len: usize) {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        // SAFETY: as for `lock`.
        let _ = unsafe { VirtualUnlock(start as *const _, len) };
    }
}

#[cfg(target_family = "unix")]
fn page_size() -> usize {
    // SAFETY: sysconf reads a constant of the running system.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).expect("the OS reports its page size")
}

#[cfg(target_family = "windows")]
fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    // SAFETY: GetSystemInfo fills the struct it is handed, and cannot fail.
    let info = unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info
    };
    info.dwPageSize as usize
}

#[cfg(not(target_family = "wasm"))]
static PAGES: Mutex<Option<PageCounts>> = Mutex::new(None);

/// Locks `[ptr, ptr + len)` for one more holder. `Err` carries the OS error code when the OS
/// refused (for example, past `RLIMIT_MEMLOCK`); the region is counted as held either way.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn lock(ptr: *const u8, len: usize) -> Result<(), i32> {
    let mut pages = PAGES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pages
        .get_or_insert_with(|| PageCounts::new(page_size()))
        .acquire(ptr as usize, len, &OsPages)
}

/// Releases one holder of `[ptr, ptr + len)`, unlocking the pages nobody else holds.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn unlock(ptr: *const u8, len: usize) {
    let mut pages = PAGES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pages) = pages.as_mut() {
        pages.release(ptr as usize, len, &OsPages);
    }
}

/// How many buffers hold the page containing `addr` (tests only).
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) fn holders_of_page(addr: usize) -> usize {
    let pages = PAGES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pages
        .as_ref()
        .map_or(0, |pages| pages.holders_of(addr / page_size()))
}

/// Browsers expose no page locking; the wipe is all a buffer gets there.
#[cfg(target_family = "wasm")]
pub(crate) fn lock(_ptr: *const u8, _len: usize) -> Result<(), i32> {
    Ok(())
}

#[cfg(target_family = "wasm")]
pub(crate) fn unlock(_ptr: *const u8, _len: usize) {}

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
