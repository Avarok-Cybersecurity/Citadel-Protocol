use crate::entropy_bank::PORT_RANGE;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use std::fmt::{Display, Formatter};
#[cfg(target_family = "unix")]
use std::os::raw::c_void;

/// Default Error type for this crate
pub enum CryptError<T = String> {
    /// Encrypt Error
    Encrypt(T),
    /// Decrypt Error
    Decrypt(T),
    /// Drill update error
    DrillUpdateError(T),
    /// Out of bounds
    OutOfBoundsError,
    /// This occurs if the byte-valued security level desired does not correspond to an actual [SecurityLevel]
    BadSecuritySetting,
}

impl<T> CryptError<T> {
    /// Use for converting to different types
    pub fn into_string(self) -> String
    where
        T: Into<String>,
    {
        match self {
            CryptError::Encrypt(s) => s.into(),
            CryptError::Decrypt(s) => s.into(),
            CryptError::DrillUpdateError(s) => s.into(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception".to_string(),
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting".to_string(),
        }
    }

    pub fn as_str(&self) -> &str
    where
        T: AsRef<str>,
    {
        match self {
            CryptError::Encrypt(s) => s.as_ref(),
            CryptError::Decrypt(s) => s.as_ref(),
            CryptError::DrillUpdateError(s) => s.as_ref(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception",
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting",
        }
    }
}

impl<T: AsRef<str>> std::fmt::Debug for CryptError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

impl<T: AsRef<str>> Display for CryptError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Creates a port pair mapping at random
pub fn create_port_mapping() -> Vec<(u16, u16)> {
    let mut input_ports = Vec::with_capacity(PORT_RANGE);
    let mut output_ports = Vec::with_capacity(PORT_RANGE);

    for i in 0..PORT_RANGE {
        input_ports.push(i);
        output_ports.push(i);
    }

    let mut rng = thread_rng();
    input_ports.as_mut_slice().shuffle(&mut rng);
    output_ports.as_mut_slice().shuffle(&mut rng);

    let mut output_vec = Vec::with_capacity(PORT_RANGE);
    for i in 0..PORT_RANGE {
        output_vec.push((input_ports[i] as u16, output_ports[i] as u16));
    }

    output_vec
}

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
    kernel32::VirtualLock(ptr as *mut c_void, len as u64);
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
    kernel32::VirtualUnlock(ptr as *mut c_void, len as u64);
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

pub mod blocking_spawn {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct BlockingSpawnError {
        pub message: String,
    }

    pub enum BlockingSpawn<T> {
        Tokio(tokio::task::JoinHandle<T>),
    }

    #[cfg(target_family = "wasm")]
    pub fn spawn_blocking<F, R>(_f: F) -> BlockingSpawn<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        panic!("Cannot call spawn_blocking on WASM")
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn spawn_blocking<F, R>(f: F) -> BlockingSpawn<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        BlockingSpawn::Tokio(tokio::task::spawn_blocking(f))
    }

    impl<T> Future for BlockingSpawn<T> {
        type Output = Result<T, BlockingSpawnError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                BlockingSpawn::Tokio(handle) => {
                    Pin::new(handle).poll(cx).map_err(|err| BlockingSpawnError {
                        message: err.to_string(),
                    })
                }
            }
        }
    }
}
