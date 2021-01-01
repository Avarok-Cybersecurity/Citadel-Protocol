use crate::drill::{PORT_RANGE, BYTES_PER_3D_ARRAY};
use rand::thread_rng;
use std::fmt::Formatter;
use std::os::raw::c_void;
use rand::prelude::SliceRandom;

/// Default Error type for this crate
pub enum CryptError<T: ToString> {
    /// Encrypt Error
    Encrypt(T),
    /// Decrypt Error
    Decrypt(T),
    /// Drill update error
    DrillUpdateError(T),
    /// Out of bounds
    OutOfBoundsError,
    /// This occurs if the byte-valued security level desired does not correspond to an actual [SecurityLevel]
    BadSecuritySetting
}

impl<T: ToString> CryptError<T> {
    /// Conveniance method
    pub fn throw<U>(self) -> Result<U, Self> {
        Err(self)
    }

    /// Use for converting to different types
    pub fn to_string(&self) -> String {
        match self {
            CryptError::Encrypt(s) => s.to_string(),
            CryptError::Decrypt(s) => s.to_string(),
            CryptError::DrillUpdateError(s) => s.to_string(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception".to_string(),
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting".to_string()
        }
    }
}

impl<T: ToString> std::fmt::Debug for CryptError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_string())
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

#[inline]
/// Converts a downloaded vector into the format necessary to create a drill
pub fn bytes_to_3d_array<T: AsRef<[u8]>>(input: T) -> [u8; BYTES_PER_3D_ARRAY] {
    let input = input.as_ref();
    debug_assert_eq!(input.len(), BYTES_PER_3D_ARRAY);

    let mut ret = [0u8; BYTES_PER_3D_ARRAY];
     ret.iter_mut().zip(input.iter())
         .for_each(|(out, val)| {
             *out = *val;
         });

    ret
}


#[cfg(not(target_os = "windows"))]
#[allow(unused_results)]
/// Locks-down the memory location, preventing it from being read until unlocked
/// For linux, returns zero if successful
pub unsafe fn mlock(ptr: *const u8, len: usize) {
    libc::mlock(ptr as *const c_void, len);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        libc::madvise(ptr as *mut c_void, len, libc::MADV_NOCORE);
    #[cfg(target_os = "linux")]
        libc::madvise(ptr as *mut c_void, len, libc::MADV_DONTDUMP);
}

#[cfg(target_os = "windows")]
#[allow(unused_results)]
/// Locks-down the memory location, preventing it from being read until unlocked
/// For windows, returns nonzero if successful
pub unsafe fn mlock(ptr: *const u8, len: usize) {
    kernel32::VirtualLock(ptr as *mut c_void, len as u64);
}

#[cfg(not(target_os = "windows"))]
#[allow(unused_results)]
/// Locks-down the memory location, preventing it from being read until unlocked
/// For linux, returns zero if successful
pub unsafe fn munlock(ptr: *const u8, len: usize) {
    libc::munlock(ptr as *const c_void, len);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        libc::madvise(ptr as *mut c_void, len, libc::MADV_CORE);
    #[cfg(target_os = "linux")]
        libc::madvise(ptr as *mut c_void, len, libc::MADV_DODUMP);
}

#[cfg(target_os = "windows")]
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
    core::intrinsics::volatile_set_memory(s, c, n);
}

/// General `memzero`.
#[inline]
pub unsafe fn zeroize(dest: *const u8, n: usize) {
    memset(dest as *mut u8, 0, n);
}