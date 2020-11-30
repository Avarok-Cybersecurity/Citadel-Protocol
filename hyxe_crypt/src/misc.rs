use crate::drill::{RawDrillSkeleton, PORT_RANGE, E_OF_X_START_INDEX, BYTES_PER_3D_ARRAY, Drill};
use crate::drill::DrillEndian;
use byteorder::ByteOrder;
use crate::drill_update::DrillUpdateObject;
use rand::{Rng, thread_rng};
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
pub fn bytes_to_3d_array<T: AsRef<[u8]>>(input: T) -> RawDrillSkeleton {
    let input = input.as_ref();
    debug_assert_eq!(input.len(), BYTES_PER_3D_ARRAY);

    let (mut low, mut med, mut high, mut ultra, mut divine) = empty_skeleton();

    let mut get_location = 0;
    for outer in 0..E_OF_X_START_INDEX {
        for inner in 0..PORT_RANGE {
            low[outer][inner] = input[get_location + 0];

            med[outer][inner] = DrillEndian::read_u16(&[input[get_location + 1], input[get_location + 2]]);

            high[outer][inner] = DrillEndian::read_u32(&[input[get_location + 3], input[get_location + 4],
                input[get_location + 5], input[get_location + 6]]);

            ultra[outer][inner] = DrillEndian::read_u64(&[input[get_location + 7], input[get_location + 8],
                input[get_location + 9], input[get_location + 10], input[get_location + 11], input[get_location + 12],
                input[get_location + 13], input[get_location + 14]]);

            divine[outer][inner] = DrillEndian::read_u128(&[input[get_location + 15], input[get_location + 16],
                input[get_location + 17], input[get_location + 18], input[get_location + 19], input[get_location + 20],
                input[get_location + 21], input[get_location + 22], input[get_location + 23], input[get_location + 24],
                input[get_location + 25], input[get_location + 26], input[get_location + 27], input[get_location + 28],
                input[get_location + 29], input[get_location + 30]]);
            get_location += 31;
        }
    }
    (low, med, high, ultra, divine)
}

/// This is the primary updating function for the SAAQ algorithm. Let n be the drill version, and let f(n) return a 3D array at
/// version n. Let c(n) be a function which stores an equal number of  bytes as f(n). Let i, j, and k equal the index within
/// f(n) and c(n) That corresponds to the security level ([0-4]; low=0, medium=1, high=2, ultra=3, divine=4), the value-type index,
/// and finally the port-value. The update algorithm is thus:
///
/// f(n+1)[i][j][k] = c(n)[i][j][k] ^ f(n)[i][j][k] where "^" is the exclusive-or logical operator (XOR).
///
/// Important secruity notes: it is NECESSARY to transmit the values of c(n) encrypted
///
/// F(0) is determined initially by the server, and then it is sent over the network via 2-FA authentication, or, in order for the warranty
/// to not be voided, f(0) is stored on a physically-shipped security ship.
#[inline]
pub(crate) fn xor2_forall_between_vec_and_drill(update: &DrillUpdateObject, drill: &Drill) -> RawDrillSkeleton {
    debug_assert_eq!(update.data.len(), BYTES_PER_3D_ARRAY);

    let (mut low, mut med, mut high, mut ultra, mut divine) = empty_skeleton();
    let update = &update.data;

    let drill_low = drill.get_low();
    let drill_med = drill.get_med();
    let drill_high = drill.get_high();
    let drill_ultra = drill.get_ultra();
    let drill_divine = drill.get_divine();

    let mut get_location = 0;
    for outer in 0..E_OF_X_START_INDEX {
        for inner in 0..PORT_RANGE {
            low[outer][inner] = update[get_location + 0]
                                ^ drill_low[outer][inner];

            med[outer][inner] = DrillEndian::read_u16(&[update[get_location + 1], update[get_location + 2]])
                                                            ^ drill_med[outer][inner];

            high[outer][inner] = DrillEndian::read_u32(&[update[get_location + 3], update[get_location + 4],
                update[get_location + 5], update[get_location + 6]])
                ^ drill_high[outer][inner];

            ultra[outer][inner] = DrillEndian::read_u64(&[update[get_location + 7], update[get_location + 8],
                update[get_location + 9], update[get_location + 10], update[get_location + 11], update[get_location + 12],
                update[get_location + 13], update[get_location + 14]])
                ^ drill_ultra[outer][inner];

            divine[outer][inner] = DrillEndian::read_u128(&[update[get_location + 15], update[get_location + 16],
                update[get_location + 17], update[get_location + 18], update[get_location + 19], update[get_location + 20],
                update[get_location + 21], update[get_location + 22], update[get_location + 23], update[get_location + 24],
                update[get_location + 25], update[get_location + 26], update[get_location + 27], update[get_location + 28],
                update[get_location + 29], update[get_location + 30]])
                ^ drill_divine[outer][inner];
        }
        get_location += 31;
    }

    (low, med, high, ultra, divine)
}

/// Returns an array of arrays of arrays, all ready to hold the amount of data necessary
pub(crate) fn empty_skeleton() -> RawDrillSkeleton {
    ([[0; PORT_RANGE]; E_OF_X_START_INDEX], [[0; PORT_RANGE]; E_OF_X_START_INDEX], [[0; PORT_RANGE]; E_OF_X_START_INDEX], [[0; PORT_RANGE]; E_OF_X_START_INDEX], [[0; PORT_RANGE]; E_OF_X_START_INDEX])
}

/// Returns the random indices to use for scrambling of data. This part uses only local randomness.
/// The final product of the `random()` function is a cross between local hardware randomness and
/// quantum randomness, rendering the distribution itself random. Whereas quantum randomness is
/// nearly 50/50, local hardware randomness is not, and as such the distribution of the distribution
/// (i.e., the metadistribution) is itself random. Sometimes there might be lots of order, other times,
/// not so much! This panics if the count is greater than E_OF_X_START_INDEX.
pub(crate) fn get_indices<Rnd: Rng>(count: u8, rng: &mut Rnd) -> ([usize; E_OF_X_START_INDEX], [usize; E_OF_X_START_INDEX]) {
    assert!(count < E_OF_X_START_INDEX as u8);
    let mut idx_outer: [usize; E_OF_X_START_INDEX] = [0; E_OF_X_START_INDEX];
    let mut idx_inner: [usize; E_OF_X_START_INDEX] = [0; E_OF_X_START_INDEX];
    for idx in 0..count as usize{
        idx_outer[idx] = rng.gen_range(0, E_OF_X_START_INDEX);
        idx_inner[idx] = rng.gen_range(0, PORT_RANGE);
    }
    (idx_outer, idx_inner)
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