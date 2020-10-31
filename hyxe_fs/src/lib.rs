#![feature(const_fn, async_closure,trivial_bounds)]
#![feature(shrink_to)]
//! hyxe_fs (Hyxe::FileSystem) organizes the libraries responsible for handling I/O with the disk and notably the variably-centralized virtual-fs
//! for home, business, enterprise, or government settings


#![deny(
missing_docs,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_features,
unused_results,
warnings
)]

#[macro_use]
/// For global constants
extern crate lazy_static;

/// Conveniance import to access important I/O subroutines, including local and virtual
pub mod prelude {
    pub use crate::hyxe_file::*;
    pub use crate::io::*;
    pub use crate::async_io::*;
}

/// Re-import
pub use hyxe_crypt;

/// Contains the filesystem manager (FSM). The FSM must be manually instantiated by the user. The FSM unlocks:
/// [0] HyxeFile listeners
/// [1] Shutdown hooks
/// [2] File scanning and HyxeFile loading
pub mod system_file_manager;

/// HyxeFiles are files that can be drilled-shut upon save, and undrilled upon load. They require a drill to use.
pub mod hyxe_file;

/// Environmental constants and subroutines for pre-checking the system
pub mod env;

/// Contains the File I/O subroutines 
pub mod io;

/// Contains the async file I/O subroutines, as well as async serialization/deserialization
pub mod async_io;

/// Contains the method for serializing/deserializing objects with Arc<RwLock<T>> types
pub mod arc_rwlock_serde;
/// Allows thread-pooled asynchronous and parallel file processing
pub mod file_crypt_scrambler;

/// Contains misc subroutines
pub mod misc;