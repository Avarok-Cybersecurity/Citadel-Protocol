#![feature(associated_type_defaults)]
//! quantum_random is an asynchronous byte downloader

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
extern crate lazy_static;

/// This should be imported by any external API
pub mod prelude {
    pub use crate::web_async::{next_i8s, next_i16s, next_i32s, next_i64s, next_i128s, next_u8s, next_u16s, next_u32s, next_u64s, next_u128s};
    pub use crate::util::QuantumError;
}

/// Contains the means of obtaining the data, as well as fetching unsigned or signed primitives
pub mod web_async;

/// Misc utilities
mod util;