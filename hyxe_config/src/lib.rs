#![feature(try_trait, unsized_locals, async_closure)]
//! Hyxe Config is the crate dedicated for providing the means of saving, reading, and editing data to the local disk
#![deny(
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_features,
unused_results,
warnings
)]

/// Convenience import
pub mod prelude {
    pub use crate::config_handler::{ConfigFile, Section, Subsection};
}

/// Allows easy parsing of data files using HFG formatting
pub mod config_handler;

/// For handling errors in this crate
pub mod error;