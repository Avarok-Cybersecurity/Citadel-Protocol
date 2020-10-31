#![feature(fundamental, alloc_layout_extra, slice_from_raw_parts, allocator_api, custom_attribute, optin_builtin_traits, arbitrary_self_types, alloc_error_hook, trivial_bounds, in_band_lifetimes, slice_index_methods)]
#![feature(label_break_value, try_trait, pin_into_inner, stmt_expr_attributes, associated_type_bounds)]
//! HyperVec is a highly-experimental primitive


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

/// Import everything herein to gain access to the HyperVec and all its associated structures, subroutines, and implementations
pub mod prelude {
    pub use crate::hypervec::{Endianness, HyperVec};
    pub use crate::impls::*;
    pub use crate::results::*;
    pub use crate::{read_visitor::ReadVisitor, write_visitor::WriteVisitor};
}

/// A memory primitive
pub mod hypervec;

pub(crate) mod results;

#[macro_use]
extern crate hyperbuf_derive;

use std::fmt::{Display, Formatter, Error};

pub(crate) mod util;

/// provides useful implementations for HyperVec
pub mod impls;

/// Low-level memory tracking system that removes the necessity to store a single type to a vector by keeping track of sizes
pub mod partition_map;

/// Low-level async memory editing module
pub mod write_visitor;

/// Low-level async memory reading module
pub mod read_visitor;

#[derive(Copy, Clone)]
///  Debug purposes
pub struct Txx {
    field: u8,
    field2: u16,
    field3: u32,
    field4: u16
}

impl Txx {
    ///e2
    pub fn new(seed: usize) -> Self {
        Self {field: (seed + 10) as u8, field2: (seed + 111) as u16, field3: (seed + 222) as u32, field4: seed as u16}
    }
}

impl Display for Txx {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{} {} {} -> SEED {}", self.field, self.field2, self.field3, self.field4)
    }
}