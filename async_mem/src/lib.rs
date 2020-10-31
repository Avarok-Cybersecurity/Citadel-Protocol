#![feature(fundamental, mem_take, async_await, generators, generator_trait, try_trait, optin_builtin_traits, arbitrary_self_types, ptr_internals, allocator_api, alloc_layout_extra, slice_from_raw_parts)]
//! This crate provides asynchronous memory access with caching capabilities

#![deny(
missing_docs,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_results,
warnings,
unused_features
)]

#![allow(dead_code)]

#[macro_use]
extern crate hyxe_util;


/// Provides all the API subroutines
pub mod prelude {
    pub use hyxe_util::prelude::*;
    pub use crate::hyxeobject::HyxeObject;
}


/// Production-use object
pub mod hyxeobject;