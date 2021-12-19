#![feature(custom_attribute, checked_duration_since, ptr_internals, try_trait, arbitrary_self_types, pin_into_inner, optin_builtin_traits)]
#![feature(label_break_value, associated_type_defaults, nll, const_fn)]
//! The networking internals for HyxeWave: The semi-active anti-quantum hyperencryption protocol
//!
//!

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

#![allow(dead_code, non_upper_case_globals)]

/// Import this to gain the most essential subroutines for networking
pub mod prelude {
    pub use ::zerocopy::*;

    pub use crate::codec::Base64Codec;
    pub use crate::packet::*;
    pub use crate::connection::{stream_wrappers, stream_wrappers::old::{RawInboundItem, OutboundItem}};
}

/// `codec` contains optimized and unique algorithms for encoding/decoding that aren't present in rust's crate repository (e.g., base64)
/// Practically speaking: A simple `Codec` implementation that splits up data into lines.
pub mod codec;

/// This mod contains all the functions needed to handle packets as efficiently as possible. We use zerocopy and BytesMut to maximize
/// the level of efficiency.
pub mod packet;

/// Contains the means for abstracting streams of data. Notable functions include: connecting, disconnecting, re-connecting, base64 encoding, custom encryption, etc
pub mod connection;

/// Contains the means for forwarding packets of information between nodes.
pub mod routing;

/// Contains loaders for networking datatypes
pub mod file_loader;

/// Contains custom result types
pub mod misc;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate hyxe_util;