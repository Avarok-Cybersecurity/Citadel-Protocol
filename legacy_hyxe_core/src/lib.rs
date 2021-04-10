/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

#![feature(async_await, optin_builtin_traits, futures_api, custom_attribute, associated_type_defaults, ip, unboxed_closures, std_internals, fn_traits, type_ascription, ptr_internals, const_fn, allocator_api, impl_trait_in_bindings, stmt_expr_attributes, arbitrary_self_types)]

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
extern crate hyxe_util;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
#[macro_use]
extern crate lazy_static;
extern crate rayon;

use std::{error::Error, fmt};
//re-imports
pub use std::str;

use serde_derive::{Deserialize, Serialize};

/// Imports for general internal use and extension herefrom
pub mod prelude {
    pub use async_mem::hyxeobject::HyxeObject;
    #[macro_use]
    pub use hyxewave_net::prelude::*;

    pub use crate::hyxewave::misc::Constants;
    pub use crate::hyxewave::network::session::{NetworkAccount::NetworkAccount, SessionHandler::Session};
}

/// Core application
pub mod hyxewave;

pub trait Substring<'a> {
    fn substring(&'a self, start: &'a str, end: &'a str) -> Option<String>;
    fn substring_unchecked(&'a self, start: &'a str, end: &'a str) -> String;

    fn substring_str(&'a self, start: &'a str, end: &'a str) -> Option<&'a str>;
    fn substring_unchecked_str(&'a self, start: &'a str, end: &'a str) -> &'a str;
}

impl<'a, T: AsRef<str>> Substring for T {
    fn substring(&'a self, start: &'a str, end: &'a str) -> Option<String> {
        let input = self.as_ref();
        if !input.contains(start) || !input.contains(end) {
            return None;
        }
        let start_idx = input.find(start)? + start.len() - 1;
        let end_idx = input.find(end)?;
        let ret: String = input
            .chars()
            .skip(start_idx + 1)
            .take(end_idx - start_idx - 1)
            .collect();
        Some(ret)
    }

    fn substring_unchecked(&'a self, start: &'a str, end: &'a str) -> String {
        let input = self.as_ref();
        let start_idx = input.find(start).unwrap() + start.len() - 1;
        let end_idx = input.find(end).unwrap();
        let ret: String = input
            .chars()
            .skip(start_idx + 1)
            .take(end_idx - start_idx - 1)
            .collect();
        ret
    }

    fn substring_str(&'a self, start: &'a str, end: &'a str) -> Option<&'a str> {
        let input = self.as_ref();
        if !input.contains(start) || !input.contains(end) {
            return None;
        }
        let start_idx = input.find(start)? + start.len() - 1;
        let end_idx = input.find(end)?;
        let ret = input
            .chars()
            .skip(start_idx + 1)
            .take(end_idx - start_idx - 1)
            .collect();
        Some(ret)
    }

    fn substring_unchecked_str(&'a self, start: &'a str, end: &'a str) -> &'a str {
        let input = self.as_ref();
        let start_idx = input.find(start).unwrap() + start.len() - 1;
        let end_idx = input.find(end).unwrap();
        let ret = input
            .chars()
            .skip(start_idx + 1)
            .take(end_idx - start_idx - 1)
            .collect();
        ret
    }
}

#[macro_export]
macro_rules! decrypt {
    ($($x: expr), *) => {
        {
        let mut decrypted_ret = Vec::new();
        $(
            decrypted_ret.push(($x + 5)*100);
        )*
        decrypted_ret
        }
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SecurityLevel {
    LOW,
    MEDIUM,
    HIGH,
    ULTRA,
    DIVINE,
}

impl SecurityLevel {
    pub fn from_byte(byte: &u8) -> Option<SecurityLevel> {
        match byte {
            0 => Some(SecurityLevel::LOW),
            1 => Some(SecurityLevel::MEDIUM),
            2 => Some(SecurityLevel::HIGH),
            3 => Some(SecurityLevel::ULTRA),
            4 => Some(SecurityLevel::DIVINE),
            _ => None
        }
    }

    pub fn get_byte_representation(&self) -> u8 {
        match self {
            SecurityLevel::LOW => 0,
            SecurityLevel::MEDIUM => 1,
            SecurityLevel::HIGH => 2,
            SecurityLevel::ULTRA => 3,
            SecurityLevel::DIVINE => 4,
        }
    }

    pub fn get_encrypt_byte_multiplier(&self) -> u8 {
        match self {
            SecurityLevel::LOW => 1,
            SecurityLevel::MEDIUM => 2,
            SecurityLevel::HIGH => 4,
            SecurityLevel::ULTRA => 8,
            SecurityLevel::DIVINE => 16,
        }
    }

    pub fn clone(&self) -> SecurityLevel {
        match self {
            SecurityLevel::LOW => SecurityLevel::from_byte(&0).unwrap(),
            SecurityLevel::MEDIUM => SecurityLevel::from_byte(&1).unwrap(),
            SecurityLevel::HIGH => SecurityLevel::from_byte(&2).unwrap(),
            SecurityLevel::ULTRA => SecurityLevel::from_byte(&3).unwrap(),
            SecurityLevel::DIVINE => SecurityLevel::from_byte(&4).unwrap(),
        }
    }
}