/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::fmt::{Debug, Display, Formatter};
use std::error::Error;

/// #
#[allow(non_camel_case_types)]
pub enum MemError<'a, E: AsRef<[u8]> +'a> {
    /// Contains the corrupted bytes
    CORRUPT(E),
    /// Out of sync
    OUT_OF_SYNC,
    /// Not ready (for polling)
    NOT_READY,
    /// #
    BAD_ALIGN(E),

    ///Exec fail
    EXEC_FAIL(E),
    /// A generic error message
    GENERIC(E),
    /// #
    _phantom(&'a E)
}

impl<'a, E: AsRef<[u8]> +'a> MemError<'a, E> {

    /// #
    pub fn throw_corrupt<U>(symbol: E) -> Result<U, Self> {
        Err(MemError::CORRUPT(symbol))
    }

    /// #
    pub fn throw_bad_align<U>(data: E) -> Result<U, Self> {
        Err(MemError::BAD_ALIGN(data))
    }

    /// #
    pub fn throw<U>(data: E) -> Result<U, Self> {
        Err(MemError::GENERIC(data))
    }

    fn printf(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            MemError::CORRUPT(t) => {
                write!(f, "[MemoryError] {}", String::from_utf8_lossy(t.as_ref()))
            },

            MemError::OUT_OF_SYNC => {
                write!(f, "[MemoryError] Out of Sync")
            },

            MemError::NOT_READY => {
                write!(f, "[MemoryError] Not ready")
            },

            MemError::EXEC_FAIL(t) => {
                write!(f, "[MemoryError] Execution fail: {}", String::from_utf8_lossy(t.as_ref()))
            },

            MemError::BAD_ALIGN(t) => {
                write!(f, "[MemoryError] Bad Align. {}", String::from_utf8_lossy(t.as_ref()))
            }

            MemError::GENERIC(msg) => {
                write!(f, "[MemoryError] {}", String::from_utf8_lossy((*msg.as_ref()).as_ref()))
            }
            _ => {write!(f, "[MemoryError] Undefined")}
        }
    }

    /// #
    #[allow(dead_code)]
    fn value(&self) -> i32 {
        match self {
            MemError::CORRUPT(_) => {
                0
            },

            MemError::OUT_OF_SYNC => {
                1
            },

            MemError::NOT_READY => {
                2
            },

            MemError::GENERIC(_) => {
                3
            }
            _ => {4}
        }
    }
}

impl<'a, E: AsRef<[u8]> +'a> Display for MemError<'a, E> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.printf(f)
    }
}

impl<'a, E: AsRef<[u8]> +'a> Debug for MemError<'a, E> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.printf(f)
    }
}

impl<'a, E: AsRef<[u8]> +'a> Error for MemError<'a, E> {}
unsafe impl<'a, E: AsRef<[u8]> +'a> Send for MemError<'a, E> {}
unsafe impl<'a, E: AsRef<[u8]> +'a> Sync for MemError<'a, E> {}

/// #
pub type InformationResult<'a, T, E> = Result<T, MemError<'a, E>>;