/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
*/

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

use futures::{Async, Future, Canceled};
use crate::misc::HyxeError::{GENERIC, CONVERTED};
use std::time::Instant;
use time::now_utc;

/// #
#[allow(non_camel_case_types)]
pub enum HyxeError<'a, E: Copy + Display + Clone + 'a> {
    /// A generic error message
    GENERIC(E, bool),
    /// For designating errors which were converted
    CONVERTED(E, bool),
    /// #
    _phantom(&'a E),
}

impl<'a, E: Copy + Display + Clone + 'a> HyxeError<'a, E> {
    /// #
    pub fn throw<U>(data: E) -> Result<U, Self> {
        Err(HyxeError::GENERIC(data, true))
    }

    pub(crate) fn printf(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            HyxeError::GENERIC(msg, _) => {
                write!(f, "[MemoryError:: Generic] {}", *msg)
            }
            HyxeError::CONVERTED(msg, _) => {
                write!(f, "[MemoryError] Converted: {}", msg)
            }

            _ => { write!(f, "[MemoryError] Undefined") }
        }
    }

    /// Pushes the error along, printing out the error, but only if not yet printed
    pub(crate) fn flow(self) -> Self {
        match self {
            GENERIC(val, r) => {
                if r {
                    println!("{}", self);
                }
                GENERIC(val, false)
            },
            
            CONVERTED(val, r) => {
                if r {
                    println!("{}", self);
                }
                CONVERTED(val, false)
            },
            
            _ => {
                self
            }
        }
    }

    /// #
    #[allow(dead_code)]
    fn value(&self) -> i32 {
        match self {
            HyxeError::GENERIC(_, _) => {
                0
            }
            _ => { 1 }
        }
    }
}

impl<'a, E: Copy + Display + Clone + 'a> Display for HyxeError<'a, E> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.printf(f)
    }
}

impl<'a, E: Copy + Display + Clone + 'a> Debug for HyxeError<'a, E> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.printf(f)
    }
}

impl<'a, E: Copy + Display + Clone + 'a> Error for HyxeError<'a, E> {}

unsafe impl<'a, E: Copy + Display + Clone + 'a> Send for HyxeError<'a, E> {}

unsafe impl<'a, E: Copy + Display + Clone + 'a> Sync for HyxeError<'a, E> {}

impl<'a, E: Copy + Display + Clone + 'a> Future for HyxeError<'a, E> {
    type Item = Self;
    type Error = Self;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        Ok(Async::Ready(self.clone()))
    }
}

impl<'a> From<()> for HyxeError<'a, &'a str> {
    fn from(_: ()) -> Self {
        HyxeError::GENERIC("Converted Error from ()", true)
    }
}

impl<'a> From<std::io::Error> for HyxeError<'_, &'a str> {
    fn from(err: std::io::Error) -> Self {
        println!("Error received: {}", err.to_string());
        HyxeError::CONVERTED("Converted Error", true)
    }
}

impl<'a> From<futures::sync::oneshot::Canceled> for HyxeError<'_, &'a str> {
    fn from(_: Canceled) -> Self {
        HyxeError::CONVERTED("Oneshot ended", true)
    }
}

impl<'a, E: Copy + Display + Clone + 'a> Clone for HyxeError<'a, E> {
    fn clone(&self) -> Self {
        match self {
            GENERIC(msg, state) => {
                GENERIC(*msg, *state)
            },
            _ => {
                panic!("Fix this")
            }
        }
    }
}

/// #
pub type HyxeResult<'a, T, E> = Result<T, HyxeError<'a, E>>;

/// Returns the default temporal measure in nsec
pub fn get_time() -> i32 {
    now_utc().to_timespec().nsec
}