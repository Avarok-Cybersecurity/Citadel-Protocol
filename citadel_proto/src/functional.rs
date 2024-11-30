//! Functional Programming Utilities for Citadel Protocol
//!
//! This module provides functional programming utilities and extensions to enhance
//! code readability and maintainability. It implements monadic-style operations
//! and conditional chaining for Rust's native types.
//!
//! # Features
//!
//! - Method chaining with `Then` trait
//! - Conditional branching with `IfEq` and `IfTrue`
//! - Tuple mapping with `PairMap`
//! - Lazy evaluation support
//! - Type-safe conditional operations
//!
//! # Usage Example
//!
//! ```rust
//! use citadel_proto::functional::Then;
//! use citadel_proto::functional::IfTrueConditional;
//!
//! // Method chaining
//! let result = 42.then(|x| x * 2)
//!               .then(|x| x.to_string());
//!
//! // Conditional operations
//! let value = true.if_true(1)
//!                 .if_false(0);
//! assert_eq!(value, 1);
//! ```
//!
//! # Important Notes
//!
//! - All operations are zero-cost abstractions
//! - Implements `FnOnce` for lazy evaluation
//! - Preserves type safety through generics
//! - Supports both eager and lazy evaluation
//!
//! # Related Components
//!
//! - Used throughout the codebase for functional patterns
//! - Integrates with error handling and option types
//! - Supports protocol state management
//! - Enhances packet processing readability

pub trait Then<U, F: Fn(Self) -> U>
where
    Self: Sized,
{
    fn then(self, fx: F) -> U;
}

impl<T: Sized, U, F: Fn(T) -> U> Then<U, F> for T {
    #[inline]
    fn then(self, fx: F) -> U {
        fx(self)
    }
}

pub struct IfEq<J> {
    true_value: Option<J>,
}

impl<J> IfEq<J> {
    pub fn if_false_then(self, lambda: impl FnOnce() -> J) -> J {
        self.true_value.unwrap_or_else(lambda)
    }

    pub fn if_false(self, value: J) -> J {
        self.true_value.unwrap_or(value)
    }
}

pub trait IfEqConditional<J>
where
    Self: PartialEq,
{
    fn if_eq(self, other: Self, value: J) -> IfEq<J>;
    fn if_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfEq<J>;
}

pub trait IfTrueConditional<J> {
    fn if_true(self, if_true: J) -> IfEq<J>;
    fn if_true_then(self, if_true: impl FnOnce() -> J) -> IfEq<J>;
    fn if_false(self, if_false: J) -> IfEq<J>;
    fn if_false_then(self, if_false: impl FnOnce() -> J) -> IfEq<J>;
}

impl<T: PartialEq, J> IfEqConditional<J> for T {
    fn if_eq(self, other: Self, value: J) -> IfEq<J> {
        if self != other {
            IfEq { true_value: None }
        } else {
            IfEq {
                true_value: Some(value),
            }
        }
    }

    fn if_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfEq<J> {
        if self != other {
            IfEq { true_value: None }
        } else {
            IfEq {
                true_value: Some(lambda()),
            }
        }
    }
}

impl<J> IfTrueConditional<J> for bool {
    fn if_true(self, if_true: J) -> IfEq<J> {
        if self {
            IfEq {
                true_value: Some(if_true),
            }
        } else {
            IfEq { true_value: None }
        }
    }

    fn if_true_then(self, if_true: impl FnOnce() -> J) -> IfEq<J> {
        if self {
            IfEq {
                true_value: Some((if_true)()),
            }
        } else {
            IfEq { true_value: None }
        }
    }

    fn if_false(self, if_false: J) -> IfEq<J> {
        if !self {
            IfEq {
                true_value: Some(if_false),
            }
        } else {
            IfEq { true_value: None }
        }
    }

    fn if_false_then(self, if_false: impl FnOnce() -> J) -> IfEq<J> {
        if !self {
            IfEq {
                true_value: Some((if_false)()),
            }
        } else {
            IfEq { true_value: None }
        }
    }
}

pub trait PairMap<A, B> {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B);
    fn map_right<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U);
}

impl<A, B> PairMap<A, B> for (A, B) {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B) {
        ((fx)(self.0), self.1)
    }
    fn map_right<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U) {
        (self.0, (fx)(self.1))
    }
}
