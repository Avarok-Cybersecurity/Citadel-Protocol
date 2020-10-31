#![feature(type_alias_impl_trait, checked_duration_since, ptr_internals, try_trait, arbitrary_self_types, pin_into_inner, optin_builtin_traits, fundamental, mem_take, allow_internal_unstable)]
//! This crate is used throughout HyxeWave's programs


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


#[allow(unused_macros)]
/// Provides useful macros for handling data
#[macro_use]
pub mod macros {
    /// Prints a red-colored text to the console. TODO: Global error monitor
    #[macro_export]
    #[allow_internal_unstable(print_internals, format_args_nl)]
    macro_rules! severe {
        ($($arg:tt)*) => ($crate::macro_fns::MacroFunction::process_severe(format_args_nl!($($arg)*)));
    }

    /// Prints a green-colored text to the console
    #[macro_export]
    #[allow_internal_unstable(print_internals, format_args_nl)]
    macro_rules! success {
    ($($arg:tt)*) => ($crate::macro_fns::MacroFunction::process_success(format_args_nl!($($arg)*)));
    }

    /// Needs to print declared variable name, size in bytes, memory location, etc
    #[macro_export]
    macro_rules! print_entity {
    ($($e: expr), *) => {
        $(
        let val: &HyperObject<_> = $e;
        success!("Variable name: {} <=> id: {}", stringify!($e), val.get_id());
        )*
    }
    }

    /// Prints a green-colored text to the console
    macro_rules! validate {

    () => (success!("System valid"));

    ($x:expr) => ({
        let val: bool = $x;
        if val {
            success!("System valid");
        }
    });

    ($($x:expr, $y:expr), *) => {
            ()
        }

    }
}


/// Useful for all Hyxe related projects
pub mod prelude {
    pub use bytes::{BufMut, BytesMut};
    pub use crossterm::{Color, Crossterm};
    pub use hashbrown::HashMap;
    pub use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

    pub use crate::macro_fns::*;
    pub use crate::macros::*;
    pub use crate::statics::{CROSSTERM, RUNTIME};
    pub use crate::temporal::temporal::{RelativeTimeStamp, RuntimeDelta};
}


/// For global access to interact with cross-program variables
pub(crate) mod statics {
    use std::time::Instant;

    use crossterm::Crossterm;
    use lazy_static::*;
    use parking_lot::RwLock;

    lazy_static! {
    ///For colorfully displaying data
    pub static ref CROSSTERM: Crossterm = Crossterm::new();

    /// The initial start point (in time) of any program that uses this crate
    pub static ref RUNTIME: RwLock<Instant> = RwLock::new(Instant::now());

    }
}

/// Precise Time Functions for tracking lifetimes
pub mod temporal;

/// The inner macro functions
pub mod macro_fns {
    use std::fmt::Display;

    use crossterm::Color;

    use crate::prelude::RuntimeDelta;
    use crate::statics::{CROSSTERM, RUNTIME};

    /// Provides functions for macros
    pub trait MacroFunction {
        /// Print green text to console
        fn process_success(self);

        /// Print red text to console
        fn process_severe(self);
    }

    impl<T> MacroFunction for T where T: Display {
        fn process_success(self) {
            println!("{}: {}", CROSSTERM.style(format!("[{}]", RUNTIME.get_displayable_runtime())).with(Color::Green).on(Color::Black), &self);
        }

        ///test
        fn process_severe(self) {
            println!("{}: {}", CROSSTERM.style(format!("[{}]", RUNTIME.get_displayable_runtime())).with(Color::Red).on(Color::Black), &self);
        }
    }
}
