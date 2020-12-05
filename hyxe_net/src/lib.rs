#![feature(async_closure, main, try_trait, ip)]
#![feature(test)]
#![feature(associated_type_bounds)]
//! Core networking components for SatoriNET
#![deny(
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_features,
unused_results,
warnings
)]

#[cfg(not(feature = "multi-threaded"))]
#[macro_use]
pub mod macros {
    use crate::hdp::hdp_session::HdpSessionInner;

    pub type SessionBorrow<'a> = std::cell::RefMut<'a, HdpSessionInner>;

    macro_rules! inner {
    ($item:expr) => {
        $item.inner.borrow()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        $item.inner.borrow_mut()
    };
}


    macro_rules! define_outer_struct_wrapper {
    ($struct_name:ident, $inner:ty) => {
        #[derive(Clone)]
        pub struct $struct_name {
            pub inner: std::rc::Rc<std::cell::RefCell<$inner>>
        }

        impl From<$inner> for $struct_name {
            fn from(inner: $inner) -> Self {
                Self { inner: create_inner!(inner) }
            }
        }
    };
}

    macro_rules! create_inner {
    ($item:expr) => {
        std::rc::Rc::new(std::cell::RefCell::new($item))
    };
}


    macro_rules! load_into_runtime {
    ($var:expr, $future:expr) => {
        $var.spawn($future)
    };
}

    macro_rules! spawn {
    ($future:expr) => {
        tokio::task::spawn_local($future)
    };
}


    macro_rules! new_runtime {
    () => {
        crate::kernel::runtime_handler::RuntimeHandler::from(Some(tokio::task::LocalSet::new()))
    };
}

    macro_rules! wrap_inner_mut {
    ($item:expr) => {
        (&mut $item).into()
    };
}

    macro_rules! wrap_inner {
    ($item:expr) => {
        (&$item).into()
    };
}
}

#[cfg(feature = "multi-threaded")]
#[macro_use]
// !WARNING! THIS IS UNSTABLE! DEADLOCKS HAVE OCCURRED IN TESTS, AND AS SUCH, COMPILING TO MULTI-THREADED IS NOT RECOMMENDED
// UNLESS IN TESTING
pub mod macros {
    use crate::hdp::hdp_session::HdpSessionInner;

    pub type SessionBorrow<'a> = parking_lot::RwLockWriteGuard<'a, HdpSessionInner>;

    macro_rules! inner {
    ($item:expr) => {
        $item.inner.read()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        $item.inner.write()
    };
}

    macro_rules! define_outer_struct_wrapper {
    ($struct_name:ident, $inner:ty) => {
        #[derive(Clone)]
        pub struct $struct_name {
            pub inner: std::sync::Arc<parking_lot::RwLock<$inner>>
        }

        unsafe impl Send for $struct_name {}
        unsafe impl Sync for $struct_name {}

        impl From<$inner> for $struct_name {
            fn from(inner: $inner) -> Self {
                Self { inner: create_inner!(inner) }
            }
        }
    };
}

    macro_rules! create_inner {
    ($item:expr) => {
        std::sync::Arc::new(parking_lot::RwLock::new($item))
    };
}

    macro_rules! load_into_runtime {
    ($var:expr, $future:expr) => {
        unsafe { $var.spawn_multi(crate::hdp::AssertThreadSafeFuture::new($future)) }
    };
}

    macro_rules! spawn {
    ($future:expr) => {
        unsafe { tokio::task::spawn(crate::hdp::AssertThreadSafeFuture::new($future)) }
    };
}

    // single: Some(tokio::task::LocalSet::new())
// multi: None
    macro_rules! new_runtime {
    () => {
        crate::kernel::runtime_handler::RuntimeHandler::from(None)
    };
}

    macro_rules! wrap_inner_mut {
    ($item:expr) => {
        (&mut $item).into()
    };
}

    macro_rules! wrap_inner {
    ($item:expr) => {
        (&$item).into()
    };
}
}

pub mod re_imports {
    pub use async_trait::*;
    pub use bstr::ByteSlice;
    pub use bytes::BufMut;
    pub use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
    pub use futures::future::try_join3;

    pub use hyxe_nat::hypernode_type::HyperNodeType;
}

/// Contains the streams for creating connections
pub mod kernel;

/// The default error type for this crate
pub mod error;

/// Contains the constants used by this crate
pub mod constants;
/// The primary module of this crate
pub mod hdp;
/// For handling misc requirements
pub mod proposed_credentials;
/// Functional extras
pub mod functional;
/// For handling differential function input types between single/multi-threaded modes
pub mod inner_arg;