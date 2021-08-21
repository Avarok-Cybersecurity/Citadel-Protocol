#![doc(html_no_source)]
#![feature(async_closure, ip, result_flattening, arbitrary_self_types)]
#![feature(test)]
#![feature(associated_type_bounds)]
#![feature(try_trait_v2)]
#![feature(control_flow_enum)]
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

#![allow(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "single-threaded")]
pub const fn build_tag() -> &'static str {
    "Single-Threaded"
}

#[cfg(not(feature = "single-threaded"))]
pub const fn build_tag() -> &'static str {
    "Multi-Threaded"
}

#[cfg(not(feature = "multi-threaded"))]
#[macro_use]
pub mod macros {
    use std::future::Future;

    use crate::hdp::hdp_session::HdpSessionInner;
    use either::Either;

    pub type OwnedReadGuard<'a, T> = std::cell::Ref<'a, T>;
    pub type OwnedWriteGuard<'a, T> = std::cell::RefMut<'a, T>;

    pub type EitherOwnedGuard<'a, T> = Either<OwnedReadGuard<'a, T>, OwnedWriteGuard<'a, T>>;

    pub trait ContextRequirements: 'static {}
    impl<T: 'static> ContextRequirements for T {}

    pub trait LocalContextRequirements<'a>: 'a {}
    impl<'a, T: 'a> LocalContextRequirements<'a> for T {}

    pub trait SyncContextRequirements: 'static {}
    impl<T: 'static> SyncContextRequirements for T {}

    #[allow(unused_results, dead_code)]
    pub fn tokio_spawn_async_then_sync<F: Future>(future: impl FnOnce() -> F + 'static, fx: impl FnOnce(<F as Future>::Output) + 'static) {
        tokio::task::spawn_local(async move { (fx)(future().await) });
    }

    pub type WeakBorrowType<T> = std::rc::Weak<std::cell::RefCell<T>>;
    pub type SessionBorrow<'a> = std::cell::RefMut<'a, HdpSessionInner>;

    pub struct WeakBorrow<T> {
        pub inner: std::rc::Weak<std::cell::RefCell<T>>
    }

    impl<T> Clone for WeakBorrow<T> {
        fn clone(&self) -> Self {
            Self { inner: self.inner.clone() }
        }
    }

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

        impl $struct_name {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner> {
                crate::macros::WeakBorrow { inner: std::rc::Rc::downgrade(&self.inner) }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(this: &crate::macros::WeakBorrow<$inner>) -> Option<$struct_name> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::rc::Rc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::rc::Rc::weak_count(&self.inner)
            }
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

    macro_rules! spawn {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn_local($future));
    };
    }

    macro_rules! spawn_handle {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn_local($future))
    };
}

    macro_rules! return_if_none {
        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!("[X-03] NoneError: {}", $err);
                    return PrimaryProcessorResult::Void;
                }
            }
        }
    }
}

#[cfg(feature = "multi-threaded")]
#[macro_use]
pub mod macros {
    use std::future::Future;

    use crate::hdp::hdp_session::HdpSessionInner;
    use either::Either;

    pub type OwnedReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;
    pub type OwnedWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;

    pub type EitherOwnedGuard<'a, T> = Either<OwnedReadGuard<'a, T>, OwnedWriteGuard<'a, T>>;

    pub trait ContextRequirements: Send + 'static {}
    impl<T: Send + 'static> ContextRequirements for T {}

    pub trait LocalContextRequirements<'a>: Send + 'a {}
    impl<'a, T: Send + 'a> LocalContextRequirements<'a> for T {}

    pub trait SyncContextRequirements: Send + Sync + 'static {}
    impl<T: Send + Sync + 'static> SyncContextRequirements for T {}

    #[allow(unused_results, dead_code)]
    pub fn tokio_spawn_async_then_sync<F: Future + ContextRequirements>(future: impl FnOnce() -> F + ContextRequirements, fx: impl FnOnce(<F as Future>::Output) + ContextRequirements) where <F as Future>::Output: Send {
        tokio::task::spawn(async move { (fx)(future().await) });
    }

    pub type WeakBorrowType<T> = std::sync::Weak<parking_lot::RwLock<T>>;
    pub type SessionBorrow<'a> = parking_lot::RwLockWriteGuard<'a, HdpSessionInner>;

    pub struct WeakBorrow<T> {
        pub inner: std::sync::Weak<parking_lot::RwLock<T>>
    }

    impl<T> Clone for WeakBorrow<T> {
        fn clone(&self) -> Self {
            Self { inner: self.inner.clone() }
        }
    }

    macro_rules! inner {
    ($item:expr) => {
        $item.inner.try_read_for(std::time::Duration::from_millis(1000)).expect("PANIC ON READ (TIMEOUT)")
        //$item.inner.read()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        $item.inner.try_write_for(std::time::Duration::from_millis(1000)).expect("PANIC ON WRITE (TIMEOUT)")
        //$item.inner.write()
    };
}

    macro_rules! define_outer_struct_wrapper {
    ($struct_name:ident, $inner:ty) => {

        #[derive(Clone)]
        pub struct $struct_name {
            pub inner: std::sync::Arc<parking_lot::RwLock<$inner>>
        }

        impl $struct_name {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner> {
                crate::macros::WeakBorrow { inner: std::sync::Arc::downgrade(&self.inner) }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(this: &crate::macros::WeakBorrow<$inner>) -> Option<$struct_name> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::sync::Arc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::sync::Arc::weak_count(&self.inner)
            }
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
        std::sync::Arc::new(parking_lot::RwLock::new($item))
    };
}

    #[allow(unused_results)]
    macro_rules! spawn {
    ($future:expr) => {
        if tokio::runtime::Handle::try_current().is_ok() {
            std::mem::drop(crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn(crate::hdp::misc::panic_future::AssertSendSafeFuture::new($future))));
        } else {
            log::warn!("Unable to spawn future: {:?}", stringify!($future));
        }
        //tokio::task::spawn($future)
    };
}

    macro_rules! spawn_handle {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn(crate::hdp::misc::panic_future::AssertSendSafeFuture::new($future)))
    };
}

    macro_rules! return_if_none {
        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!("[X-03] NoneError: {}", $err);
                    return PrimaryProcessorResult::Void;
                }
            }
        }
    }
}

pub mod re_imports {
    pub use async_trait::*;
    pub use bstr::ByteSlice;
    pub use bytes::BufMut;
    pub use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
    pub use futures::future::try_join3;

    pub use ez_pqcrypto::build_tag;
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
/// Functional extras
pub mod functional;
/// For handling differential function input types between single/multi-threaded modes
pub mod inner_arg;
