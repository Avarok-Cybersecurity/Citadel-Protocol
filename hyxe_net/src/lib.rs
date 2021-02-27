#![feature(async_closure, main, try_trait, ip, type_alias_impl_trait, bindings_after_at)]
#![feature(test)]
#![feature(associated_type_bounds)]
#![forbid(unsafe_code)]
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

    pub trait ContextRequirements: 'static {}
    impl<T: 'static> ContextRequirements for T {}

    pub trait SyncContextRequirements: 'static {}
    impl<T: 'static> SyncContextRequirements for T {}

    pub type SessionBorrow<'a> = std::cell::RefMut<'a, HdpSessionInner>;
    pub struct WeakBorrow<T> {
        pub inner: std::rc::Weak<std::cell::RefCell<T>>
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
        tokio::task::spawn_local($future);
    };
    }

    macro_rules! spawn_handle {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn_local($future))
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
pub mod macros {
    use crate::hdp::hdp_session::HdpSessionInner;

    pub trait ContextRequirements: Send + 'static {}
    impl<T: Send + 'static> ContextRequirements for T {}

    pub trait SyncContextRequirements: Send + Sync + 'static {}
    impl<T: Send + Sync + 'static> SyncContextRequirements for T {}

    pub type SessionBorrow<'a> = parking_lot::RwLockWriteGuard<'a, HdpSessionInner>;
    pub struct WeakBorrow<T> {
        pub inner: std::sync::Weak<parking_lot::RwLock<T>>
    }

    macro_rules! inner {
    ($item:expr) => {
        //$item.inner.try_read_for(std::time::Duration::from_millis(1000)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.read()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(1000)).expect("PANIC ON WRITE (TIMEOUT)")
        $item.inner.write()
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
            std::mem::drop(tokio::task::spawn($future));
        } else {
            log::warn!("Unable to spawn future: {:?}", stringify!($future));
        }
        //tokio::task::spawn($future)
    };
}

    macro_rules! spawn_handle {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn($future))
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
/// For handling misc requirements
pub mod proposed_credentials;
/// Functional extras
pub mod functional;
/// For handling differential function input types between single/multi-threaded modes
pub mod inner_arg;
