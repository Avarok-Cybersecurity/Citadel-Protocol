//! In order to switch from single to multithreaded, follow comments below

use crate::hdp::hdp_session::HdpSessionInner;

/*
// single: std::cell::RefMut<'a, HdpSessionInner>
// multi: parking_lot::RwLockWriteGuard<'a, HdpSessionInner>
pub type SessionBorrow<'a> = parking_lot::RwLockWriteGuard<'a, HdpSessionInner>;

// single: $item.inner.borrow()
// multi: $item.inner.read()
macro_rules! inner {
    ($item:expr) => {
        $item.inner.read()
    };
}

// single: $item.inner.borrow_mut()
// multi: $item.inner.write()
macro_rules! inner_mut {
    ($item:expr) => {
        $item.inner.write()
    };
}

// single: pub inner: std::rc::Rc<std::cell::RefCell<$inner>>
// multi: pub inner: std::sync::Arc<parking_lot::RwLock<$inner>>
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

// single: std::rc::Rc::new(std::cell::RefCell::new($item))
// multi: std::sync::Arc::new(parking_lot::RwLock::new($item))
macro_rules! create_inner {
    ($item:expr) => {
        std::sync::Arc::new(parking_lot::RwLock::new($item))
    };
}


// single: $var.spawn($future)
// multi: $var.spawn_multi($future)
macro_rules! load_into_runtime {
    ($var:expr, $future:expr) => {
        unsafe { $var.spawn_multi(crate::hdp::ThreadSafeFuture::new($future)) }
    };
}

// single: tokio::task::spawn_local($future)
// multi: tokio::task::spawn($future);
macro_rules! spawn {
    ($future:expr) => {
        unsafe { tokio::task::spawn(crate::hdp::ThreadSafeFuture::new($future)) }
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
}*/