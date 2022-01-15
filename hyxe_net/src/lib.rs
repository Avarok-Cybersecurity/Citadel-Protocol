#![doc(html_no_source)]
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

    use either::Either;

    use crate::hdp::hdp_session::HdpSessionInner;

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

    macro_rules! inner_state {
    ($item:expr) => {
        //$item.inner.borrow()
        self.inner.read()
    };
}

    macro_rules! inner_mut_state {
    ($item:expr) => {
        //$item.inner.borrow_mut()
        self.inner.write()
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
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn_local($future))
    };
    }

    macro_rules! spawn_handle {
    ($future:expr) => {
        crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn_local($future))
    };
}

    macro_rules! to_concurrent_processor {
        ($executor:expr, $future:expr) => {
            $executor.send(Box::pin($future)).map(|_| PrimaryProcessorResult::Void).map_err(|_| NetworkError::InternalError("Async concurrent executor died"))
        }
    }

    macro_rules! return_if_none {
        ($opt:expr) => {
            return_if_none!($opt, stringify!($opt))
        };

        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!("[X-03] NoneError: {}", $err);
                    return Ok(PrimaryProcessorResult::Void);
                }
            }
        }
    }
}

#[cfg(feature = "multi-threaded")]
#[macro_use]
pub mod macros {
    use std::future::Future;

    use either::Either;

    use crate::hdp::hdp_session::HdpSessionInner;

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
        //$item.inner.try_read_for(std::time::Duration::from_millis(10)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.read()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(10)).expect("PANIC ON WRITE (TIMEOUT)")
        $item.inner.write()
    };
}

    macro_rules! inner_state {
    ($item:expr) => {
        //$item.inner.try_read_for(std::time::Duration::from_millis(10)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.read()
    };
}

    macro_rules! inner_mut_state {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(10)).expect("PANIC ON WRITE (TIMEOUT)")
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
            std::mem::drop(crate::hdp::misc::panic_future::ExplicitPanicFuture::new(tokio::task::spawn($future)));
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

    macro_rules! to_concurrent_processor {
        ($executor:expr, $future:expr) => {
            $executor.send(Box::pin($future)).map(|_| PrimaryProcessorResult::Void).map_err(|_| NetworkError::InternalError("Async concurrent executor died"))
        }
    }


    macro_rules! return_if_none {
        ($opt:expr) => {
            return_if_none!($opt, "NoneError Default")
        };

        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!("[X-03] NoneError: {}", $err);
                    return Ok(PrimaryProcessorResult::Void);
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
    pub use hyxe_nat::hypernode_type::NodeType;
}


pub mod prelude {
    pub use ez_pqcrypto::algorithm_dictionary::{EncryptionAlgorithm, KemAlgorithm};
    pub use hyxe_crypt::argon::{argon_container::ArgonDefaultServerSettings, autotuner::calculate_optimal_argon_params};
    pub use hyxe_crypt::fcm::keys::FcmKeys;
    pub use hyxe_crypt::secure_buffer::{sec_bytes::SecBuffer, sec_string::SecString};
    pub use hyxe_user::account_manager::AccountManager;
    pub use hyxe_user::auth::proposed_credentials::ProposedCredentials;
    pub use hyxe_user::backend::BackendType;
    pub use hyxe_user::external_services::RtdbConfig;
    pub use hyxe_user::external_services::ServicesConfig;
    pub use hyxe_user::external_services::ServicesObject;
    pub use hyxe_user::prelude::{ConnectProtocol, UserIdentifier};
    pub use hyxe_user::server_misc_settings::ServerMiscSettings;

    pub use crate::error::NetworkError;
    pub use crate::functional::*;
    pub use crate::hdp::file_transfer::FileTransferStatus;
    pub use crate::hdp::hdp_packet_crafter::SecureProtocolPacket;
    pub use crate::hdp::hdp_packet_processor::peer::group_broadcast::{GroupBroadcast, MemberState};
    pub use crate::hdp::hdp_server::{atexit, HdpServerRequest, HdpServerResult, NodeRemote, Remote, SecrecyMode};
    pub use crate::hdp::hdp_server::ConnectMode;
    pub use crate::hdp::hdp_server::Ticket;
    pub use crate::hdp::misc::panic_future::ExplicitPanicFuture;
    pub use crate::hdp::misc::session_security_settings::{SessionSecuritySettings, SessionSecuritySettingsBuilder};
    pub use crate::hdp::misc::underlying_proto::UnderlyingProtocol;
    pub use crate::hdp::outbound_sender::OutboundUdpSender;
    pub use crate::hdp::peer::channel::*;
    pub use crate::hdp::peer::group_channel::{GroupBroadcastPayload, GroupChannel, GroupChannelRecvHalf, GroupChannelSendHalf};
    pub use crate::hdp::peer::message_group::MessageGroupKey;
    pub use crate::hdp::peer::peer_layer::{PeerConnectionType, PeerSignal, UdpMode};
    pub use crate::hdp::peer::peer_layer::PeerResponse;
    pub use crate::hdp::state_container::VirtualTargetType;
    pub use crate::kernel::{kernel::NetKernel, kernel_executor::KernelExecutor};
    pub use crate::re_imports::{async_trait, NodeType};
    pub use hyxe_user::external_services::fcm::kem::FcmPostRegister;
    pub use crate::hdp::peer::peer_layer::HypernodeConnectionType;
    pub use crate::hdp::misc::sync_future::*;
}

/// Contains the streams for creating connections
mod kernel;
/// The default error type for this crate
mod error;
/// Contains the constants used by this crate
pub mod constants;
/// The primary module of this crate
mod hdp;
/// Functional extras
mod functional;
/// For handling differential function input types between single/multi-threaded modes
mod inner_arg;
#[doc(hidden)]
pub mod test_common;
pub mod auth;
